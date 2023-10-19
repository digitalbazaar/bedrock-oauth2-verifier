/*!
 * Copyright (c) 2021-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {createLocalJWKSet, jwtVerify} from 'jose';
import {httpsAgent as agent} from '@bedrock/https-agent';
import {httpClient} from '@digitalbazaar/http-client';
import {LruCache} from '@digitalbazaar/lru-memoize';

// load config defaults
import './config.js';

const {util: {BedrockError}} = bedrock;

const OAUTH2_TOKEN_REGEX = /^Bearer (.+)$/i;
const WELL_KNOWN_REGEX = /\/\.well-known\/([^\/]+)/;

let ISSUER_CONFIG_CACHE;

bedrock.events.on('bedrock.init', async () => {
  _createIssuerConfigCache();
});

/**
 * Checks an OAuth2 JWT access token. The only claims checked will be:
 * `typ`, `iss`, `aud`, `exp`, `nbf`. Scopes must be checked externally.
 *
 * @param {object} options - The options to use.
 * @param {object} options.req - The HTTP request interface.
 * @param {string} options.issuerConfigUrl - The URL for the config (meta data)
 *   for the trusted issuer.
 * @param {Array} [options.allowedAlgorithms] - An allow list of JOSE
 *   algorithms; the `none` algorithm is automatically disallowed.
 * @param {number} [options.maxClockSkew=300] - The maximum clock skew to allow
 *   in seconds (when verifying time-based claims).
 * @param {string} options.audience - A string that represents the expected
 *   (and allowed) audience for the JWT.
 *
 * @returns {Promise<object>} An object with `issuer`, `jwks`, and full
 *   meta data config in `config`.
 */
export async function checkAccessToken({
  req, issuerConfigUrl,
  // e.g. ['EdDSA', 'ES256', 'ES256K', 'ES521']
  allowedAlgorithms,
  // default is to permit 300 seconds of clock skew
  maxClockSkew = 300,
  // audience to check
  audience
} = {}) {
  if(!(audience && typeof audience === 'string')) {
    throw new TypeError('"audience" must be a string.');
  }

  // discover issuer oauth2 authz server config
  const {issuer, jwks} = await discoverIssuer({issuerConfigUrl});

  // get access token
  const jwt = req.get('authorization')?.match(OAUTH2_TOKEN_REGEX)[1];
  if(!jwt) {
    throw new BedrockError(
      'Access token validation failed.', {
        name: 'NotAllowedError',
        details: {
          httpStatusCode: 403,
          public: true,
          code: 'ERR_JWT_INVALID',
          reason: `Access token not provided or invalid.`
        }
      });
  }

  // use `jose` lib (for now) to verify JWT and return `payload`;
  // pass optional supported algorithms as allow list ... note
  // that `jose` *always* prohibits the `none` algorithm
  let verifyResult;
  try {
    // `jwtVerify` checks claims: `typ`, `iss`, `aud`, `exp`, `nbf`
    const {payload, protectedHeader} = await jwtVerify(jwt, jwks, {
      algorithms: allowedAlgorithms,
      audience,
      clockTolerance: maxClockSkew,
      issuer,
      // JWT access token type required
      typ: 'at+jwt'
    });
    verifyResult = {payload, protectedHeader};
  } catch(e) {
    const details = {
      httpStatusCode: 403,
      public: true,
      code: e.code,
      reason: e.message
    };
    if(e.claim) {
      details.claim = e.claim;
    }
    throw new BedrockError('Access token validation failed.', {
      name: 'NotAllowedError',
      details
    });
  }

  return verifyResult;
}

/**
 * Fetches the issuer configuration meta data from the given URL. If the URL
 * was previously fetched, then the result may be returned from a cache.
 *
 * @param {object} options - The options to use.
 * @param {string} options.issuerConfigUrl - The URL for the issuer config.
 *
 * @returns {Promise<object>} An object with `issuer`, `jwks`, and full
 *   meta data config in `config`.
 */
export async function discoverIssuer({issuerConfigUrl} = {}) {
  // use `issuerConfigUrl` to get cached oauth2 issuer config via
  // RFC 8414, including JWKs
  // https://datatracker.ietf.org/doc/html/rfc8414
  const key = issuerConfigUrl;
  const fn = () => _getUncachedIssuerConfig({issuerConfigUrl});

  // memoize but fetch promise directly to compare below whilst avoiding race
  // condition where the cache could be updated during `await`
  await ISSUER_CONFIG_CACHE.memoize({key, fn});
  const promise = ISSUER_CONFIG_CACHE.cache.get(key);
  const record = await promise;

  // clear expired record from cache (if it hasn't already changed) and retry
  const now = new Date();
  if(record.expires < now) {
    const current = ISSUER_CONFIG_CACHE.cache.get(key);
    if(current === promise) {
      ISSUER_CONFIG_CACHE.delete(key);
    }
    return _getUncachedIssuerConfig({issuerConfigUrl});
  }

  const {issuer, jwks, config} = record;
  return {issuer, jwks, config};
}

// exposed for testing purposes only
export function _resetIssuerConfigCache({ttl} = {}) {
  _createIssuerConfigCache({ttl});
}

function _createIssuerConfigCache({ttl} = {}) {
  const {issuerConfig} = bedrock.config['oauth2-verifier'];
  // force `updateAgeOnGet` to ensure rotation can happen
  const options = {...issuerConfig.cache, updateAgeOnGet: true};
  if(ttl !== undefined) {
    options.maxAge = ttl;
  }
  ISSUER_CONFIG_CACHE = new LruCache(options);
}

async function _getUncachedIssuerConfig({issuerConfigUrl}) {
  // ensure retrieving file has both timeout and size limits
  const {issuerConfig} = bedrock.config['oauth2-verifier'];
  const fetchOptions = {...issuerConfig.fetchOptions, agent};
  let response = await httpClient.get(issuerConfigUrl, fetchOptions);
  if(!response.data) {
    throw new BedrockError(
      'Invalid OAuth2 issuer configuration; format is not JSON.', {
        name: 'OperationError',
        details: {
          httpStatusCode: 500,
          public: true
        }
      });
  }
  const {data: config} = response;
  const {data: {issuer, jwks_uri}} = response;

  // validate `issuer` and `jwk_uris`
  if(!(typeof issuer === 'string' && issuer.startsWith('https://'))) {
    throw new BedrockError(
      'Invalid OAuth2 issuer configuration; "issuer" is not an HTTPS URL.', {
        name: 'OperationError',
        details: {
          httpStatusCode: 500,
          public: true
        }
      });
  }
  if(!(typeof jwks_uri === 'string' && jwks_uri.startsWith('https://'))) {
    throw new BedrockError(
      'Invalid OAuth2 issuer configuration; "jwks_uri" is not an HTTPS URL.', {
        name: 'OperationError',
        details: {
          httpStatusCode: 500,
          public: true
        }
      });
  }

  /* Validate `issuer` value against `issuerConfigUrl` (per RFC 8414):

  The `origin` and `path` element must be parsed from `issuer` and checked
  against `issuerConfigUrl` like so:

  For issuer `<origin>` (no path), `issuerConfigUrl` must match:
  `<origin>/.well-known/<any-path-segment>`

  For issuer `<origin><path>`, `issuerConfigUrl` must be:
  `<origin>/.well-known/<any-path-segment><path>` */
  const {pathname: wellKnownPath} = new URL(issuerConfigUrl);
  const anyPathSegment = wellKnownPath.match(WELL_KNOWN_REGEX)[1];
  const {origin, pathname} = new URL(issuer);
  let expectedConfigUrl = `${origin}/.well-known/${anyPathSegment}`;
  if(pathname !== '/') {
    expectedConfigUrl += pathname;
  }
  if(issuerConfigUrl !== expectedConfigUrl) {
    throw new BedrockError(
      'Invalid OAuth2 issuer configuration; "issuer" does not match ' +
      'configuration URL.', {
        name: 'OperationError',
        details: {
          httpStatusCode: 500,
          public: true,
          expected: expectedConfigUrl,
          actual: issuerConfigUrl
        }
      });
  }

  // fetch JWKs
  response = await httpClient.get(jwks_uri, fetchOptions);
  if(!response.data) {
    throw new BedrockError(
      'Invalid OAuth2 issuer "jwk_uri" response; format is not JSON.', {
        name: 'OperationError',
        details: {
          httpStatusCode: 500,
          public: true
        }
      });
  }
  // try to parse JSON Web Key Set
  let jwks;
  try {
    jwks = await createLocalJWKSet(response.data);
  } catch(cause) {
    throw new BedrockError(
      'Invalid OAuth2 issuer "jwk_uri" response; ' +
      'JSON Web Key Set is malformed.', {
        name: 'OperationError',
        cause,
        details: {
          httpStatusCode: 500,
          public: true
        }
      });
  }

  // return issuer and JWKs only at this time; perhaps cache and return
  // full config response as `config` in the future; expire config at twice
  // its cache TTL
  const expires = new Date(Date.now() + ISSUER_CONFIG_CACHE.cache.maxAge * 2);
  const record = {issuer, jwks, config, next: null, expires};

  // schedule potential cache record rotation
  record.next = new Promise(resolve => setTimeout(() => {
    // only continue if key is still in cache
    const current = ISSUER_CONFIG_CACHE.cache.get(issuerConfigUrl);
    if(!current) {
      return resolve(null);
    }
    Promise.resolve(current).then(currentRecord => {
      // only start rotation if same record is still present in the cache
      if(!(currentRecord === record &&
        current === ISSUER_CONFIG_CACHE.cache.get(issuerConfigUrl))) {
        return resolve(null);
      }

      // start rotation process
      const promise = _getUncachedIssuerConfig({issuerConfigUrl}).catch(e => e);
      Promise.resolve(promise)
        .then(e => {
          if(!(e instanceof Error) &&
            current === ISSUER_CONFIG_CACHE.cache.get(issuerConfigUrl)) {
            ISSUER_CONFIG_CACHE.cache.set(issuerConfigUrl, promise);
          }
        }).catch(() => {});
      resolve(promise);
    }).catch(() => resolve(null));
  }, ISSUER_CONFIG_CACHE.cache.maxAge));

  return record;
}
