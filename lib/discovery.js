/*!
 * Copyright (c) 2021-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {httpsAgent as agent} from '@bedrock/https-agent';
import {createLocalJWKSet} from 'jose';
import {httpClient} from '@digitalbazaar/http-client';
import {LruCache} from '@digitalbazaar/lru-memoize';

const {util: {BedrockError}} = bedrock;

const WELL_KNOWN_REGEX = /\/\.well-known\/([^\/]+)/;

let ISSUER_CONFIG_CACHE;

bedrock.events.on('bedrock.init', async () => {
  _createIssuerConfigCache();
});

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
  const promise = ISSUER_CONFIG_CACHE.cache.peek(key);
  const record = await promise;

  // clear expired record from cache (if it hasn't already changed) and retry
  const now = new Date();
  if(record.expires < now) {
    if(ISSUER_CONFIG_CACHE.cache.peek(key) === promise) {
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
    const current = ISSUER_CONFIG_CACHE.cache.peek(issuerConfigUrl);
    if(!current) {
      return resolve(null);
    }
    current.then(currentRecord => {
      // only start rotation if same record is still present in the cache
      if(!(currentRecord === record &&
        current === ISSUER_CONFIG_CACHE.cache.peek(issuerConfigUrl))) {
        return resolve(null);
      }

      // start rotation process
      const promise = _getUncachedIssuerConfig({issuerConfigUrl});
      promise.then(() => {
        if(current === ISSUER_CONFIG_CACHE.cache.peek(issuerConfigUrl)) {
          ISSUER_CONFIG_CACHE.cache.set(issuerConfigUrl, promise);
        }
      }).catch(() => {});

      // `next` always stores `null` or a promise that resolves
      // to a record or error, but does not reject
      resolve(promise.catch(e => e));
    }).catch(() => resolve(null));
  }, ISSUER_CONFIG_CACHE.cache.maxAge));

  return record;
}
