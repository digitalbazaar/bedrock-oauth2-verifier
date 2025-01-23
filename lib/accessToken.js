/*!
 * Copyright (c) 2021-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {discoverIssuer} from './discovery.js';
import {jwtVerify} from 'jose';

const {util: {BedrockError}} = bedrock;

const OAUTH2_TOKEN_REGEX = /^Bearer (.+)$/i;

/**
 * Checks an OAuth2 JWT access token. The only claims checked will be:
 * `typ`, `iss`, `aud`, `exp`, `nbf`. Scopes must be checked externally.
 *
 * @param {object} options - The options to use.
 * @param {object} [options.req] - The HTTP request interface, providing a
 *   `get()` function to access the `authorization` header; this or "jwt"
 *   must be given, but not both.
 * @param {string} [options.jwt] - The JWT; this or "req" must be given, but
 *   not both.
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
  req, jwt,
  issuerConfigUrl,
  // e.g. ['EdDSA', 'ES256', 'ES256K', 'ES521']
  allowedAlgorithms,
  // default is to permit 300 seconds of clock skew
  maxClockSkew = 300,
  // audience to check
  audience
} = {}) {
  if(!(req || jwt)) {
    throw new TypeError('One of "req" or "jwt" is required.');
  }
  if(req && jwt) {
    throw new TypeError('Only one of "req" or "jwt" must be given.');
  }
  if(!(audience && typeof audience === 'string')) {
    throw new TypeError('"audience" must be a string.');
  }

  // get access token
  if(req) {
    jwt = req.get('authorization')?.match(OAUTH2_TOKEN_REGEX)[1];
  }
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

  // discover issuer oauth2 authz server config
  const {issuer, jwks} = await discoverIssuer({issuerConfigUrl});

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
