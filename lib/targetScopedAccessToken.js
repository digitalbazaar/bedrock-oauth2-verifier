/*!
 * Copyright (c) 2021-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {checkAccessToken} from './accessToken.js';

const {util: {BedrockError}} = bedrock;

// note: these default actions match ezcap-express
// https://github.com/digitalbazaar/ezcap-express
const DEFAULT_ACTION_FOR_METHOD = new Map([
  ['GET', 'read'],
  ['HEAD', 'read'],
  ['OPTIONS', 'read'],
  ['POST', 'write'],
  ['PUT', 'write'],
  ['PATCH', 'write'],
  ['DELETE', 'write'],
  ['CONNECT', 'write'],
  ['TRACE', 'write'],
  ['PATCH', 'write']
]);

/**
 * Checks an OAuth2 JWT access token that uses a scope that must match
 * the given request's method and target resource and the "expected values" as
 * returned from `getExpectedValues()`.
 *
 * A JWT must have a scope with a format of `<action>:<target> ...`, where
 * at least one space-delimited value matches the expected `<action>:<target>`,
 * e.g., `read:/some/path` or `write:/another/place?foo=bar`.
 *
 * The scope will be considered a "match" based on the rules described below
 * in the description of `getExpectedValues()`.
 *
 * The only other claims checked will be: `typ`, `iss`, `aud`, `exp`, `nbf`.
 *
 * The `getExpectedValues()` function returns an object (or a promise that
 * resolves to such an object) that includes:
 *
 * `host` (required string): The expected HTTP host value.
 * `rootInvocationTarget` (required string): The root path that both the
 *   request target resource (aka "request URI", e.g., GET <target resource>)
 *   and the `target` component from a space-delimited scope value must start
 *   with; path-based and query-based attenuation are possible with this design
 *   such that a JWT with a scope of, e.g., `read:/foos` can be
 *   used to perform an authorized HTTP GET on each of these: `/foos`,
 *   `/foos/1`, and `/foos/1/bars/2/something`.
 * `action` (optional string): The expected action that must match the `action`
 *   component from a space-delimited scope value; if not provided, the
 *   expected action will default to "read" for HTTP methods like `GET`,
 *   `HEAD`, and `OPTIONS` and "write" for other common HTTP methods like
 *   `POST`, `PUT`, `PATCH`, and `DELETE`; not all verbs are supported; using
 *   an action that might map to multiple HTTP methods allows for fewer scopes
 *   to be used or for differentiating based on read/write instead of the
 *   specific mechanisms used to read/write.
 * `target` (optional string): The expected target that must match the `target`
 *   component from a space-delimited scope value; if not provided, the
 *   expected `target` will be set to the request's full path; if the expected
 *   `target` value is not prefixed by `rootInvocationTarget`, the access token
 *   will be rejected.
 *
 * Note that a JWT must have a scope that includes a space-delimited value
 * that has BOTH a matching `action` and `target`. For clarify, a single
 * `<action>:<target>` (no spaces) is a potentially acceptable scope.
 *
 * @param {object} options - The options to use.
 * @param {object} options.req - The HTTP request interface, providing a
 *   `get()` function to access the `authorization` header.
 * @param {string} options.issuerConfigUrl - The URL for the config (meta data)
 *   for the trusted issuer.
 * @param {Function} options.getExpectedValues - A function that returns
 *   an object (or a promise that resolves to such an object) that includes
 *   the expected values as described above.
 * @param {Array} [options.allowedAlgorithms] - An allow list of JOSE
 *   algorithms; the `none` algorithm is automatically disallowed.
 * @param {number} [options.maxClockSkew=300] - The maximum clock skew to allow
 *   in seconds (when verifying time-based claims).
 * @param {string} [options.audience] - A string that represents the expected
 *   (and allowed) `audience` claim for the JWT; if not provided, it will
 *   default to the expected `rootInvocationTarget`.
 * @param {string} [options.typ='at+jwt'] - A string that represents the
 *   expected (and allowed) `typ` claim for the JWT.
 *
 * @returns {Promise<object>} An object with `issuer`, `jwks`, and full
 *   meta data config in `config`.
 */
export async function checkTargetScopedAccessToken({
  req, issuerConfigUrl, getExpectedValues,
  allowedAlgorithms, maxClockSkew = 300, audience, typ = 'at+jwt'
} = {}) {
  // get expected values
  const expected = await getExpectedValues({req});
  _checkExpectedValues({req, expected});

  // set expected defaults
  expected.action =
    expected.action ?? DEFAULT_ACTION_FOR_METHOD.get(req.method);
  if(expected.action === undefined) {
    const error = new Error(
      `The HTTP method ${req.method} has no expected capability action.`);
    error.name = 'NotSupportedError';
    error.httpStatusCode = 400;
    throw error;
  }
  if(expected.target === undefined) {
    // default expected target is always the full request URL
    expected.target = `https://${expected.host}${req.originalUrl}`;
  }

  // do not allow a custom target to be outside of the scope of the
  // root invocation target (its oauth2 rules only apply to targets within
  // its scope)
  const {rootInvocationTarget} = expected;
  if(!expected.target.startsWith(rootInvocationTarget)) {
    throw new Error(
      `Expected "target" must start with "${rootInvocationTarget}".`);
  }

  if(audience === undefined) {
    audience = rootInvocationTarget;
  }

  const {payload} = await checkAccessToken({
    req, issuerConfigUrl, audience, allowedAlgorithms, maxClockSkew, typ
  });

  // generate required action scope and relative path from action and target
  const requiredActionScope = `${expected.action}:`;
  const path = expected.target.slice(rootInvocationTarget.length) || '/';

  // ensure scope matches...
  const scopes = payload.scope?.split(' ') || [];
  for(const scope of scopes) {
    // require exact `action` match
    if(!scope.startsWith(requiredActionScope)) {
      continue;
    }
    // allow hierarchical, HTTP path- or query- based attenuation
    const pathScope = scope.slice(requiredActionScope.length);
    if(pathScope === '/') {
      // full path access granted
      return true;
    }
    // `pathScope` must terminate just before a path or query delimiter
    if(path.startsWith(pathScope)) {
      const rest = path.slice(pathScope.length);
      if(rest.length === 0 || rest.startsWith('/') || rest.startsWith('?') ||
        rest.startsWith('&') || rest.startsWith('#')) {
        return true;
      }
    }
  }

  throw new BedrockError(
    'Access token validation failed.', {
      name: 'NotAllowedError',
      details: {
        httpStatusCode: 403,
        public: true,
        code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
        reason: `Access token "scope" is insufficient.`,
        claim: 'scope'
      }
    });
}

function _checkExpectedValues({expected}) {
  if(!(expected && typeof expected === 'object')) {
    throw new TypeError('"getExpectedValues" must return an object.');
  }

  const {action, host, rootInvocationTarget, target} = expected;

  // expected `action` is optional
  if(!(action === undefined || typeof action === 'string')) {
    throw new TypeError('Expected "action" must be a string.');
  }

  // expected `host` is required
  if(typeof host !== 'string') {
    throw new TypeError('Expected "host" must be a string.');
  }

  // expected `rootInvocationTarget` is required
  if(!(typeof rootInvocationTarget === 'string' &&
    rootInvocationTarget.includes(':'))) {
    throw new Error(
      'Expected "rootInvocationTarget" must be a string ' +
      'that expresses an absolute URI.');
  }

  // expected `target` is optional
  if(target !== undefined &&
    !(typeof target === 'string' && target.includes(':'))) {
    throw new Error(
      'Expected "target" must be a string that expresses an absolute ' +
      'URI.');
  }
}
