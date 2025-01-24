/*!
 * Copyright (c) 2021-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';

const {util: {BedrockError}} = bedrock;

const AUTHORIZATION_BASIC_REGEX = /^Basic (.+)$/i;

/**
 * Parses "Basic Authorization" credentials from the given HTTP request. This
 * is useful in conjunction with OAuth2 "client_credentials" grant types.
 *
 * See: https://datatracker.ietf.org/doc/html/rfc7617#section-2 .
 *
 * @param {object} options - The options to use.
 * @param {object} options.req - The HTTP request interface, providing a
 *   `get()` function to access the `authorization` header.
 *
 * @returns {Promise<object>} An object with a `credentials` object that
 *   includes `userId` and `password`.
 */
export function getBasicAuthorizationCredentials({req} = {}) {
  // get basic authorization credentials
  const credentials = req.get('authorization')
    ?.match(AUTHORIZATION_BASIC_REGEX)?.[1];
  if(!credentials) {
    throw new BedrockError(
      'Missing or invalid "Authorization" header.', {
        name: 'DataError',
        details: {
          httpStatusCode: 400,
          public: true
        }
      });
  }

  try {
    // parse credentials
    const parsed = Buffer.from(credentials, 'base64').toString();
    const [userId, ...rest] = parsed.split(':');
    const password = rest.join(':');
    return {credentials: {userId, password}};
  } catch(cause) {
    throw new BedrockError(
      'Could not parse "Authorization" header value.', {
        name: 'DataError',
        details: {
          httpStatusCode: 400,
          public: true
        },
        cause
      });
  }
}
