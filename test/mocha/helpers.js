/*
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {importJWK, SignJWT} from 'jose';

import {mockData} from './mock.data.js';

export async function getOAuth2AccessToken({
  audience, exp, iss, nbf, typ = 'at+jwt'
}) {
  const scope = 'read:/';
  const builder = new SignJWT({scope})
    .setProtectedHeader({alg: 'EdDSA', typ})
    .setIssuer(iss ?? mockData.oauth2Config.issuer)
    .setAudience(audience);
  if(exp !== undefined) {
    builder.setExpirationTime(exp);
  } else {
    // default to 5 minute expiration time
    builder.setExpirationTime('5m');
  }
  if(nbf !== undefined) {
    builder.setNotBefore(nbf);
  }
  const key = await importJWK({...mockData.ed25519KeyPair, alg: 'EdDSA'});
  return builder.sign(key);
}

export function createRequest({accessToken, credentials}) {
  if(accessToken !== undefined) {
    return {
      get() {
        return `Bearer ${accessToken}`;
      }
    };
  }
  const {userId, password} = credentials;
  const b64 = Buffer.from(`${userId}:${password}`).toString('base64');
  return {
    get() {
      return `Basic ${b64}`;
    }
  };
}
