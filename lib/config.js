/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';

const cfg = config['oauth2-verifier'] = {};

// FIXME: bikeshed format
cfg.authorization = {
  // 300 second clock skew permitted by default
  maxClockSkew: 300,
  // options for authz server configs
  issuerConfig: {
    // params for fetching issuer config related files
    fetchOptions: {
      // max size for issuer config related responses; applies to both
      // issuer authz server config and JWKs (in bytes, ~8 KiB)
      size: 8192,
      // timeout in ms for fetching an issuer config / JWKs
      timeout: 5000
    },
    cache: {
      // ~800 KiB cache ~= 1 MiB max size
      maxSize: 100,
      // 10 minute max age
      maxAge: 10 * 60 * 1000
    }
  },
  /*supportedAlgorithms: [
    // RSASSA-PKCS1-v1_ w/sha-XXX
    'RS256',
    'RS384',
    'RS512',
    // RSASSA-PSS w/ SHA-XXX
    'PS256',
    'PS384',
    'PS512',
    // ECDSA w/ SHA-XXX
    'ES256',
    'ES256K',
    'ES384',
    'ES512',
    // ed25519 / ed448
    'EdDSA'
  ]*/
};
