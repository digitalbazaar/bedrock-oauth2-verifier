/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';

const cfg = config['oauth2-verifier'] = {};

// options for authz server (issuer) configs
cfg.issuerConfig = {
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
};
