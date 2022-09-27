/*!
 * Copyright (c) 2016-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import '@bedrock/express';
import '@bedrock/server';
import '@bedrock/oauth2-verifier';

import {mockData} from './mocha/mock.data.js';

// mock oauth2 authz server routes
bedrock.events.on('bedrock-express.configure.routes', app => {
  app.get(mockData.oauth2IssuerConfigRoute, (req, res) => {
    res.json(mockData.oauth2Config);
  });
  app.get('/oauth2/jwks', (req, res) => {
    res.json(mockData.jwks);
  });
});

import '@bedrock/test';
bedrock.start();
