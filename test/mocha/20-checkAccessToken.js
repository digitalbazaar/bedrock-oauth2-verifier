/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {checkAccessToken} from '@bedrock/oauth2-verifier';
import {mockData} from './mock.data.js';

const {baseUrl} = mockData;

describe('checkAccessToken', () => {
  const audience = 'test:audience';
  const issuerConfigUrl = `${baseUrl}${mockData.oauth2IssuerConfigRoute}`;

  it('passes on a valid token', async () => {
    const accessToken = await helpers.getOAuth2AccessToken({audience});
    const req = helpers.createRequest({accessToken});
    let err;
    let result;
    try {
      result = await checkAccessToken({req, issuerConfigUrl, audience});
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result);
    result.should.have.keys(['protectedHeader', 'payload']);
  });
  it('fails with an expired token', async () => {
    const accessToken = await helpers.getOAuth2AccessToken({
      audience,
      // expired 10 minutes ago
      exp: Math.floor(Date.now() / 1000 - 600)
    });
    const req = helpers.createRequest({accessToken});
    let err;
    let result;
    try {
      result = await checkAccessToken({req, issuerConfigUrl, audience});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.status.should.equal(403);
    err.data.type.should.equal('NotAllowedError');
    should.exist(err.data.cause);
    should.exist(err.data.cause.details);
    should.exist(err.data.cause.details.code);
    err.data.cause.details.code.should.equal('ERR_JWT_EXPIRED');
    should.exist(err.data.cause.details.claim);
    err.data.cause.details.claim.should.equal('exp');
  });
  it('fails on a future "nbf" claim', async () => {
    const accessToken = await helpers.getOAuth2AccessToken({
      audience,
      // 10 minutes from now
      nbf: Math.floor(Date.now() / 1000 + 600)
    });
    const req = helpers.createRequest({accessToken});
    let err;
    let result;
    try {
      result = await checkAccessToken({req, issuerConfigUrl, audience});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.status.should.equal(403);
    err.data.type.should.equal('NotAllowedError');
    should.exist(err.data.cause);
    should.exist(err.data.cause.details);
    should.exist(err.data.cause.details.code);
    err.data.cause.details.code.should.equal(
      'ERR_JWT_CLAIM_VALIDATION_FAILED');
    should.exist(err.data.cause.details.claim);
    err.data.cause.details.claim.should.equal('nbf');
  });
  it('fails on a bad "typ" claim', async () => {
    const accessToken = await helpers.getOAuth2AccessToken({
      audience,
      typ: 'unexpected'
    });
    const req = helpers.createRequest({accessToken});
    let err;
    let result;
    try {
      result = await checkAccessToken({req, issuerConfigUrl, audience});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.status.should.equal(403);
    err.data.type.should.equal('NotAllowedError');
    should.exist(err.data.cause);
    should.exist(err.data.cause.details);
    should.exist(err.data.cause.details.code);
    err.data.cause.details.code.should.equal(
      'ERR_JWT_CLAIM_VALIDATION_FAILED');
    should.exist(err.data.cause.details.claim);
    err.data.cause.details.claim.should.equal('typ');
  });
  it('fails on a bad "iss" claim', async () => {
    const accessToken = await helpers.getOAuth2AccessToken({
      audience,
      iss: 'urn:example:unexpected'
    });
    const req = helpers.createRequest({accessToken});
    let err;
    let result;
    try {
      result = await checkAccessToken({req, issuerConfigUrl, audience});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.status.should.equal(403);
    err.data.type.should.equal('NotAllowedError');
    should.exist(err.data.cause);
    should.exist(err.data.cause.details);
    should.exist(err.data.cause.details.code);
    err.data.cause.details.code.should.equal(
      'ERR_JWT_CLAIM_VALIDATION_FAILED');
    should.exist(err.data.cause.details.claim);
    err.data.cause.details.claim.should.equal('iss');
  });
});
