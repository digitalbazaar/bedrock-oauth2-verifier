/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {checkAccessToken} from '@bedrock/oauth2-verifier';
import {mockData} from './mock.data.js';

const {baseUrl} = mockData;

describe('checkAccessToken', () => {
  const audience = 'test:audience';
  const issuerConfigUrl = `${baseUrl}${mockData.oauth2IssuerConfigRoute}`;

  it('passes on a valid token passed via "Bearer" header', async () => {
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
    result.should.have.include.keys(['protectedHeader', 'payload']);
  });
  it('passes on a valid token passed via "jwt" param', async () => {
    const jwt = await helpers.getOAuth2AccessToken({audience});
    let err;
    let result;
    try {
      result = await checkAccessToken({jwt, issuerConfigUrl, audience});
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result);
    result.should.have.include.keys(['protectedHeader', 'payload']);
  });
  it('passes on a valid token with custom "typ" claim', async () => {
    const jwt = await helpers.getOAuth2AccessToken({
      audience,
      typ: 'jwt'
    });
    let err;
    let result;
    try {
      result = await checkAccessToken({
        jwt, issuerConfigUrl, audience, typ: 'jwt'
      });
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result);
    result.should.have.include.keys(['protectedHeader', 'payload']);
  });
  it('passes on a valid token with any "typ" claim', async () => {
    const jwt = await helpers.getOAuth2AccessToken({
      audience,
      typ: 'anything'
    });
    let err;
    let result;
    try {
      result = await checkAccessToken({
        jwt, issuerConfigUrl, audience, typ: false
      });
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result);
    result.should.have.include.keys(['protectedHeader', 'payload']);
  });
  it('fails when passed neither "req" nor "jwt"', async () => {
    let err;
    let result;
    try {
      result = await checkAccessToken({issuerConfigUrl, audience});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.name.should.equal('TypeError');
  });
  it('fails when passed both "req" and "jwt"', async () => {
    const accessToken = await helpers.getOAuth2AccessToken({audience});
    const req = helpers.createRequest({accessToken});
    let err;
    let result;
    try {
      result = await checkAccessToken({
        req, jwt: accessToken, issuerConfigUrl, audience
      });
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.name.should.equal('TypeError');
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
    err.name.should.equal('NotAllowedError');
    should.exist(err.details);
    err.details.should.have.include.keys(['httpStatusCode', 'code', 'claim']);
    err.details.httpStatusCode.should.equal(403);
    err.details.code.should.equal('ERR_JWT_EXPIRED');
    err.details.claim.should.equal('exp');
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
    err.name.should.equal('NotAllowedError');
    should.exist(err.details);
    err.details.should.have.include.keys(['httpStatusCode', 'code', 'claim']);
    err.details.httpStatusCode.should.equal(403);
    err.details.code.should.equal('ERR_JWT_CLAIM_VALIDATION_FAILED');
    err.details.claim.should.equal('nbf');
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
    err.name.should.equal('NotAllowedError');
    should.exist(err.details);
    err.details.should.have.include.keys(['httpStatusCode', 'code', 'claim']);
    err.details.httpStatusCode.should.equal(403);
    err.details.code.should.equal('ERR_JWT_CLAIM_VALIDATION_FAILED');
    err.details.claim.should.equal('typ');
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
    err.name.should.equal('NotAllowedError');
    should.exist(err.details);
    err.details.should.have.include.keys(['httpStatusCode', 'code', 'claim']);
    err.details.httpStatusCode.should.equal(403);
    err.details.code.should.equal('ERR_JWT_CLAIM_VALIDATION_FAILED');
    err.details.claim.should.equal('iss');
  });
});
