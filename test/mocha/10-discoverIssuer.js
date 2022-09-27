/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import {discoverIssuer} from '@bedrock/oauth2-verifier';
import {mockData} from './mock.data.js';

const {baseUrl} = mockData;

describe('discoverIssuer', () => {
  const issuerConfigUrl = `${baseUrl}${mockData.oauth2IssuerConfigRoute}`;
  const invalidIssuerConfigUrl = baseUrl;

  it('gets an issuer config', async () => {
    let err;
    let result;
    try {
      result = await discoverIssuer({issuerConfigUrl});
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result);
    result.should.have.keys(['issuer', 'jwks', 'config']);
    result.issuer.should.equal(mockData.oauth2Config.issuer);
  });
  it('throws error on bad `issuerConfigUrl`', async () => {
    let err;
    let result;
    try {
      result = await discoverIssuer({issuerConfigUrl: invalidIssuerConfigUrl});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.data.details.errors.should.have.length(1);
    const [error] = err.data.details.errors;
    error.name.should.equal('XXXError');
    error.message.should.contain('YYY');
  });
});
