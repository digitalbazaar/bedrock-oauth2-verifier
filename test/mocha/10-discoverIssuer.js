/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {
  _resetIssuerConfigCache,
  discoverIssuer
} from '@bedrock/oauth2-verifier';
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
    err.status.should.equal(404);
  });
  it('rotates a stored issuer config', async () => {
    // forcibly clear the issuer config cache and set new short TTL
    const ttl = 500;
    _resetIssuerConfigCache({ttl});

    // get initial issuer config
    const {config: issuerConfig1} = await discoverIssuer({issuerConfigUrl});

    // get again; should be same cached value
    await new Promise(r => setTimeout(r, 200));
    const {config: issuerConfig2} = await discoverIssuer({issuerConfigUrl});
    issuerConfig2.should.equal(issuerConfig1);

    // get again; should be a new rotated issuer config
    await new Promise(r => setTimeout(r, 400));
    const {config: issuerConfig3} = await discoverIssuer({issuerConfigUrl});
    issuerConfig3.should.not.equal(issuerConfig1);

    // get again; should be a brand new issuer config
    await new Promise(r => setTimeout(r, 600));
    const {config: issuerConfig4} = await discoverIssuer({issuerConfigUrl});
    issuerConfig4.should.not.equal(issuerConfig3);

    // reset cache to ensure rotation will not occur
    _resetIssuerConfigCache({ttl});

    // get again; should be a brand new issuer config
    await new Promise(r => setTimeout(r, 600));
    const {config: issuerConfig5} = await discoverIssuer({issuerConfigUrl});
    issuerConfig5.should.not.equal(issuerConfig4);

    // reset cache again
    _resetIssuerConfigCache();
  });
});
