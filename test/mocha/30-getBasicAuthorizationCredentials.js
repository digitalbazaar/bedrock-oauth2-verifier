/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import {getBasicAuthorizationCredentials} from '@bedrock/oauth2-verifier';

describe('getBasicAuthorizationCredentials', () => {
  // see: https://datatracker.ietf.org/doc/html/rfc7617#section-2
  it('parses RFC 7617 example', async () => {
    const credentials = {userId: 'Aladdin', password: 'open sesame'};
    const req = helpers.createRequest({credentials});

    let err;
    let result;
    try {
      result = await getBasicAuthorizationCredentials({req});
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result);
    result.should.include.keys(['credentials']);
    result.credentials.should.deep.equal(credentials);
  });
  it('fails on a bad "Authorization" header', async () => {
    // create `Bearer` authorization header instead
    const req = helpers.createRequest({accessToken: ''});
    let err;
    let result;
    try {
      result = await getBasicAuthorizationCredentials({req});
    } catch(e) {
      err = e;
    }
    should.exist(err);
    should.not.exist(result);
    err.name.should.equal('DataError');
    err.message.should.equal('Missing or invalid "Authorization" header.');
    err.details.httpStatusCode.should.equal(400);
  });
});
