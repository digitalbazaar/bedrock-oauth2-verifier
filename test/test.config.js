/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import '@bedrock/https-agent';
import '@bedrock/oauth2-verifier';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

config.mocha.options.fullTrace = true;
config.mocha.tests.push(path.join(__dirname, 'mocha'));

// allow self-signed certs in test framework
config['https-agent'].rejectUnauthorized = false;
