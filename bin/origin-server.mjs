#!/usr/bin/env node
import { loadDeployment } from '../deployment.mjs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { verifier } from '../gateway.mjs';
import { createPortalGateway } from '../portal-gateway.mjs';
import { portalPage } from '../portal-view.mjs';
import { FreshLogin } from '../fresh-login.mjs';
import { readFileSync } from 'node:fs';

const deployment = loadDeployment();
const runtime = join(homedir(), 'Library/Application Support/key-c');
const state = JSON.parse(readFileSync(join(runtime, 'authentik-state.json'), 'utf8'));
if (!Number.isInteger(state.owner_id) || state.owner_id <= 0) throw new Error('Configure the authentik owner first.');
const identityOrigin = 'https://' + deployment.identity_hostname;
const config = {
  hostname: deployment.hostname,
  issuer: 'https://' + deployment.team_domain,
  audience: deployment.access_audience,
  email: deployment.owner_email,
  socketPath: join(homedir(), 'Library/Application Support/key-c/run/ttyd.sock'),
};
const credentials = JSON.parse(readFileSync(join(homedir(),
  'Library/Application Support/key-c/secrets/fresh-oidc.json'), 'utf8'));
const freshLogin = new FreshLogin({ ...config, clientId: credentials.client_id,
  clientSecret: credentials.client_secret, ownerSubject: String(state.owner_id),
  oidcIssuer: identityOrigin + '/application/o/terminal-fresh/',
  authorizationEndpoint: identityOrigin + '/application/o/authorize/',
  tokenEndpoint: identityOrigin + '/application/o/token/',
  redirectUri: 'https://' + config.hostname + '/callback',
}, { renderAuthorized: portalPage });
const server = createPortalGateway({ ...config, freshLogin, verify: verifier(config),
  assetDirectory: join(runtime, 'paseo/node_modules/@getpaseo/server/dist/server/web-ui'),
});
server.listen(17682, '127.0.0.1', () => console.log('Origin listening on loopback with Access JWT validation.'));
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => {
  server.closeConnections(); server.close(() => process.exit(0));
});
