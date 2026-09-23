import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { FreshLogin } from '../fresh-login.mjs';

const { privateKey, publicKey } = await generateKeyPair('RS256');
const config = { hostname: 'terminal.example.com', email: 'owner@example.com', ownerSubject: '1',
  clientId: 'fresh-terminal', oidcIssuer: 'https://auth.example.com/application/o/fresh/',
  authorizationEndpoint: 'https://auth.example.com/application/o/authorize/',
  redirectUri: 'https://terminal.example.com/callback' };
const identity = { sub: 'cloudflare-owner' };
function capture() {
  return { writeHead(status, headers) { this.status = status; this.headers = headers; return this; },
    end(body) { this.body = body; return this; } };
}
async function attempt(changes = {}) {
  let requested, exchangeCount = 0;
  const gate = new FreshLogin(config, { keys: publicKey,
    render: async () => '<html><head></head><body>terminal</body></html>',
    exchange: async (_code, verifier) => {
      exchangeCount++;
      assert.equal(createHash('sha256').update(verifier).digest('base64url'), requested.searchParams.get('code_challenge'));
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({ iss: config.oidcIssuer, aud: config.clientId, sub: config.ownerSubject,
        email: config.email, nonce: requested.searchParams.get('nonce'), auth_time: now,
        amr: ['user'], iat: now, exp: now + 60, ...changes })
        .setProtectedHeader({ alg: 'RS256' }).sign(privateKey);
    } });
  const begin = capture();
  await gate.handle({ url: '/', headers: {} }, begin, identity);
  assert.equal(begin.status, 302);
  assert.match(begin.headers['set-cookie'], /Secure; HttpOnly; SameSite=Lax/);
  assert.equal(begin.headers['cache-control'], 'no-store');
  requested = new URL(begin.headers.location);
  assert.equal(requested.searchParams.get('code_challenge_method'), 'S256');
  const state = requested.searchParams.get('state');
  const callback = { url: `/callback?code=one-use-code&state=${state}`,
    headers: { cookie: begin.headers['set-cookie'].split(';')[0] } };
  return { gate, callback, exchanges: () => exchangeCount };
}
test('fresh signed callback creates only a short-lived, single-use, subject-bound ticket', async () => {
  const { gate, callback, exchanges } = await attempt();
  const response = capture(); await gate.handle(callback, response, identity);
  assert.equal(response.status, 200); assert.equal(exchanges(), 1);
  assert.match(response.headers['set-cookie'], /Max-Age=0/);
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.match(response.body, /Sign in with your YubiKey/);
  assert.doesNotMatch(response.body, /localStorage|sessionStorage/);
  const ticket = response.body.match(/\/ws\?ticket=([\w-]+)/)[1];
  const request = { url: `/ws?ticket=${ticket}` };
  gate.consume(request, identity);
  assert.throws(() => gate.consume(request, identity), /Fresh login required/);
  const replay = capture(); await gate.handle(callback, replay, identity);
  assert.equal(replay.status, 403); assert.equal(exchanges(), 1);
});
test('a retained identity cookie cannot itself create a terminal attachment', async () => {
  const { gate } = await attempt();
  assert.throws(() => gate.consume({ url: '/ws' }, identity), /Fresh login required/);
  const response = capture();
  await gate.handle({ url: '/', headers: { cookie: 'CF_Authorization=existing-login' } }, response, identity);
  assert.equal(response.status, 302);
  assert.match(response.headers.location, /application\/o\/authorize/);
});
test('wrong state cookie, old authentication, wrong nonce/subject/audience/issuer/AMR fail closed', async () => {
  const badCookie = await attempt(), denied = capture();
  await badCookie.gate.handle({ ...badCookie.callback, headers: { cookie: 'wrong=value' } }, denied, identity);
  assert.equal(denied.status, 403); assert.equal(badCookie.exchanges(), 0);
  for (const change of [{ auth_time: 1 }, { nonce: 'wrong' }, { sub: '6' },
    { aud: 'other' }, { iss: 'https://other.example.com/' }, { email: 'other@example.com' },
    { amr: ['pwd'] }, { exp: 1 }, { auth_time: undefined }]) {
    const { gate, callback } = await attempt(change), response = capture();
    await gate.handle(callback, response, identity);
    assert.equal(response.status, 403, JSON.stringify(change));
    assert.equal(gate.tickets.size, 0);
  }
});
test('tickets expire and cannot be transferred to another Access subject', async () => {
  for (const expired of [false, true]) {
    const { gate, callback } = await attempt(), response = capture();
    await gate.handle(callback, response, identity);
    const ticket = response.body.match(/\/ws\?ticket=([\w-]+)/)[1];
    if (expired) gate.tickets.get(ticket).expires = 1;
    assert.throws(() => gate.consume({ url: `/ws?ticket=${ticket}` },
      expired ? identity : { sub: 'another-user' }), /Fresh login required/);
    assert.throws(() => gate.consume({ url: `/ws?ticket=${ticket}` }, identity), /Fresh login required/);
  }
});
