import assert from 'node:assert/strict';
import { test } from 'node:test';
import http from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket, { WebSocketServer } from 'ws';
import { generateKeyPair, SignJWT } from 'jose';
import { createGateway, verifier } from '../gateway.mjs';

const config = { issuer: 'https://test.cloudflareaccess.com', audience: 'expected-audience',
  email: 'owner@example.com', hostname: 'computer.example.com' };
const { privateKey, publicKey } = await generateKeyPair('RS256');
const verify = verifier(config, publicKey);
const sign = async (changes = {}, key = privateKey) => {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: config.issuer, aud: config.audience, email: config.email,
    sub: 'owner', iat: now, exp: now + 60, ...changes })
    .setProtectedHeader({ alg: 'RS256' }).sign(key);
};
async function fixture(t, extra = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'terminal-gw-'));
  const socketPath = join(dir, 'terminal.sock');
  const observed = [];
  const upstream = http.createServer((req, res) => { observed.push(req.headers); res.end('terminal'); });
  const upstreamWS = new WebSocketServer({ server: upstream });
  upstreamWS.on('connection', (ws, req) => {
    observed.push(req.headers);
    ws.on('message', (data, binary) => ws.send(data, { binary }));
    ws.on('error', () => {});
  });
  upstream.listen(socketPath); await once(upstream, 'listening');
  const gateway = createGateway({ ...config, socketPath, verify, ...extra });
  gateway.listen(0, '127.0.0.1'); await once(gateway, 'listening');
  const port = gateway.address().port;
  const clients = new Set();
  t.after(async () => {
    for (const ws of clients) ws.terminate();
    gateway.closeConnections();
    for (const ws of upstreamWS.clients) ws.terminate();
    await new Promise(resolve => gateway.close(resolve));
    await new Promise(resolve => upstream.close(resolve));
    await rm(dir, { recursive: true, force: true });
  });
  const request = headers => new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port, headers }, r => {
      r.resume(); r.on('end', () => resolve(r.statusCode));
    }).on('error', reject);
  });
  const open = async (token, extraHeaders = {}, query = '') => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws${query}`, 'tty', { headers: {
      host: config.hostname, origin: `https://${config.hostname}`,
      'cf-access-jwt-assertion': token, ...extraHeaders } });
    clients.add(ws); ws.on('error', () => {});
    await once(ws, 'open'); return ws;
  };
  return { request, open, observed, upstreamWS };
}
test('only correctly signed, current tokens for this app and identity pass', async () => {
  assert.equal((await verify(await sign())).sub, 'owner');
  for (const changes of [{ email: 'other@example.com' }, { aud: 'other-app' },
    { iss: 'https://other.example.com' }, { exp: 1 }, { sub: '' }, { exp: undefined },
    { iat: Math.floor(Date.now() / 1000) - 3700 }])
    await assert.rejects(() => sign(changes).then(verify));
  const attacker = await generateKeyPair('RS256');
  await assert.rejects(() => sign({}, attacker.privateKey).then(verify));
  await assert.rejects(() => verify(undefined));
  await assert.rejects(() => verify('forged'));
});
test('HTTP/WS enforce identity and origin and never forward private headers', async t => {
  const f = await fixture(t), token = await sign();
  const base = { host: config.hostname, 'cf-access-jwt-assertion': token };
  assert.equal(await f.request({ host: config.hostname }), 403);
  assert.equal(await f.request({ ...base, host: 'alternate.example.com' }), 403);
  assert.equal(await f.request({ ...base, origin: 'https://attacker.example.com' }), 403);
  assert.equal(await f.request({ ...base, cookie: 'private=value', authorization: 'private' }), 200);
  await assert.rejects(() => f.open('forged'), /403/);
  await assert.rejects(() => f.open(token, { origin: 'https://attacker.example.com' }), /403/);
  const ws = await f.open(token, { cookie: 'private=value', authorization: 'private' });
  ws.send(Buffer.from('0hello'));
  assert.equal((await once(ws, 'message'))[0].toString(), '0hello');
  for (const headers of f.observed) {
    assert.equal(headers['cf-access-jwt-assertion'], undefined);
    assert.equal(headers.cookie, undefined); assert.equal(headers.authorization, undefined);
  }
});
test('an open connection ends when its Access token expires', { timeout: 6000 }, async t => {
  const f = await fixture(t);
  const exp = Math.floor(Date.now() / 1000) + 2;
  const ws = await f.open(await sign({ exp }));
  const [code, reason] = await once(ws, 'close');
  assert.equal(code, 1000); assert.equal(reason.toString(), 'Login expired');
  assert.ok(Date.now() >= exp * 1000 - 50);
});
test('new valid connection replaces old; failed authentication cannot evict it', async t => {
  const f = await fixture(t), token = await sign();
  const first = await f.open(token);
  await assert.rejects(() => f.open('forged'), /403/);
  assert.equal(first.readyState, WebSocket.OPEN);
  const closed = once(first, 'close');
  const second = await f.open(token);
  assert.equal((await closed)[1].toString(), 'Opened in another browser');
  second.send(Buffer.from('0still running'));
  assert.equal((await once(second, 'message'))[0].toString(), '0still running');
});
test('output, flow control, resize and ping cannot keep an idle browser alive', { timeout: 5000 }, async t => {
  const f = await fixture(t, { idleTimeoutMs: 350 });
  const ws = await f.open(await sign());
  const interval = setInterval(() => {
    if (ws.readyState !== WebSocket.OPEN) return;
    ws.send(Buffer.from('3')); ws.send(Buffer.from('1{"columns":80}')); ws.ping();
    for (const peer of f.upstreamWS.clients) peer.send(Buffer.from('0background output'));
  }, 30);
  t.after(() => clearInterval(interval));
  const [code, reason] = await once(ws, 'close');
  assert.equal(code, 1000); assert.equal(reason.toString(), 'Disconnected after inactivity');
});
test('real terminal input resets inactivity, including fragmented messages', { timeout: 5000 }, async t => {
  const f = await fixture(t, { idleTimeoutMs: 500 });
  const ws = await f.open(await sign());
  await delay(300);
  ws.send(Buffer.from('0'), { fin: false }); ws.send(Buffer.from('input'), { fin: true });
  await once(ws, 'message');
  await delay(300);
  assert.equal(ws.readyState, WebSocket.OPEN);
  assert.equal((await once(ws, 'close'))[1].toString(), 'Disconnected after inactivity');
});
test('fresh gate is checked before upstream connection or replacing the active browser', async t => {
  let allowed = true;
  const f = await fixture(t, { freshLogin: { consume() {
    if (!allowed) throw new Error('No fresh ceremony'); allowed = false;
  } } });
  const token = await sign(), first = await f.open(token);
  await assert.rejects(() => f.open(token), /403/);
  assert.equal(first.readyState, WebSocket.OPEN);
});
