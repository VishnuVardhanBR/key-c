import assert from 'node:assert/strict';
import { test } from 'node:test';
import http from 'node:http';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket, { WebSocketServer } from 'ws';
import { createPortalGateway } from '../portal-gateway.mjs';

async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'key-c-test-'));
  const socketPath = join(directory, 'terminal.sock');
  await writeFile(join(directory, 'metadata.json'), '{"static":true}');
  const observed = [], clients = new Set(), tickets = new Set(['fresh-one', 'fresh-two', 'fresh-three']);
  const responder = (req, res) => {
    observed.push({ headers: req.headers, url: req.url });
    res.setHeader('content-type', req.url === '/' ? 'text/html' : 'application/json');
    res.end(req.url === '/' ? '<html><head></head><body>app</body></html>' : '{"ok":true}');
  };
  const vncClients = new Set();
  let vncConnections = 0;
  const vnc = net.createServer(peer => {
    vncConnections++; vncClients.add(peer);
    peer.on('data', data => peer.write(data));
    peer.on('error', () => {}); peer.on('close', () => vncClients.delete(peer));
  });
  vnc.listen(0, '127.0.0.1'); await once(vnc, 'listening');
  const terminal = http.createServer(responder), paseo = http.createServer(responder);
  terminal.listen(socketPath); paseo.listen(0, '127.0.0.1');
  await Promise.all([once(terminal, 'listening'), once(paseo, 'listening')]);
  const backends = [terminal, paseo].map(server => {
    const ws = new WebSocketServer({ server });
    ws.on('connection', (peer, req) => {
      observed.push({ headers: req.headers, url: req.url });
      peer.on('message', (data, binary) => peer.send(data, { binary })); peer.on('error', () => {});
    });
    return ws;
  });
  let expiry = Math.floor(Date.now() / 1000) + 60;
  const gateway = createPortalGateway({ hostname: 'computer.example.com', socketPath,
    vncPort: vnc.address().port, paseoPort: paseo.address().port, paseoPassword: 'backend-secret-not-for-browser', assetDirectory: directory,
    verify: async token => { if (token !== 'valid') throw Error('Denied'); return { sub: 'owner', exp: expiry }; },
    freshLogin: { consume(req) { const ticket = new URL(req.url, 'https://computer.example.com').searchParams.get('ticket');
      if (!tickets.delete(ticket)) throw Error('Fresh key required'); },
      handle(req, res) { res.writeHead(302, { location: '/fresh-key' }).end(); } }, ...options });
  gateway.listen(0, '127.0.0.1'); await once(gateway, 'listening');
  const port = gateway.address().port;
  const headers = { host: 'computer.example.com', origin: 'https://computer.example.com', 'cf-access-jwt-assertion': 'valid' };
  const request = (path, token, extra = {}) => new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, path, method: extra.method ?? 'GET',
      headers: { ...headers, ...(token ? { authorization: 'Bearer ' + token } : {}), ...extra.headers } }, res => {
      let body = ''; res.on('data', chunk => body += chunk); res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
    }); req.on('error', reject); req.end(extra.body);
  });
  const open = async (path, protocol) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}${path}`, protocol, { headers });
    clients.add(ws); ws.on('error', () => {});
    const ready = path.startsWith('/session') ? once(ws, 'message') : undefined;
    ready?.catch(() => {});
    await once(ws, 'open'); return { ws, token: ready ? JSON.parse((await ready)[0]).token : undefined };
  };
  const control = ticket => open('/session?ticket=' + ticket, 'key-c');
  const launch = async (token, app = 'paseo') => {
    const response = await request('/launch', token, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ app }) });
    assert.equal(response.status, 200); return JSON.parse(response.body).url;
  };
  t.after(async () => {
    gateway.closeConnections(); for (const ws of clients) ws.terminate();
    for (const peer of vncClients) peer.destroy();
    for (const backend of backends) for (const peer of backend.clients) peer.terminate();
    await Promise.all([gateway, terminal, paseo, vnc].map(server => new Promise(resolve => server.close(resolve))));
    await rm(directory, { recursive: true, force: true });
  });
  return { request, open, control, launch, observed, port, headers, vncClients, vncConnections: () => vncConnections, expiry: value => expiry = value };
}

test('all apps require a fresh key, one-use document grant, and active in-memory session', async t => {
  const f = await fixture(t);
  assert.equal((await f.request('/api/status')).status, 403);
  await assert.rejects(() => f.open('/ws', undefined), /403/);
  await assert.rejects(() => f.control('missing'), /403/);
  const { ws, token } = await f.control('fresh-one');
  await assert.rejects(() => f.control('fresh-one'), /403/);
  assert.equal((await f.request('/api/status', token)).status, 200);
  for (const app of ['terminal', 'paseo', 'novnc']) {
    const url = await f.launch(token, app), page = await f.request(url);
    assert.equal(page.status, 200); assert.match(page.body, /bridgeClient/);
    assert.doesNotMatch(page.body, /backend-secret-not-for-browser/);
    assert.equal((await f.request(url)).status, 403);
  }
  const peer = await f.open('/ws?__key_c=' + token), terminal = await f.open('/terminal/ws?__key_c=' + token, 'tty');
  peer.ws.send('chat'); assert.equal((await once(peer.ws, 'message'))[0].toString(), 'chat');
  terminal.ws.send(Buffer.from('0command')); assert.equal((await once(terminal.ws, 'message'))[0].toString(), '0command');
  const closed = once(peer.ws, 'close'); ws.close(); await closed;
  assert.equal((await f.request('/api/status', token)).status, 403);
  await assert.rejects(() => f.open('/ws?__key_c=' + token), /403/);
});

test('replacement invalidates old HTTP, sockets, and unused launch grants; a failed login cannot evict', async t => {
  const f = await fixture(t), first = await f.control('fresh-one');
  const url = await f.launch(first.token);
  await assert.rejects(() => f.control('invalid'), /403/);
  assert.equal((await f.request('/api/status', first.token)).status, 200);
  const closed = once(first.ws, 'close');
  const second = await f.control('fresh-two');
  assert.equal((await closed)[1].toString(), 'Opened in another browser');
  assert.equal((await f.request('/api/status', first.token)).status, 403);
  assert.equal((await f.request(url)).status, 403);
  assert.equal((await f.request('/api/status', second.token)).status, 200);
});

test('background app traffic does not extend idle; interaction extends it; Access expiry closes it', async t => {
  const f = await fixture(t, { idleTimeoutMs: 400 }), first = await f.control('fresh-one');
  const peer = await f.open('/ws?__key_c=' + first.token);
  const traffic = setInterval(() => { if (peer.ws.readyState === WebSocket.OPEN) peer.ws.send('background'); }, 30);
  t.after(() => clearInterval(traffic));
  assert.equal((await once(first.ws, 'close'))[1].toString(), 'Disconnected after inactivity');
  const second = await f.control('fresh-two');
  await delay(250); second.ws.send('activity'); await delay(250);
  assert.equal(second.ws.readyState, WebSocket.OPEN);
  second.ws.close();
  f.expiry(Date.now() / 1000 + 0.15);
  const third = await f.control('fresh-three');
  assert.equal((await once(third.ws, 'close'))[1].toString(), 'Login expired');
});

test('proxy strips client credentials and query grants; mutations need same origin; static files expose no API', async t => {
  const f = await fixture(t), { token } = await f.control('fresh-one');
  assert.equal((await f.request('/api/status?__key_c=' + token, undefined, { headers: { cookie: 'private=secret' } })).status, 200);
  const latest = f.observed.at(-1);
  assert.equal(latest.url, '/api/status');
  assert.equal(latest.headers.authorization, 'Bearer backend-secret-not-for-browser');
  assert.equal(latest.headers.cookie, undefined); assert.equal(latest.headers['cf-access-jwt-assertion'], undefined);
  assert.equal((await f.request('/launch', token, { method: 'POST', headers: { origin: 'https://other.example.com' } })).status, 403);
  assert.equal((await f.request('/metadata.json')).status, 200);
  assert.equal((await f.request('/assets/%2e%2e%2f%2e%2e%2fetc/passwd')).status, 404);
  assert.equal((await f.request('/api/health')).status, 403);
  assert.equal((await f.request('/api/files/download?token=upstream-only')).status, 403);
});

test('malformed HTTP and upgrade targets cannot interrupt the active session', async t => {
  const f = await fixture(t), { token } = await f.control('fresh-one');
  assert.equal((await f.request('//[')).status, 400);
  const socket = net.connect(f.port, '127.0.0.1');
  await once(socket, 'connect');
  const response = once(socket, 'data');
  socket.write('GET //[ HTTP/1.1\r\nHost: computer.example.com\r\nOrigin: https://computer.example.com\r\n' +
    'Cf-Access-Jwt-Assertion: valid\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n' +
    'Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ' + randomBytes(16).toString('base64') + '\r\n\r\n');
  assert.match((await response)[0].toString(), /^HTTP\/1.1 403/); socket.destroy();
  assert.equal((await f.request('/api/status', token)).status, 200);
});

test('aborted launch bodies cannot interrupt the gateway or active session', async t => {
  const f = await fixture(t), { token } = await f.control('fresh-one');
  const socket = net.connect(f.port, '127.0.0.1');
  await once(socket, 'connect');
  socket.write('POST /launch HTTP/1.1\r\nHost: computer.example.com\r\nOrigin: https://computer.example.com\r\n' +
    'Cf-Access-Jwt-Assertion: valid\r\nAuthorization: Bearer ' + token + '\r\nContent-Length: 50\r\n\r\n{');
  await delay(40); socket.destroy(); await delay(40);
  assert.equal((await f.request('/api/status', token)).status, 200);
  assert.equal((await f.request(await f.launch(token))).status, 200);
});


test('noVNC requires active auth and binary protocol before opening the fixed TCP backend', async t => {
  const f = await fixture(t);
  await assert.rejects(() => f.open('/novnc/ws', 'binary'), /403/);
  assert.equal(f.vncConnections(), 0);
  const { ws, token } = await f.control('fresh-one');
  await assert.rejects(() => f.open('/novnc/ws?__key_c=' + token), /403/);
  assert.equal(f.vncConnections(), 0);
  const peer = await f.open('/novnc/ws?host=other.example.com&port=22&__key_c=' + token, 'binary');
  assert.equal(f.vncConnections(), 1);
  const binary = Buffer.from([0, 255, 13, 10, 128]);
  peer.ws.send(binary);
  const [message, isBinary] = await once(peer.ws, 'message');
  assert.deepEqual(message, binary); assert.equal(isBinary, true);
  const closed = once(peer.ws, 'close'); ws.close(); await closed;
  await delay(30); assert.equal(f.vncClients.size, 0);
  await assert.rejects(() => f.open('/novnc/ws?__key_c=' + token, 'binary'), /403/);
});

test('noVNC sockets are revoked on browser replacement, inactivity, and Access expiry', async t => {
  const f = await fixture(t, { idleTimeoutMs: 250 });
  const first = await f.control('fresh-one');
  const peer = await f.open('/novnc/ws?__key_c=' + first.token, 'binary');
  const closed = once(peer.ws, 'close');
  const second = await f.control('fresh-two'); await closed;
  const next = await f.open('/novnc/ws?__key_c=' + second.token, 'binary');
  const traffic = setInterval(() => { if (next.ws.readyState === WebSocket.OPEN) next.ws.send(Buffer.from('frame')); }, 30);
  t.after(() => clearInterval(traffic));
  await once(next.ws, 'close'); assert.equal(second.ws.readyState, WebSocket.CLOSED);
  f.expiry(Date.now() / 1000 + 0.15);
  const third = await f.control('fresh-three');
  const last = await f.open('/novnc/ws?__key_c=' + third.token, 'binary');
  await once(last.ws, 'close'); await delay(30); assert.equal(f.vncClients.size, 0);
});

test('noVNC assets are confined to the installed library; the document is one-use and uncached', async t => {
  const f = await fixture(t);
  assert.equal((await f.request('/novnc/core/rfb.js')).status, 200);
  assert.equal((await f.request('/novnc/core/rfb.js', undefined, { headers: { 'cf-access-jwt-assertion': 'invalid' } })).status, 403);
  const { token } = await f.control('fresh-one');
  for (const path of ['/novnc/package.json', '/novnc/core/%2e%2e%2f%2e%2e%2fpackage.json', '/novnc/core/%2e%2e%2f%2e%2e%2foutside.js'])
    assert.equal((await f.request(path, token)).status, 404);
  const url = await f.launch(token, 'novnc');
  const page = await f.request(url);
  assert.equal(page.status, 200); assert.equal(page.headers['cache-control'], 'no-store');
  assert.match(page.body, /novncClient/); assert.match(page.body, /autocomplete="off"/);
  assert.equal((await f.request(url)).status, 403);
  const peer = await f.open('/novnc/ws?__key_c=' + token, 'binary');
  peer.ws.send('text'); await once(peer.ws, 'close');
  assert.equal((await f.request('/api/status', token)).status, 200);
});
