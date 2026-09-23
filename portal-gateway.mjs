import http from 'node:http';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { readFile, realpath, stat } from 'node:fs/promises';
import { resolve, sep, extname } from 'node:path';
import WebSocket, { WebSocketServer } from 'ws';
import { applicationBridge } from './portal-view.mjs';

const random = () => randomBytes(32).toString('base64url');
const baseHeaders = { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff', 'x-frame-options': 'SAMEORIGIN',
  'content-security-policy': "frame-ancestors 'self'; object-src 'none'; base-uri 'none'" };
const types = { '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf' };
const isAsset = path => /^\/(?:_expo\/static\/|assets\/)/.test(path) ||
  /^\/(?:favicon\.ico|manifest\.json|metadata\.json|apple-touch-icon\.png|pwa-icon-(?:192|512)\.png)$/.test(path);

export function createPortalGateway({ hostname, socketPath, verify, freshLogin, paseoPort = 6767,
  paseoPassword, assetDirectory, idleTimeoutMs = 120000, documentLifetimeMs = 30000 }) {
  let active;
  const rawSockets = new Set();
  const documents = new Map();
  const websocketServer = new WebSocketServer({ noServer: true, perMessageDeflate: false,
    maxPayload: 16 * 1024 * 1024, handleProtocols: protocols =>
      protocols.has('key-c') ? 'key-c' : protocols.has('tty') ? 'tty' : false });
  const send = (response, status, body = '', headers = {}) => {
    response.writeHead(status, { ...baseHeaders, ...headers }); response.end(body);
  };
  const deny = response => response.writeHead ? send(response, 403, 'Unlock key-c with your YubiKey.') :
    response.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  const identity = async (request, upgrade = false) => {
    if (request.headers.host !== hostname || !['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(request.method))
      throw new Error('Wrong host or method');
    const origin = request.headers.origin;
    if ((origin && origin !== `https://${hostname}`) || (upgrade && origin !== `https://${hostname}`))
      throw new Error('Wrong origin');
    if (!['GET', 'HEAD'].includes(request.method) && origin !== `https://${hostname}`)
      throw new Error('Mutation origin required');
    return verify(request.headers['cf-access-jwt-assertion']);
  };
  const authorize = (request, owner) => {
    const url = new URL(request.url, `https://${hostname}`);
    const token = request.headers.authorization?.replace(/^Bearer /, '') ?? url.searchParams.get('__key_c');
    if (!active || active.closed || active.token !== token || active.subject !== owner.sub ||
        active.expiry <= Date.now() || active.lastInput + idleTimeoutMs <= Date.now()) throw new Error('Locked');
    return active;
  };
  const forwardHeaders = (request, terminal = false) => {
    const headers = { host: hostname, origin: `https://${hostname}`, 'x-forwarded-proto': 'https' };
    for (const key of ['accept', 'accept-encoding', 'content-type', 'content-length', 'range', 'user-agent'])
      if (request.headers[key]) headers[key] = request.headers[key];
    if (!terminal && paseoPassword) headers.authorization = 'Bearer ' + paseoPassword;
    return headers;
  };
  const fetchDocument = terminal => new Promise((resolveDocument, reject) => {
    const req = http.get({ ...(terminal ? { socketPath } : { hostname: '127.0.0.1', port: paseoPort }),
      path: '/', headers: { host: hostname, 'x-forwarded-proto': 'https', 'accept-encoding': 'identity',
        ...(!terminal && paseoPassword ? { authorization: 'Bearer ' + paseoPassword } : {}) } }, response => {
      if (response.statusCode !== 200) { response.resume(); reject(new Error('App unavailable')); return; }
      let html = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { html += chunk; if (html.length > 4 * 1024 * 1024) req.destroy(new Error('Response too large')); });
      response.on('end', () => resolveDocument(html)); response.on('error', reject);
    });
    req.setTimeout(10000, () => req.destroy(new Error('App timeout'))); req.on('error', reject);
  });
  async function staticAsset(path, response) {
    const root = await realpath(assetDirectory);
    const candidate = await realpath(resolve(root, '.' + decodeURIComponent(path)));
    if (!candidate.startsWith(root + sep) || !types[extname(candidate)]) throw new Error('Unknown asset');
    const info = await stat(candidate);
    if (!info.isFile() || info.size > 32 * 1024 * 1024) throw new Error('Invalid asset');
    send(response, 200, await readFile(candidate), { 'content-type': types[extname(candidate)] });
  }
  const server = http.createServer({ maxHeaderSize: 32768, requestTimeout: 120000 }, async (request, response) => {
    let owner;
    try { owner = await identity(request); } catch { return deny(response); }
    let url;
    try { url = new URL(request.url, `https://${hostname}`); } catch { return send(response, 400); }
    const path = url.pathname;
    if (['/', '/callback'].includes(path) && request.method === 'GET') {
      try { return await freshLogin.handle(request, response, owner); } catch { return deny(response); }
    }
    if (isAsset(path) && ['GET', 'HEAD'].includes(request.method)) {
      // Only immutable application files, never daemon API responses or user data.
      try { return await staticAsset(path, response); } catch { return send(response, 404); }
    }
    if (/^\/view\/(terminal|paseo)$/.test(path) && request.method === 'GET') {
      const grant = url.searchParams.get('grant'), document = documents.get(grant);
      documents.delete(grant);
      if (!document || document.expires <= Date.now() || document.session !== active ||
          active.closed || active.expiry <= Date.now() || active.lastInput + idleTimeoutMs <= Date.now() ||
          document.subject !== owner.sub || document.app !== path.split('/')[2]) return deny(response);
      const session = active;
      try {
        const html = await fetchDocument(document.app === 'terminal');
        if (session !== active || session.closed || session.expiry <= Date.now() ||
            session.lastInput + idleTimeoutMs <= Date.now() || !html.includes('<head>')) return deny(response);
        return send(response, 200, html.replace('<head>', '<head>' + applicationBridge(document.app, session.token)),
          { 'content-type': 'text/html; charset=utf-8' });
      } catch { return send(response, 502, 'App unavailable. Return to All apps and try again.'); }
    }
    let session;
    try { session = authorize(request, owner); } catch { return deny(response); }
    if (path === '/launch' && request.method === 'POST') {
      try {
        let body = '';
        for await (const chunk of request) {
          body += chunk; if (body.length > 256) return send(response, 413);
        }
        authorize(request, owner);
        const { app } = JSON.parse(body);
        if (!['terminal', 'paseo'].includes(app)) return send(response, 400);
        for (const [key, value] of documents) if (value.expires <= Date.now()) documents.delete(key);
        if (documents.size >= 32) return send(response, 429);
        const grant = random();
        documents.set(grant, { session, app, subject: owner.sub, expires: Date.now() + documentLifetimeMs });
        return send(response, 200, JSON.stringify({ url: `/view/${app}?grant=${grant}` }), { 'content-type': 'application/json' });
      } catch { if (!response.destroyed) return deny(response); return; }
    }
    if (path === '/token' && request.method === 'GET')
      return send(response, 200, '{"token":""}', { 'content-type': 'application/json' });
    if (!/^\/(api|mcp|public)\//.test(path)) return send(response, 404);
    url.searchParams.delete('__key_c');
    const upstream = http.request({ hostname: '127.0.0.1', port: paseoPort,
      method: request.method, path: url.pathname + url.search, headers: forwardHeaders(request) }, incoming => {
      if (session.closed) { upstream.destroy(); return response.destroy(); }
      const headers = {};
      for (const key of ['content-type', 'content-disposition', 'content-length', 'content-encoding', 'content-range', 'accept-ranges'])
        if (incoming.headers[key]) headers[key] = incoming.headers[key];
      response.writeHead(incoming.statusCode, { ...headers, ...baseHeaders }); incoming.pipe(response);
    });
    const stop = () => { upstream.destroy(); response.destroy(); };
    session.jobs.add(stop);
    response.on('close', () => { session.jobs.delete(stop); upstream.destroy(); });
    upstream.on('error', () => { if (!response.headersSent) send(response, 502); else response.end(); });
    upstream.setTimeout(120000, () => upstream.destroy()); request.pipe(upstream);
  });
  server.on('upgrade', async (request, client, head) => {
    client.on('error', () => client.destroy());
    rawSockets.add(client); client.on('close', () => rawSockets.delete(client));
    let owner;
    try { owner = await identity(request, true); } catch { return deny(client); }
    let url;
    try { url = new URL(request.url, `https://${hostname}`); } catch { return deny(client); }
    if (url.pathname === '/session') {
      if (request.headers['sec-websocket-protocol'] !== 'key-c') return deny(client);
      try { freshLogin.consume(request, owner); } catch { return deny(client); }
      if (client.destroyed || owner.exp * 1000 <= Date.now()) return client.destroy();
      return websocketServer.handleUpgrade(request, client, head, browser => {
        active?.close('Opened in another browser'); documents.clear();
        const session = { token: random(), subject: owner.sub, expiry: owner.exp * 1000,
          lastInput: Date.now(), closed: false, jobs: new Set() };
        let idle, deadline, liveness;
        session.close = reason => {
          if (session.closed) return;
          session.closed = true; clearTimeout(idle); clearTimeout(deadline); clearInterval(liveness);
          if (active === session) active = undefined;
          for (const [grant, document] of documents) if (document.session === session) documents.delete(grant);
          for (const stop of session.jobs) stop(); session.jobs.clear();
          browser.close(1000, reason); setTimeout(() => browser.terminate(), 1000).unref();
        };
        const reset = () => { session.lastInput = Date.now(); clearTimeout(idle);
          idle = setTimeout(() => session.close('Disconnected after inactivity'), idleTimeoutMs); idle.unref(); };
        browser.on('message', (data, binary) => {
          if (binary || data.length > 32) return session.close('Invalid session message');
          if (data.toString() === 'activity') reset();
        });
        browser.on('error', () => session.close('Connection ended'));
        browser.on('close', () => session.close('Connection ended'));
        let alive = true;
        browser.on('pong', () => { alive = true; });
        liveness = setInterval(() => { if (!alive) return session.close('Connection lost'); alive = false; browser.ping(); }, 15000); liveness.unref();
        active = session; reset();
        deadline = setTimeout(() => session.close('Login expired'), Math.max(1, session.expiry - Date.now())); deadline.unref();
        browser.send(JSON.stringify({ type: 'ready', token: session.token }));
      });
    }
    let session;
    try { session = authorize(request, owner); } catch { return deny(client); }
    const terminal = url.pathname === '/terminal/ws';
    if (!terminal && url.pathname !== '/ws') return deny(client);
    if (terminal && request.headers['sec-websocket-protocol'] !== 'tty') return deny(client);
    const origin = new WebSocket(`ws://${hostname}/ws`, terminal ? 'tty' : paseoPassword ? ['paseo.bearer.' + paseoPassword] : undefined, {
      createConnection: () => terminal ? net.connect({ path: socketPath }) : net.connect({ host: '127.0.0.1', port: paseoPort }),
      headers: forwardHeaders(request, terminal), perMessageDeflate: false, maxPayload: 32 * 1024 * 1024, handshakeTimeout: 10000,
    });
    let browser, closed = false;
    const stop = () => {
      if (closed) return; closed = true; session.jobs.delete(stop); origin.terminate();
      if (browser) { browser.close(1000, 'Session ended'); setTimeout(() => browser.terminate(), 1000).unref(); }
      else client.destroy();
    };
    session.jobs.add(stop);
    client.on('close', stop); origin.on('error', stop); origin.on('close', stop);
    origin.on('open', () => {
      if (closed || session.closed || session !== active || session.expiry <= Date.now()) return stop();
      websocketServer.handleUpgrade(request, client, head, connected => {
        browser = connected; browser.on('error', stop); browser.on('close', stop);
        const relay = (from, to) => from.on('message', (data, binary) => {
          if (closed || session.closed) return;
          to.send(data, { binary }, error => { if (error) return stop(); if (to.bufferedAmount < 65536) from.resume(); });
          if (to.bufferedAmount >= 65536) from.pause();
        });
        relay(browser, origin); relay(origin, browser);
      });
    });
  });
  server.closeConnections = () => { active?.close('Service restarting'); for (const socket of rawSockets) socket.destroy(); };
  server.on('close', () => websocketServer.close());
  return server;
}
