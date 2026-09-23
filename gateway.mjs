import http from 'node:http';
import net from 'node:net';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import WebSocket, { WebSocketServer } from 'ws';

export function verifier({ issuer, audience, email }, keys) {
  const jwks = keys ?? createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`),
    { timeoutDuration: 5000, cacheMaxAge: 300000 });
  return async token => {
    if (typeof token !== 'string' || token.length > 16000) throw new Error('Missing token');
    const { payload } = await jwtVerify(token, jwks, {
      issuer, audience, algorithms: ['RS256'],
      requiredClaims: ['exp', 'iat', 'sub', 'email'], maxTokenAge: '1h',
    });
    if (payload.email?.toLowerCase() !== email.toLowerCase() || !payload.sub ||
        !Number.isFinite(payload.exp) || payload.exp * 1000 <= Date.now()) {
      throw new Error('Invalid identity');
    }
    return payload;
  };
}

const headersFor = request => {
  const headers = {};
  for (const key of ['host', 'origin', 'accept', 'accept-encoding', 'user-agent']) {
    if (request.headers[key]) headers[key] = request.headers[key];
  }
  return headers;
};

export function createGateway({ hostname, socketPath, verify, freshLogin, idleTimeoutMs = 120000 }) {
  const sockets = new Set();
  const connections = new Set();
  let activeConnection;
  const websocketServer = new WebSocketServer({ noServer: true, perMessageDeflate: false,
    maxPayload: 1024 * 1024, handleProtocols: protocols => protocols.has('tty') ? 'tty' : false });
  const deny = response => {
    if (response.writeHead) response.writeHead(403, { 'Cache-Control': 'no-store' }).end('Access denied\n');
    else response.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  };
  async function authenticate(request, upgrade = false) {
    if (request.headers.host !== hostname || !['GET', 'HEAD'].includes(request.method))
      throw new Error('Wrong host or method');
    if (request.headers.origin && request.headers.origin !== `https://${hostname}`)
      throw new Error('Wrong origin');
    const path = new URL(request.url, `https://${hostname}`).pathname;
    if (upgrade && (path !== '/ws' || request.headers.origin !== `https://${hostname}`))
      throw new Error('Wrong WebSocket origin');
    if (upgrade && request.headers['sec-websocket-protocol'] !== 'tty')
      throw new Error('Wrong WebSocket protocol');
    if (!['/', '/callback', '/token', '/ws', '/favicon.ico'].includes(path)) throw new Error('Wrong path');
    return verify(request.headers['cf-access-jwt-assertion']);
  }
  const server = http.createServer({ maxHeaderSize: 32768, requestTimeout: 10000 }, async (request, response) => {
    let payload;
    try { payload = await authenticate(request); } catch { return deny(response); }
    if (freshLogin) {
      try { return await freshLogin.handle(request, response, payload); }
      catch { return deny(response); }
    }
    const upstream = http.request({ socketPath, method: request.method,
      path: request.url, headers: headersFor(request) }, incoming => {
      response.writeHead(incoming.statusCode, { ...incoming.headers,
        'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY' });
      incoming.pipe(response);
    });
    upstream.setTimeout(10000, () => upstream.destroy());
    upstream.on('error', () => { if (!response.headersSent) response.writeHead(502); response.end(); });
    response.on('close', () => upstream.destroy());
    upstream.end();
  });
  server.on('upgrade', async (request, client, head) => {
    sockets.add(client);
    client.on('error', () => client.destroy());
    client.on('close', () => sockets.delete(client));
    let payload;
    try { payload = await authenticate(request, true); } catch { return deny(client); }
    try { freshLogin?.consume(request, payload); } catch { return deny(client); }
    if (client.destroyed) return;
    // ws handles frame parsing, masking, fragmentation, and flow control.
    // The upstream is always the private Unix socket, never a remote host.
    const origin = new WebSocket(`ws://${hostname}/ws`, 'tty', {
      createConnection: () => net.connect({ path: socketPath }),
      headers: headersFor(request), perMessageDeflate: false,
      maxPayload: 16 * 1024 * 1024, handshakeTimeout: 10000,
    });
    origin.on('error', () => client.destroy());
    client.on('close', () => origin.terminate());
    origin.on('open', () => {
      if (client.destroyed || payload.exp * 1000 <= Date.now()) {
        origin.terminate(); client.destroy(); return;
      }
      websocketServer.handleUpgrade(request, client, head, browser => {
        let closed = false;
        let idleTimer;
        let deadline;
        const close = reason => {
          if (closed) return;
          closed = true;
          clearTimeout(idleTimer); clearTimeout(deadline);
          connections.delete(close);
          if (activeConnection === close) activeConnection = undefined;
          // Stop forwarding immediately, then deliver a normal close so the
          // browser does not automatically compete for the active session.
          browser.close(1000, reason);
          origin.terminate();
          const force = setTimeout(() => browser.terminate(), 1000);
          force.unref();
        };
        const resetIdle = () => {
          clearTimeout(idleTimer);
          idleTimer = setTimeout(() => close('Disconnected after inactivity'), idleTimeoutMs);
          idleTimer.unref();
        };
        const relay = (source, destination, trackInput) => {
          source.on('message', (data, binary) => {
            if (closed) return;
            // ttyd prefixes actual terminal input with "0". Output-driven
            // flow-control messages, resize events, and pings are not input.
            if (trackInput && data.length > 1 && data[0] === 0x30) resetIdle();
            destination.send(data, { binary }, error => {
              if (error) return close('Connection ended');
              if (!closed && destination.bufferedAmount < 65536) source.resume();
            });
            if (destination.bufferedAmount >= 65536) source.pause();
          });
          source.on('error', () => close('Connection ended'));
          source.on('close', () => close('Connection ended'));
        };
        relay(browser, origin, true);
        relay(origin, browser, false);
        activeConnection?.('Opened in another browser');
        activeConnection = close;
        connections.add(close);
        resetIdle();
        deadline = setTimeout(() => close('Login expired'), Math.max(1, payload.exp * 1000 - Date.now()));
        deadline.unref();
      });
    });
  });
  server.closeConnections = () => {
    for (const close of connections) close('Service restarting');
    for (const socket of sockets) socket.destroy();
  };
  server.on('close', () => websocketServer.close());
  return server;
}
