import { randomBytes, createHash } from 'node:crypto';
import http from 'node:http';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const cookieName = '__Host-terminal-login';
const random = () => randomBytes(32).toString('base64url');
const stateCookie = (value, seconds) =>
  `${cookieName}=${value}; Path=/; Max-Age=${seconds}; Secure; HttpOnly; SameSite=Lax`;
const safeHeaders = {
  'cache-control': 'no-store', 'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY',
  'content-security-policy': "frame-ancestors 'none'; object-src 'none'; base-uri 'none'",
};

export class FreshLogin {
  constructor(config, { keys, exchange, render, renderAuthorized } = {}) {
    this.config = config;
    this.pending = new Map();
    this.tickets = new Map();
    this.renderAuthorized = renderAuthorized;
    this.keys = keys ?? createRemoteJWKSet(new URL(`${config.oidcIssuer}jwks/`),
      { timeoutDuration: 5000, cacheMaxAge: 300000 });
    this.exchange = exchange ?? (async (code, verifier) => {
      const response = await fetch(config.tokenEndpoint, {
        method: 'POST', signal: AbortSignal.timeout(10000), redirect: 'error',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', code,
          redirect_uri: config.redirectUri, client_id: config.clientId,
          client_secret: config.clientSecret, code_verifier: verifier }),
      });
      if (!response.ok) throw new Error('Login exchange failed');
      return (await response.json()).id_token;
    });
    this.render = render ?? (() => new Promise((resolve, reject) => {
      const request = http.get({ socketPath: config.socketPath, path: '/',
        headers: { host: config.hostname, 'accept-encoding': 'identity' } }, response => {
        if (response.statusCode !== 200) { response.resume(); reject(new Error('Terminal unavailable')); return; }
        let html = '';
        response.setEncoding('utf8');
        response.on('data', data => { html += data; if (html.length > 2 * 1024 * 1024) request.destroy(); });
        response.on('end', () => resolve(html));
        response.on('error', reject);
      });
      request.setTimeout(10000, () => request.destroy(new Error('Terminal timeout')));
      request.on('error', reject);
    }));
  }

  prune() {
    for (const map of [this.pending, this.tickets])
      for (const [key, value] of map) if (value.expires <= Date.now()) map.delete(key);
  }

  consume(request, identity) {
    this.prune();
    const ticket = new URL(request.url, `https://${this.config.hostname}`).searchParams.get('ticket');
    const grant = this.tickets.get(ticket);
    // Delete before any asynchronous upgrade work, even if the identity mismatches.
    this.tickets.delete(ticket);
    if (!grant || grant.subject !== identity.sub) throw new Error('Fresh login required');
  }

  async handle(request, response, identity) {
    this.prune();
    const url = new URL(request.url, `https://${this.config.hostname}`);
    const finish = (status, body = '', headers = {}) => {
      response.writeHead(status, { ...safeHeaders, ...headers }); response.end(body);
    };
    if (url.pathname === '/') {
      if (this.pending.size >= 128) return finish(429, 'Please try again shortly.');
      const state = random(), nonce = random(), verifier = random();
      this.pending.set(state, { nonce, verifier, subject: identity.sub,
        started: Math.floor(Date.now() / 1000), expires: Date.now() + 300000 });
      const authorize = new URL(this.config.authorizationEndpoint);
      authorize.search = new URLSearchParams({ client_id: this.config.clientId,
        redirect_uri: this.config.redirectUri, response_type: 'code', scope: 'openid email profile',
        state, nonce, code_challenge_method: 'S256',
        code_challenge: createHash('sha256').update(verifier).digest('base64url') }).toString();
      return finish(302, '', { location: authorize.href, 'set-cookie': stateCookie(state, 300) });
    }
    if (url.pathname === '/callback') {
      const state = url.searchParams.get('state');
      const pending = this.pending.get(state);
      this.pending.delete(state);
      const cookies = (request.headers.cookie ?? '').split(';').map(c => c.trim());
      const clearCookie = { 'set-cookie': stateCookie('', 0) };
      try {
        if (!pending || !cookies.includes(`${cookieName}=${state}`) ||
            pending.subject !== identity.sub || !url.searchParams.get('code') || url.searchParams.has('error'))
          throw new Error('Invalid login response');
        const token = await this.exchange(url.searchParams.get('code'), pending.verifier);
        const { payload } = await jwtVerify(token, this.keys, {
          issuer: this.config.oidcIssuer, audience: this.config.clientId,
          algorithms: ['RS256'], maxTokenAge: '5m',
          requiredClaims: ['exp', 'iat', 'sub', 'email', 'nonce', 'auth_time'],
        });
        if (payload.nonce !== pending.nonce || payload.email !== this.config.email ||
            payload.sub !== this.config.ownerSubject || !Number.isFinite(payload.auth_time) ||
            payload.auth_time < pending.started - 2 || payload.auth_time > Date.now() / 1000 + 2 ||
            !Array.isArray(payload.amr) || !payload.amr.some(method => ['user', 'mfa'].includes(method)))
          throw new Error('Fresh key verification required');
        const ticket = random();
        const html = this.renderAuthorized ? await this.renderAuthorized(ticket) : await this.render();
        if (!html.includes('<head>')) throw new Error('Unexpected terminal response');
        if (this.tickets.size >= 128) throw new Error('Too many pending connections');
        this.tickets.set(ticket, { subject: identity.sub, expires: Date.now() + 30000 });
        const script = `<script>(()=>{
          history.replaceState(null,'','/');
          const Native=window.WebSocket;
          let used=false;
          const lock=()=>{
            window.term=undefined;
            document.body.innerHTML='<main style="font:18px system-ui;max-width:520px;margin:15vh auto;padding:24px;color:#eee"><a style="color:#9bc8ff" href="/">Sign in with your YubiKey</a></main>';
            document.body.style.background='#17191d';
            document.title='Sign in';
          };
          window.WebSocket=class extends Native{
            constructor(_url,protocols){
              if(used){lock();throw new Error('Fresh login required');}
              used=true;
              super('wss://${this.config.hostname}/ws?ticket=${ticket}',protocols);
              this.addEventListener('close',()=>setTimeout(lock,0));
            }
          };
          window.addEventListener('pageshow',event=>{if(event.persisted)location.reload();});
        })();</script>`;
        return finish(200, this.renderAuthorized ? html : html.replace('<head>', `<head>${script}`),
          { ...clearCookie, 'content-type': 'text/html; charset=utf-8' });
      } catch {
        return finish(403, '<a href="/">Sign in with YubiKey</a>',
          { ...clearCookie, 'content-type': 'text/html; charset=utf-8' });
      }
    }
    if (url.pathname === '/token') return finish(200, '{"token":""}', { 'content-type': 'application/json' });
    return finish(404, 'Not found');
  }
}
