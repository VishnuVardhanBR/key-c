const encoded = value => JSON.stringify(value).replaceAll('<', '\\u003c');

export function portalPage(ticket) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>key-c</title>
  <style>
  :root{color-scheme:dark;font-family:ui-sans-serif,system-ui,sans-serif;background:#111714;color:#edf3ee}*{box-sizing:border-box}body{margin:0}button,a{font:inherit}button{cursor:pointer;color:inherit;background:#1c2820;border:1px solid #435348;border-radius:8px;padding:12px 20px}button:hover{background:#263a2c}button:disabled{opacity:.5;cursor:wait}button:focus-visible,a:focus-visible{outline:3px solid #b9e9ac;outline-offset:4px}header{height:60px;padding:0 20px;display:flex;align-items:center;justify-content:flex-end;gap:12px;border-bottom:1px solid #2d3831}main{max-width:760px;margin:15vh auto;padding:24px}.apps{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.app{padding:28px;font-size:22px}#status{color:#aebfb2}#workspace{position:fixed;inset:60px 0 0;display:none}iframe{width:100%;height:100%;border:0}#back{display:none}.locked{text-align:center}.locked a{color:#c0e9af}@media(max-width:600px){.apps{grid-template-columns:1fr}}
  </style></head><body><header><button id="back">All apps</button><button id="lock">Lock</button></header>
  <main id="chooser"><div class="apps"><button class="app" data-app="terminal" disabled>Terminal</button><button class="app" data-app="paseo" disabled>Paseo</button><button class="app" data-app="novnc" disabled>noVNC</button></div><p id="status" role="status">Connecting…</p></main><section id="workspace" aria-label="Workspace"></section>
  <script>(${portalClient})(${encoded(ticket)});</script></body></html>`;
}

function portalClient(ticket) {
  history.replaceState(null, '', '/');
  let token, frame, lastActivity = 0, locked = false;
  const control = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/session?ticket=' + ticket, 'key-c');
  ticket = undefined;
  const workspace = document.querySelector('#workspace'), chooser = document.querySelector('#chooser');
  const lock = () => {
    if (locked) return;
    locked = true; token = undefined; frame?.remove(); control.close();
    document.body.innerHTML = '<main class="locked"><a href="/">Sign in with YubiKey</a></main>';
    document.title = 'key-c · Sign in';
  };
  const activity = () => {
    if (control.readyState === WebSocket.OPEN && Date.now() - lastActivity > 1000) {
      lastActivity = Date.now(); control.send('activity');
    }
  };
  const showChooser = () => {
    frame?.remove(); frame = undefined; workspace.style.display = 'none'; chooser.style.display = '';
    document.querySelector('#back').style.display = 'none'; document.title = 'key-c';
  };
  control.onmessage = event => {
    const data = JSON.parse(event.data);
    if (data.type === 'ready') {
      token = data.token;
      for (const button of document.querySelectorAll('[data-app]')) button.disabled = false;
      document.querySelector('#status').textContent = '';
    }
  };
  control.onclose = lock; control.onerror = lock;
  document.querySelector('#lock').onclick = lock;
  document.querySelector('#back').onclick = showChooser;
  for (const button of document.querySelectorAll('[data-app]')) button.onclick = async () => {
    try {
      const response = await fetch('/launch', { method: 'POST', headers: { authorization: 'Bearer ' + token,
        'content-type': 'application/json' }, body: JSON.stringify({ app: button.dataset.app }) });
      if (!response.ok) return lock();
      const { url } = await response.json();
      frame?.remove(); frame = document.createElement('iframe'); frame.title = { terminal: 'Terminal', paseo: 'Paseo', novnc: 'noVNC' }[button.dataset.app];
      frame.allow = 'clipboard-read; clipboard-write; microphone; fullscreen';
      frame.src = url; workspace.replaceChildren(frame); workspace.style.display = 'block'; chooser.style.display = 'none';
      document.querySelector('#back').style.display = 'block'; document.title = 'key-c · ' + frame.title;
    } catch { lock(); }
  };
  for (const type of ['pointerdown', 'pointermove', 'keydown', 'input', 'wheel', 'touchstart'])
    window.addEventListener(type, event => { if (event.isTrusted) activity(); }, { passive: true, capture: true });
  window.addEventListener('message', event => {
    if (event.origin === location.origin && event.source === frame?.contentWindow && event.data === 'key-c:activity') activity();
  });
  window.addEventListener('pagehide', () => control.close());
  window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
}

export function applicationBridge(app, token) {
  return `<script>(${bridgeClient})(${encoded(app)},${encoded(token)});</script>`;
}

function bridgeClient(app, token) {
  history.replaceState(null, '', '/');
  if (app === 'paseo') {
    let connection;
    Object.defineProperty(window, '__PASEO_INITIAL_DAEMON_CONNECTION__', {
      configurable: true, get: () => connection,
      set: value => { connection = { ...value, listen: location.host +
        (location.port ? '' : location.protocol === 'https:' ? ':443' : ':80'),
        useTls: location.protocol === 'https:', label: 'My Mac' }; },
    });
  }
  // Auth lives only in these closures. Reloading loses it and needs a fresh key.
  const authorize = raw => {
    const url = new URL(raw, location.href);
    if (url.host !== location.host || !['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) return url;
    url.searchParams.set('__key_c', token); return url;
  };
  const nativeFetch = window.fetch.bind(window);
  window.fetch = (input, init = {}) => {
    const url = new URL(input instanceof Request ? input.url : input, location.href);
    if (url.origin !== location.origin) return nativeFetch(input, init);
    const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
    headers.set('authorization', 'Bearer ' + token);
    return nativeFetch(input, { ...init, headers });
  };
  const nativeOpen = XMLHttpRequest.prototype.open, nativeSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    this.keyCSameOrigin = new URL(url, location.href).origin === location.origin;
    return nativeOpen.call(this, method, url, ...rest);
  };
  XMLHttpRequest.prototype.send = function(body) {
    if (this.keyCSameOrigin) this.setRequestHeader('authorization', 'Bearer ' + token);
    return nativeSend.call(this, body);
  };
  const NativeWebSocket = window.WebSocket;
  window.WebSocket = new Proxy(NativeWebSocket, {
    construct(Target, [raw, protocols]) {
      const url = new URL(raw, location.href);
      if (url.host === location.host) {
        if (app === 'terminal') url.pathname = '/terminal/ws';
        url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        return new Target(authorize(url).href, protocols);
      }
      return new Target(raw, protocols);
    },
  });
  // Downloads/media may be initiated by elements instead of fetch().
  const decorate = raw => {
    const url = new URL(raw, location.href);
    return url.origin === location.origin && /^\/(api|mcp|public)\//.test(url.pathname) ? authorize(url).href : raw;
  };
  for (const [type, property] of [[HTMLAnchorElement, 'href'], [HTMLImageElement, 'src'], [HTMLMediaElement, 'src']]) {
    const descriptor = Object.getOwnPropertyDescriptor(type.prototype, property);
    if (descriptor?.set) Object.defineProperty(type.prototype, property, { ...descriptor,
      set(value) { descriptor.set.call(this, decorate(value)); } });
  }
  const setAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, value) {
    return setAttribute.call(this, name, ['href', 'src'].includes(name) ? decorate(value) : value);
  };
  // Retain UI preferences only for this open page, including Paseo host metadata.
  for (const name of ['localStorage', 'sessionStorage']) {
    const data = new Map();
    const storage = { getItem: key => data.get(String(key)) ?? null, setItem: (key, value) => data.set(String(key), String(value)),
      removeItem: key => data.delete(String(key)), clear: () => data.clear(), key: i => [...data.keys()][i] ?? null,
      get length() { return data.size; } };
    Object.defineProperty(window, name, { configurable: true, value: storage });
  }
  let last = 0;
  for (const type of ['pointerdown', 'pointermove', 'keydown', 'input', 'wheel', 'touchstart'])
    window.addEventListener(type, event => {
      if (event.isTrusted && Date.now() - last > 1000) {
        last = Date.now(); parent.postMessage('key-c:activity', location.origin);
      }
    }, { passive: true, capture: true });
  window.addEventListener('pageshow', event => { if (event.persisted) top.location.href = '/'; });
}
