export function novncPage() {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>noVNC</title>
  <style>
  :root{color-scheme:dark;font-family:system-ui;background:#111714;color:#edf3ee}*{box-sizing:border-box}[hidden]{display:none!important}body{margin:0;height:100dvh;display:flex;flex-direction:column}button,input,textarea{font:inherit;color:inherit;background:#1c2820;border:1px solid #435348;border-radius:6px;padding:8px}button{cursor:pointer}button:disabled{opacity:.5;cursor:default}button:focus-visible,input:focus-visible,textarea:focus-visible{outline:2px solid #b9e9ac}header{display:flex;gap:8px;padding:8px;align-items:center;flex-wrap:wrap}#status{font-size:14px}#screen{flex:1;min-height:0;overflow:hidden}dialog{background:#111714;color:inherit;border:1px solid #435348;border-radius:8px;max-width:90vw}form{display:grid;gap:12px}label{display:grid;gap:4px}#clipboard{padding:8px;display:flex;gap:8px}#clipboard[hidden]{display:none}#clipboard textarea{flex:1;min-width:0;resize:vertical}#keyboard-input{position:fixed;left:-1000px;top:0;width:1px;height:1px;opacity:0}
  </style></head><body><header><button id="reconnect" hidden>Reconnect</button><button id="keyboard" disabled>Keyboard</button><button id="clipboard-toggle" disabled>Clipboard</button><button id="fullscreen">Full screen</button><span id="status" role="status">Connecting…</span></header>
  <div id="clipboard" hidden><textarea aria-label="Clipboard text" autocomplete="off" spellcheck="false"></textarea><button id="paste">Send</button></div>
  <textarea id="keyboard-input" aria-label="Remote keyboard" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></textarea>
  <div id="screen" aria-label="Remote desktop"></div>
  <dialog id="credentials"><form autocomplete="off"><label id="username-row">Mac username<input name="username" autocomplete="off" autocapitalize="off" spellcheck="false"></label><label id="password-row">Password<input name="password" type="password" autocomplete="off"></label><label id="target-row">Target<input name="target" autocomplete="off"></label><button type="submit">Connect</button></form></dialog>
  <script type="module">import RFB from '/novnc/core/rfb.js'; (${novncClient})(RFB);</script></body></html>`;
}

function novncClient(RFB) {
  const $ = id => document.getElementById(id);
  const form = $('credentials').querySelector('form');
  const clipboard = $('clipboard').querySelector('textarea');
  let rfb, submitted, requested = [];
  const clearCredentials = () => {
    if (submitted) for (const key of Object.keys(submitted)) delete submitted[key];
    submitted = undefined;
  };
  const status = text => { $('status').textContent = text; };
  const connected = value => {
    for (const id of ['keyboard', 'clipboard-toggle', 'paste']) $(id).disabled = !value;
  };
  const reset = () => {
    clearCredentials(); form.reset(); $('credentials').close(); clipboard.value = '';
    $('clipboard').hidden = true; $('keyboard-input').value = '';
  };
  const connect = () => {
    rfb?.disconnect(); reset(); connected(false); $('reconnect').hidden = true; status('Connecting…');
    $('screen').replaceChildren();
    rfb = new RFB($('screen'), new URL('/novnc/ws', location.href).href.replace(/^http/, 'ws'), { wsProtocols: ['binary'] });
    const peer = rfb;
    rfb.scaleViewport = true; rfb.resizeSession = false; rfb.showDotCursor = true;
    rfb.addEventListener('connect', () => {
      if (rfb !== peer) return;
      clearCredentials(); status(''); connected(true); form.reset(); rfb.focus();
    });
    rfb.addEventListener('disconnect', () => {
      if (rfb !== peer) return;
      connected(false); reset(); rfb = undefined; status('Disconnected'); $('reconnect').hidden = false;
    });
    rfb.addEventListener('securityfailure', () => {
      if (rfb === peer) { form.reset(); status('Sign-in failed'); }
    });
    rfb.addEventListener('credentialsrequired', event => {
      if (rfb !== peer) return;
      requested = event.detail.types;
      if (requested.some(type => !['username', 'password', 'target'].includes(type))) {
        rfb.disconnect(); return;
      }
      for (const type of ['username', 'password', 'target']) {
        $(type + '-row').hidden = !requested.includes(type);
        form.elements[type].required = requested.includes(type);
      }
      status(''); $('credentials').showModal();
      form.elements[requested[0]]?.focus();
    });
    rfb.addEventListener('clipboard', event => { if (rfb === peer) clipboard.value = event.detail.text; });
  };
  form.addEventListener('submit', event => {
    event.preventDefault();
    submitted = Object.fromEntries(requested.map(type => [type, form.elements[type].value]));
    rfb.sendCredentials(submitted); form.reset(); $('credentials').close(); status('Connecting…');
  });
  $('credentials').addEventListener('cancel', () => rfb?.disconnect());
  $('reconnect').onclick = connect;
  $('fullscreen').onclick = async () => {
    try { if (document.fullscreenElement) await document.exitFullscreen(); else await document.documentElement.requestFullscreen(); }
    catch { status('Full screen unavailable'); }
  };
  $('clipboard-toggle').onclick = () => {
    $('clipboard').hidden = !$('clipboard').hidden;
    if (!$('clipboard').hidden) clipboard.focus(); else rfb.focus();
  };
  $('paste').onclick = () => { rfb.clipboardPasteFrom(clipboard.value); rfb.focus(); };
  const keyboard = $('keyboard-input');
  $('keyboard').onclick = () => { keyboard.value = '_'; keyboard.focus(); keyboard.setSelectionRange(1, 1); };
  keyboard.addEventListener('input', event => {
    if (event.isComposing) return;
    if (event.inputType === 'deleteContentBackward') rfb.sendKey(0xff08);
    else if (event.inputType === 'insertLineBreak') rfb.sendKey(0xff0d);
    else for (const char of keyboard.value.replace(/^_/, '')) {
      const code = char.codePointAt(0); rfb.sendKey(code === 10 ? 0xff0d : code < 256 ? code : 0x01000000 | code);
    }
    keyboard.value = '_';
  });
  window.addEventListener('pagehide', () => { rfb?.disconnect(); reset(); });
  connect();
}
