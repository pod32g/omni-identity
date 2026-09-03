// Omni Identity passkey helper. Served from the same origin (CSP script-src
// 'self'); no inline scripts. It converts between the WebAuthn JSON forms the
// server speaks (base64url fields) and the ArrayBuffers the browser API wants,
// and wires up the buttons on the login and account pages.
(function () {
  'use strict';

  function b64uToBuf(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    var pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
    var bin = atob(s + pad);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function bufToB64u(b) {
    var bytes = new Uint8Array(b), bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function decodeCreation(pk) {
    pk.challenge = b64uToBuf(pk.challenge);
    pk.user.id = b64uToBuf(pk.user.id);
    (pk.excludeCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
    return pk;
  }
  function decodeRequest(pk) {
    pk.challenge = b64uToBuf(pk.challenge);
    (pk.allowCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
    return pk;
  }
  function encodeCredential(cred) {
    var r = cred.response;
    var out = { id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
      response: { clientDataJSON: bufToB64u(r.clientDataJSON) } };
    if (r.attestationObject) out.response.attestationObject = bufToB64u(r.attestationObject);
    if (r.authenticatorData) {
      out.response.authenticatorData = bufToB64u(r.authenticatorData);
      out.response.signature = bufToB64u(r.signature);
      out.response.userHandle = r.userHandle ? bufToB64u(r.userHandle) : null;
    }
    if (typeof r.getTransports === 'function') out.response.transports = r.getTransports();
    if (typeof cred.getClientExtensionResults === 'function') out.clientExtensionResults = cred.getClientExtensionResults();
    if (cred.authenticatorAttachment) out.authenticatorAttachment = cred.authenticatorAttachment;
    return out;
  }
  function postJSON(url, body) {
    return fetch(url, { method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(body) }).then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (data) {
          if (!res.ok) throw new Error(data.error_description || data.error || ('HTTP ' + res.status));
          return data;
        });
      });
  }

  var passkey = {
    supported: function () { return !!(window.PublicKeyCredential && navigator.credentials); },
    register: function (csrf, name) {
      return postJSON('/account/passkeys/begin', { csrf_token: csrf }).then(function (begin) {
        return navigator.credentials.create({ publicKey: decodeCreation(begin.options.publicKey) }).then(function (cred) {
          return postJSON('/account/passkeys/finish', { csrf_token: csrf, ceremony: begin.ceremony, name: name, credential: encodeCredential(cred) });
        });
      });
    },
    login: function (csrf, username, next, req) {
      return postJSON('/login/passkey/begin', { csrf_token: csrf, username: username || '' }).then(function (begin) {
        var opts = { publicKey: decodeRequest(begin.options.publicKey) };
        if (begin.options.mediation) opts.mediation = begin.options.mediation;
        return navigator.credentials.get(opts).then(function (cred) {
          return postJSON('/login/passkey/finish', { csrf_token: csrf, ceremony: begin.ceremony, credential: encodeCredential(cred), next: next || '', req: req || '' });
        });
      });
    }
  };
  window.omniPasskey = passkey;

  function showError(el, msg) {
    if (!el) return;
    el.textContent = msg;
    el.hidden = false;
  }

  document.addEventListener('DOMContentLoaded', function () {
    var loginBtn = document.getElementById('passkey-login');
    if (loginBtn) {
      if (!passkey.supported()) { loginBtn.hidden = true; }
      loginBtn.addEventListener('click', function () {
        var form = loginBtn.closest('form') || document;
        var user = form.querySelector('[name=username]');
        var next = form.querySelector('[name=next]');
        var req = form.querySelector('[name=req]');
        var errBox = document.getElementById('passkey-error');
        loginBtn.disabled = true;
        passkey.login(loginBtn.dataset.csrf, user ? user.value.trim() : '', next ? next.value : '', req ? req.value : '')
          .then(function (data) { window.location.href = data.redirect || '/account'; })
          .catch(function (e) { loginBtn.disabled = false; showError(errBox, e && e.message ? e.message : 'Passkey sign-in failed.'); });
      });
    }
    var addForm = document.getElementById('passkey-add');
    if (addForm) {
      if (!passkey.supported()) {
        showError(document.getElementById('passkey-error'), 'This browser does not support passkeys.');
        addForm.querySelector('button').disabled = true;
      }
      addForm.addEventListener('submit', function (ev) {
        ev.preventDefault();
        var btn = addForm.querySelector('button');
        var errBox = document.getElementById('passkey-error');
        btn.disabled = true;
        passkey.register(addForm.dataset.csrf, addForm.querySelector('[name=name]').value.trim())
          .then(function () { window.location.href = '/account/passkeys?saved=1'; })
          .catch(function (e) { btn.disabled = false; showError(errBox, e && e.message ? e.message : 'Registration failed.'); });
      });
    }
  });
})();
