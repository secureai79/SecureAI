/*
 * session-guard.js — session safety for the signed-in pages (dashboard, history, settings).
 *
 * Include it FIRST in <head>, before any other script:
 *     <script src="session-guard.js"></script>
 *
 *  1. No session  -> redirect to login.html (instead of showing stale cached data).
 *  2. API answers 401 to an authenticated call (token expired or revoked) -> clear the session and
 *     send the user to login.html?expired=1.
 *  3. Log out calls POST /auth/logout so the server revokes the token, then clears browser storage.
 *  4. Browser caches belong to exactly ONE account. If a different account signs in, the cached scan
 *     history, profile and workspace name are wiped before the page renders, so nobody ever sees
 *     another account's data.
 *  5. The scan history is rebuilt from the server (the source of truth) for the signed-in account.
 *  6. The real workspace name and e-mail come from /auth/me (SecureAI.me, event "secureai:me").
 */
(function () {
  if (window.__saGuard) return;
  window.__saGuard = true;

  var TOKEN = 'secureai_access_token', ORG = 'secureai_organization_id', USER = 'secureai_user_id';
  var SESSION_KEYS = [TOKEN, ORG, USER, 'aisc_session', 'secureai_last_sync'];
  var HISTORY = 'secureai_scan_history', OWNER = 'secureai_history_owner';
  var ME = 'secureai-me', PROFILE = 'secureai-profile', WORKSPACE = 'secureai-workspace';
  var realFetch = window.fetch.bind(window);
  var ending = false;

  function apiBase() {
    try { if (typeof api === 'function') return api(); } catch (e) {}
    var h = location.hostname;
    var local = (h === '127.0.0.1' || h === 'localhost') &&
      (location.port === '5500' || location.port === '5501' || location.protocol === 'file:');
    return (local ? 'http://127.0.0.1:8001' : (window.SECUREAI_API_BASE || location.origin)).replace(/\/$/, '');
  }

  // Everything tied to one account. (PROFILE is kept on logout so the same person keeps their photo.)
  function wipeAccountCaches(includeProfile) {
    try {
      localStorage.removeItem(HISTORY); localStorage.removeItem(ME); localStorage.removeItem(WORKSPACE);
      if (includeProfile) { localStorage.removeItem(PROFILE); localStorage.removeItem(OWNER); }
    } catch (e) {}
  }
  function clearSession() {
    SESSION_KEYS.forEach(function (k) { try { sessionStorage.removeItem(k); } catch (e) {} });
    wipeAccountCaches(false);
  }

  // 1. no (complete) session -> login. The app needs both the token and the organisation id.
  var token = null, org = '', uid = '';
  try { token = sessionStorage.getItem(TOKEN); org = sessionStorage.getItem(ORG) || ''; uid = sessionStorage.getItem(USER) || ''; } catch (e) {}
  if (!token || !org) { clearSession(); location.replace('login.html'); return; }

  // 4. caches belong to one account (organisation + user)
  var owner = org + '|' + uid, ownerChanged = false;
  try {
    if (localStorage.getItem(OWNER) !== owner) {
      wipeAccountCaches(true);
      localStorage.setItem(OWNER, owner);
      ownerChanged = true;
    }
  } catch (e) {}

  // 2. expired / revoked token -> login
  function sentAuth(headers) {
    if (!headers) return false;
    try {
      if (typeof Headers !== 'undefined' && headers instanceof Headers) return headers.has('authorization');
      if (Array.isArray(headers)) return headers.some(function (p) { return String(p[0]).toLowerCase() === 'authorization'; });
      return Object.keys(headers).some(function (k) { return k.toLowerCase() === 'authorization'; });
    } catch (e) { return false; }
  }
  window.fetch = function (input, init) {
    return realFetch(input, init).then(function (res) {
      if (res.status === 401 && !ending) {
        var url = typeof input === 'string' ? input : (input && input.url) || '';
        var headers = (init && init.headers) || (input && input.headers);
        if (sentAuth(headers) && !/\/auth\/(login|signup)\b/.test(url)) {
          ending = true;
          clearSession();
          location.replace('login.html?expired=1');
        }
      }
      return res;
    });
  };

  // 3. logout revokes the token server-side
  function logout() {
    var t = null, finished = false;
    try { t = sessionStorage.getItem(TOKEN); } catch (e) {}
    function finish() {
      if (finished) return;
      finished = true;
      clearSession();
      location.href = 'login.html';
    }
    if (!t) { finish(); return; }
    try {
      realFetch(apiBase() + '/auth/logout', { method: 'POST', headers: { Authorization: 'Bearer ' + t }, keepalive: true })
        .then(finish, finish);
    } catch (e) { finish(); }
    setTimeout(finish, 1500);                      // never trap the user if the API is unreachable
  }
  document.addEventListener('click', function (e) {
    var el = e.target && e.target.closest ? e.target.closest('#saOut, #settingsLogout, .logout, [data-logout]') : null;
    if (el) { e.preventDefault(); e.stopImmediatePropagation(); logout(); }
  }, true);
  window.addEventListener('load', function () { window.secureaiLogout = logout; });
  // After a password change the server issues a fresh token: store it everywhere the pages look.
  function setToken(t) {
    try {
      sessionStorage.setItem(TOKEN, t);
      var raw = sessionStorage.getItem('aisc_session');          // the dashboard keeps its own copy
      if (raw) { var o = JSON.parse(raw); o.token = t; sessionStorage.setItem('aisc_session', JSON.stringify(o)); }
    } catch (e) {}
  }

  function getJson(path) {
    return window.fetch(apiBase() + path, { headers: { Authorization: 'Bearer ' + sessionStorage.getItem(TOKEN) } })
      .then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; });
  }
  function readHistory() {
    try { var h = JSON.parse(localStorage.getItem(HISTORY) || '[]'); return Array.isArray(h) ? h : []; } catch (e) { return []; }
  }

  // 6. real account details (workspace name, e-mail)
  var me = null;
  try { me = JSON.parse(localStorage.getItem(ME) || 'null'); } catch (e) {}
  function repaint() {
    try { if (window.SA) { if (SA.avatar) SA.avatar(); if (SA.refresh) SA.refresh(); if (SA.bell) SA.bell(); } } catch (e) {}
    try { if (typeof window.renderScanHistory === 'function') window.renderScanHistory(); } catch (e) {}
  }
  function loadMe() {
    return getJson('/auth/me').then(function (m) {
      if (!m) return;
      var changed = !me || me.email !== m.email || me.organization_name !== m.organization_name;
      me = { email: m.email, organization_name: m.organization_name, email_verified: m.email_verified,
             verification_required: m.verification_required, role: m.role };
      window.SecureAI.me = me;
      try { localStorage.setItem(ME, JSON.stringify(me)); } catch (e) {}
      try { window.dispatchEvent(new CustomEvent('secureai:me', { detail: me })); } catch (e) {}
      if (changed) repaint();
    });
  }

  // 5. scan history for THIS account, rebuilt from the server
  function syncHistory() {
    var now = Date.now(), last = 0;
    try { last = parseInt(sessionStorage.getItem('secureai_last_sync') || '0', 10) || 0; } catch (e) {}
    if (!ownerChanged && readHistory().length && now - last < 120000) return Promise.resolve();
    return getJson('/repositories').then(function (repos) {
      if (!Array.isArray(repos)) return;
      return Promise.all(repos.map(function (r) {
        return getJson('/repositories/' + encodeURIComponent(r.id) + '/scans').then(function (s) { return { r: r, s: Array.isArray(s) ? s : [] }; });
      })).then(function (lists) {
        var rows = [];
        lists.forEach(function (x) { x.s.forEach(function (sc) { rows.push({ r: x.r, sc: sc }); }); });
        rows.sort(function (a, b) { return new Date(b.sc.started_at) - new Date(a.sc.started_at); });
        rows = rows.slice(0, 20);
        var local = {};
        readHistory().forEach(function (h) { local[h.scanId] = h; });
        return Promise.all(rows.map(function (o) {
          var sc = o.sc, st = String(sc.status || '');
          var status = st === 'completed' ? 'completed' : (st === 'failed' || st === 'cancelled' ? 'failed' : 'in progress');
          var item = { scanId: sc.id, repoId: o.r.id, repoName: o.r.repo_url, scannedAt: sc.finished_at || sc.started_at, status: status };
          var prev = local[sc.id];
          if (prev && prev.score != null) { item.score = prev.score; item.findings = prev.findings; item.high = prev.high; return item; }
          if (status !== 'completed') return item;
          item.score = sc.score;
          return getJson('/scans/' + encodeURIComponent(sc.id) + '/findings').then(function (f) {
            if (Array.isArray(f)) {
              var open = f.filter(function (x) { return x.scored && x.status !== 'resolved'; });
              item.findings = open.length;
              item.high = open.filter(function (x) { return x.severity === 'HIGH' || x.severity === 'CRITICAL'; }).length;
            }
            return item;
          });
        })).then(function (items) {
          try { localStorage.setItem(HISTORY, JSON.stringify(items)); sessionStorage.setItem('secureai_last_sync', String(Date.now())); } catch (e) {}
          repaint();
        });
      });
    });
  }

  window.SecureAI = { logout: logout, apiBase: apiBase, endSession: clearSession, setToken: setToken, me: me, syncHistory: syncHistory };

  window.addEventListener('DOMContentLoaded', function () {
    // Load the e-mail-verification banner and the Help & Support panel (optional: a missing file is ignored).
    ['verify-banner.js', 'help-center.js', 'workspaces.js'].forEach(function (f) {
      var s = document.createElement('script'); s.src = f; s.async = true; s.onerror = function () {};
      document.head.appendChild(s);
    });
    loadMe().then(syncHistory);
  });
})();
