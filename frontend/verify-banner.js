/*
 * verify-banner.js — asks unverified users to confirm their e-mail, and explains blocked actions.
 * Loaded automatically by session-guard.js on the signed-in pages (no HTML edits needed).
 *
 *  - Shows a banner when the API says the account is unverified AND the server requires verification.
 *  - "Resend email" calls POST /auth/resend-verification and shows the server's message.
 *  - Re-checks when the tab regains focus (the user may have verified in another tab).
 *  - If an action is refused with "verify your email", the banner is shown and highlighted.
 */
(function () {
  if (window.__saVerify) return;
  window.__saVerify = true;
  var base = function () { return (window.SecureAI && SecureAI.apiBase) ? SecureAI.apiBase() : location.origin; };
  var tok = function () { try { return sessionStorage.getItem('secureai_access_token'); } catch (e) { return null; } };
  var realFetch = window.fetch.bind(window);
  var bar = null, timer = null;

  function call(method, path) {
    return realFetch(base() + path, { method: method, headers: { Authorization: 'Bearer ' + tok() } });
  }
  function visible(e) {
    if (!e) return false;
    var r = e.getBoundingClientRect(), s = getComputedStyle(e);
    return r.width > 0 && r.height > 0 && s.display !== 'none' && s.visibility !== 'hidden';
  }
  // First VISIBLE container, in priority order. (A plain querySelector with a selector list returns the first match
  // in document order, which on the dashboard is a hidden marketing <main>, so banners went in but never showed.)
  function host() {
    var sels = ['#overviewSection', '.st-wrap', 'main'];
    for (var i = 0; i < sels.length; i++) {
      var list = document.querySelectorAll(sels[i]);
      for (var j = 0; j < list.length; j++) if (visible(list[j])) return list[j];
    }
    return document.body;
  }
  function remove() { if (bar && bar.parentNode) bar.parentNode.removeChild(bar); bar = null; if (timer) { clearInterval(timer); timer = null; } }

  function show(email, flash) {
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'saVerifyBar';
      bar.setAttribute('role', 'status');
      bar.style.cssText = 'display:flex;flex-wrap:wrap;align-items:center;gap:10px 14px;margin:0 0 18px;padding:13px 16px;' +
        'border-radius:12px;border:1px solid var(--warn-t,#e0b84a);background:var(--warn-bg,#3a2f12);color:var(--warn-t,#f7e090);font-size:13px;line-height:1.5';
      var text = document.createElement('span'); text.id = 'saVerifyText'; text.style.flex = '1 1 260px';
      var btn = document.createElement('button'); btn.type = 'button'; btn.id = 'saVerifyResend'; btn.textContent = 'Resend email';
      btn.style.cssText = 'min-height:34px;padding:0 14px;border-radius:9px;border:1px solid currentColor;background:transparent;color:inherit;font-weight:700;cursor:pointer';
      var msg = document.createElement('span'); msg.id = 'saVerifyMsg'; msg.style.cssText = 'flex:1 1 100%;font-size:12px;opacity:.95';
      bar.appendChild(text); bar.appendChild(btn); bar.appendChild(msg);
      btn.addEventListener('click', resend);
      var h = host(); h.insertBefore(bar, h.firstChild);
      timer = setInterval(check, 15000);
    }
    bar.querySelector('#saVerifyText').textContent =
      '✉️ Confirm your email to start scanning. We sent a link to ' + email + ' — open it to unlock repositories and scans.';
    if (flash) {
      bar.scrollIntoView({ behavior: 'smooth', block: 'center' });
      bar.animate([{ transform: 'scale(1)' }, { transform: 'scale(1.015)' }, { transform: 'scale(1)' }], { duration: 450, iterations: 2 });
    }
  }

  function check(flash) {
    if (!tok()) return Promise.resolve();
    return call('GET', '/auth/me').then(function (r) { return r.ok ? r.json() : null; }).then(function (me) {
      if (!me) return;
      if (me.verification_required && !me.email_verified) show(me.email, flash === true); else remove();
    }).catch(function () {});
  }

  function resend() {
    var btn = bar.querySelector('#saVerifyResend'), msg = bar.querySelector('#saVerifyMsg');
    btn.disabled = true; msg.textContent = 'Sending…';
    call('POST', '/auth/resend-verification').then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) {
        msg.textContent = (typeof d.detail === 'string' ? d.detail : (r.ok ? 'Sent.' : 'Could not send the email (HTTP ' + r.status + ').'));
        var wait = r.status === 429 ? 20000 : 8000;
        setTimeout(function () { btn.disabled = false; }, wait);
      });
    }).catch(function () { msg.textContent = 'Could not reach the server.'; btn.disabled = false; });
  }

  // A refused action ("Please verify your email address to continue.") should explain itself.
  window.fetch = function (input, init) {
    return realFetch(input, init).then(function (res) {
      if (res.status === 403) {
        res.clone().json().then(function (d) {
          if (d && typeof d.detail === 'string' && /verify your email/i.test(d.detail)) check(true);
        }).catch(function () {});
      }
      return res;
    });
  };

  document.addEventListener('visibilitychange', function () { if (!document.hidden) check(); });
  window.addEventListener('focus', function () { check(); });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { check(); }); else check();
})();