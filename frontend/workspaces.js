/*
 * workspaces.js — workspace switcher + in-app invitations.
 * Loaded by session-guard.js on every signed-in page.
 *  - Fills the header "workspace" dropdown with every workspace the account belongs to; clicking one switches to it.
 *  - Shows invitations addressed to this account as a banner with Accept / Decline, so nobody has to hunt for an e-mail.
 */
(function () {
  if (window.__saWs) return;
  window.__saWs = true;

  function base() { return window.SecureAI.apiBase(); }
  function hdr() {
    return { 'Authorization': 'Bearer ' + sessionStorage.getItem('secureai_access_token'), 'Content-Type': 'application/json' };
  }
  function call(path, method, data) {
    var o = { method: method || 'GET', headers: hdr() };
    if (data) o.body = JSON.stringify(data);
    return fetch(base() + path, o).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { return { ok: r.ok, status: r.status, j: j }; });
    }).catch(function () { return { ok: false, status: 0, j: { detail: 'Could not reach the server.' } }; });
  }
  function el(tag, css, text) {
    var n = document.createElement(tag);
    if (css) n.style.cssText = css;
    if (text != null) n.textContent = text;
    return n;
  }
  function toast(m) { try { if (window.SA && SA.toast) SA.toast(m); } catch (e) {} }

  // The page reads the active workspace from sessionStorage; a reload then wipes the other workspace's caches
  // (session-guard compares organisation|user) and rebuilds history for the new one.
  function activate(orgId) {
    try {
      sessionStorage.setItem('secureai_organization_id', orgId);
      var raw = sessionStorage.getItem('aisc_session');
      if (raw) { var o = JSON.parse(raw); if (o) { o.orgId = orgId; sessionStorage.setItem('aisc_session', JSON.stringify(o)); } }
    } catch (e) {}
    location.reload();
  }

  // ------------------------------------------------------------ switcher
  function paintSwitcher(list) {
    var pop = document.getElementById('saWsPop');
    if (!pop || !list || !list.length) return;
    var old = document.getElementById('saWsList');
    if (old) old.remove();
    var box = el('div'); box.id = 'saWsList'; box.setAttribute('role', 'menu');
    list.forEach(function (w) {
      var a = el('a', 'display:flex;justify-content:space-between;align-items:center;gap:10px;cursor:pointer');
      a.href = '#'; a.setAttribute('role', 'menuitem');
      a.appendChild(el('span', 'font-weight:' + (w.active ? '800' : '600'), w.name + (w.active ? '  \u2713' : '')));
      a.appendChild(el('small', 'opacity:.65;text-transform:capitalize;font-size:11px', w.role));
      a.addEventListener('click', function (e) {
        e.preventDefault();
        if (w.active) return;
        call('/team/workspaces/switch', 'POST', { organization_id: w.id }).then(function (r) {
          if (r.ok) activate(r.j.organization_id); else toast((r.j && r.j.detail) || 'Could not switch workspace.');
        });
      });
      box.appendChild(a);
    });
    var nameEl = document.getElementById('saWsPopName');
    if (nameEl) { nameEl.style.display = 'none'; nameEl.parentNode.insertBefore(box, nameEl.nextSibling); }
    else pop.insertBefore(box, pop.children[1] || null);
  }

  // ------------------------------------------------------------ invitations banner
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

  function paintInvites(list) {
    var old = document.getElementById('saInviteBar');
    if (old) { wanted = null; old.remove(); }
    if (!list || !list.length) return;
    var bar = el('div', 'margin:0 0 14px;display:flex;flex-direction:column;gap:8px');
    bar.id = 'saInviteBar'; bar.setAttribute('role', 'status');
    list.slice(0, 3).forEach(function (inv) {
      var row = el('div', 'display:flex;flex-wrap:wrap;align-items:center;gap:10px;padding:12px 14px;border-radius:12px;' +
        'background:var(--ok-bg,#e6f4ff);color:var(--ok-t,#0b4f7a);font-size:13px;line-height:1.5');
      var txt = el('div', 'flex:1;min-width:220px');
      var b = el('b', null, inv.organization_name);
      txt.appendChild(document.createTextNode('You were invited to join '));
      txt.appendChild(b);
      txt.appendChild(document.createTextNode(' as ' + (inv.role === 'admin' ? 'an admin' : 'a member') +
        (inv.invited_by ? ' by ' + inv.invited_by : '') + '.'));
      row.appendChild(txt);
      var msg = el('span', 'font-size:12px');
      function btn(label, primary, fn) {
        var x = el('button', 'border:0;border-radius:10px;padding:0 16px;min-height:34px;font-weight:700;cursor:pointer;font-size:13px;' +
          (primary ? 'background:linear-gradient(135deg,var(--accent,#6f5de8),var(--accent2,#7c63f0));color:#fff' : 'background:rgba(0,0,0,.08);color:inherit'), label);
        x.type = 'button'; x.onclick = fn; return x;
      }
      var acc = btn('Accept', true, function () {
        acc.disabled = dec.disabled = true; msg.textContent = 'Joining\u2026';
        call('/team/my-invitations/' + encodeURIComponent(inv.id) + '/accept', 'POST').then(function (r) {
          if (r.ok) activate(r.j.organization_id);
          else { msg.textContent = (r.j && r.j.detail) || 'Could not accept the invitation.'; acc.disabled = dec.disabled = false; }
        });
      });
      var dec = btn('Decline', false, function () {
        acc.disabled = dec.disabled = true;
        call('/team/my-invitations/' + encodeURIComponent(inv.id) + '/decline', 'POST').then(function (r) {
          if (r.ok) { row.remove(); toast('Invitation declined.'); if (!bar.children.length) { wanted = null; bar.remove(); } }
          else { acc.disabled = dec.disabled = false; msg.textContent = (r.j && r.j.detail) || 'Could not decline.'; }
        });
      });
      row.appendChild(acc); row.appendChild(dec); row.appendChild(msg);
      bar.appendChild(row);
    });
    place(bar);
  }

  // Put the banner in the visible content area, and put it back if the page re-renders that area.
  var wanted = null, watching = false;
  function place(bar) {
    wanted = bar;
    attach();
    if (watching) return;
    watching = true;
    var timer = null;
    var mo = new MutationObserver(function () {
      clearTimeout(timer);
      timer = setTimeout(function () { if (wanted && !wanted.isConnected) attach(); }, 120);
    });
    mo.observe(document.body, { childList: true, subtree: true });
    setTimeout(function () { mo.disconnect(); watching = false; }, 30000);
    var tries = 0, iv = setInterval(function () {            // the visible container may not exist for a moment
      if (!wanted || wanted.isConnected && visible(wanted) || ++tries > 20) clearInterval(iv); else attach();
    }, 300);
  }
  function attach() {
    if (!wanted) return;
    var h = host();
    if (wanted.parentNode === h && h.firstChild === wanted) return;
    h.insertBefore(wanted, h.firstChild);
  }

  function refresh() {
    call('/team/workspaces').then(function (r) { if (r.ok) paintSwitcher(r.j.workspaces); });
    call('/team/my-invitations').then(function (r) { if (r.ok) paintInvites(r.j.invitations); });
  }
  window.SecureAIWorkspaces = { refresh: refresh };
  refresh();
})();
