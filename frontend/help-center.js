/*
 * help-center.js — the "Help & Support" panel (FAQ + contact form).
 * Loaded by session-guard.js on every signed-in page; opens from the sidebar "Help & Support" button.
 * Uses the page's own colour variables, so it follows light/dark mode automatically.
 */
(function () {
  if (window.__saHelp) return;
  window.__saHelp = true;

  var FAQ = [
    ['How do I scan a repository?',
      'On the Overview page choose <b>Connect with GitHub</b> (you pick which repositories SecureAI may read) or paste a repository URL and press <b>Connect &amp; Scan</b>. A scan usually takes under a few minutes. Finished scans appear on Overview and in <b>History</b>, where <b>View Report</b> opens the full findings.'],
    ['What does SecureAI look for?',
      'It statically analyses your code for the security boundary between AI output and real actions: AI-controlled payments, emails or database changes, command execution, sensitive data sent to outside services, hard-coded credentials, injection risks and missing human approval. It asks whether a value produced by AI actually <i>reaches</i> a consequential operation, not just whether AI is present.'],
    ['What does the security score mean?',
      'It is a heuristic triage signal: higher means fewer and less severe open findings, and it rises when you resolve findings. It is not a percentage of security and not a guarantee that a repository is safe, so treat it as a way to decide what to look at first.'],
    ['Is my source code stored?',
      'By default SecureAI does not keep source snippets, and scan results are deleted automatically after the retention period (30 days unless your administrator changed it). SecureAI never asks for your GitHub password or one-time codes; GitHub handles sign-in and access.'],
    ['I did not get the confirmation or reset email',
      'Check your spam folder first. For the confirmation email use <b>Resend email</b> in the banner on Overview (you can request one about once a minute). For a reset, use <b>Forgot password?</b> on the log-in page. Reset links work once and expire after 30 minutes.'],
    ['How do I turn on two-factor authentication?',
      'Go to <b>Settings &rarr; Security &rarr; Two-Factor Authentication</b>, scan the QR code with an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, 1Password) and enter the 6-digit code. Save the recovery codes it shows: each works once if you lose your phone.'],
    ['I lost my phone and my recovery codes',
      'Send us a message below with category <b>Account or sign-in</b> from the e-mail address on the account. We will verify it is you before turning two-factor off.'],
    ['My account is locked',
      'After several wrong passwords or codes in a row, sign-in pauses for about 15 minutes. You can try again after that, or use <b>Forgot password?</b> to unlock straight away by choosing a new password.'],
    ['How do I disconnect GitHub?',
      'Open <b>Settings &rarr; Integrations &rarr; Disconnect</b>. SecureAI stops reading your repositories immediately and keeps past reports until they expire. To also remove the app from GitHub, open GitHub &rarr; Settings &rarr; Applications and uninstall it.']
  ];

  var CATEGORIES = [['question', 'Question'], ['bug', 'Something is not working'], ['account', 'Account or sign-in'],
                    ['security', 'Security concern'], ['feature', 'Feature request']];
  var overlay = null, lastFocus = null;

  function css() {
    if (document.getElementById('saHelpCss')) return;
    var s = document.createElement('style'); s.id = 'saHelpCss';
    s.textContent =
      '.sh-ov{position:fixed;inset:0;z-index:9999;background:rgba(6,10,20,.55);display:flex;align-items:flex-start;justify-content:center;padding:6vh 16px;overflow:auto}' +
      '.sh-box{width:100%;max-width:660px;background:var(--panel,#fff);color:var(--text,#1b2538);border:1px solid var(--line,#e0e5ef);border-radius:16px;box-shadow:0 24px 70px rgba(0,0,0,.35);font:14px/1.55 Inter,system-ui,sans-serif}' +
      '.sh-head{display:flex;align-items:center;justify-content:space-between;padding:20px 24px 6px}.sh-head h2{margin:0;font-size:20px}' +
      '.sh-x{background:none;border:0;color:var(--muted,#64748b);font-size:24px;line-height:1;cursor:pointer;padding:4px 8px;border-radius:8px}.sh-x:hover{background:var(--panel2,#f3f5fb)}' +
      '.sh-sub{margin:0;padding:0 24px 14px;color:var(--muted,#64748b)}.sh-body{padding:0 24px 24px}' +
      '.sh-sec{margin:18px 0 8px;font-size:11px;letter-spacing:.08em;font-weight:800;color:var(--muted,#64748b);text-transform:uppercase}' +
      '.sh-box details{border:1px solid var(--line,#e0e5ef);border-radius:10px;margin:0 0 8px;background:var(--panel2,#f3f5fb)}' +
      '.sh-box summary{cursor:pointer;padding:11px 14px;font-weight:600;list-style:none}.sh-box summary::-webkit-details-marker{display:none}' +
      '.sh-box summary:before{content:"+";display:inline-block;width:18px;color:var(--accent,#6f5de8);font-weight:800}.sh-box details[open] summary:before{content:"\\2212"}' +
      '.sh-box details div{padding:0 14px 13px 32px;color:var(--muted,#64748b)}.sh-box details div b,.sh-box details div i{color:var(--text,#1b2538)}' +
      '.sh-box label{display:block;font-size:12px;font-weight:700;margin:10px 0 4px}' +
      '.sh-box select,.sh-box input,.sh-box textarea{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid var(--line2,#cfd6e4);border-radius:10px;background:var(--input,#fff);color:var(--text,#1b2538);font:inherit}' +
      '.sh-box textarea{min-height:110px;resize:vertical}.sh-box :focus-visible{outline:2px solid var(--accent,#6f5de8);outline-offset:1px}' +
      '.sh-row{display:flex;align-items:center;gap:12px;margin-top:14px;flex-wrap:wrap}' +
      '.sh-send{background:linear-gradient(135deg,var(--accent,#6f5de8),var(--accent2,#7c63f0));color:#fff;border:0;border-radius:10px;padding:0 22px;min-height:40px;font-weight:700;cursor:pointer}.sh-send:disabled{opacity:.6;cursor:default}' +
      '.sh-msg{font-size:13px}.sh-msg.ok{color:var(--green,#12a36d)}.sh-msg.bad{color:var(--red,#d93036)}.sh-mail a{color:var(--accent,#6f5de8);font-weight:700}';
    document.head.appendChild(s);
  }

  function el(tag, attrs, html) {
    var n = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    if (html != null) n.innerHTML = html;
    return n;
  }
  function base() { return (window.SecureAI && SecureAI.apiBase) ? SecureAI.apiBase() : ''; }
  function authHeaders() {
    return { 'Authorization': 'Bearer ' + sessionStorage.getItem('secureai_access_token'), 'Content-Type': 'application/json' };
  }

  function close() {
    if (!overlay) return;
    overlay.remove(); overlay = null;
    document.removeEventListener('keydown', onKey, true);
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }
  function onKey(e) { if (e.key === 'Escape') { e.stopPropagation(); close(); } }

  function open() {
    if (overlay) return;
    css(); lastFocus = document.activeElement;
    overlay = el('div', { 'class': 'sh-ov' });
    var box = el('div', { 'class': 'sh-box', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'shTitle' });
    box.innerHTML =
      '<div class="sh-head"><h2 id="shTitle">Help &amp; Support</h2><button type="button" class="sh-x" aria-label="Close">&times;</button></div>' +
      '<p class="sh-sub">Answers to common questions, or send us a message.</p><div class="sh-body">' +
      '<div class="sh-sec">Common questions</div><div id="shFaq"></div>' +
      '<div class="sh-sec">Contact support</div>' +
      '<form id="shForm" novalidate><label for="shCat">What is this about?</label><select id="shCat"></select>' +
      '<label for="shSub">Subject</label><input id="shSub" maxlength="120" autocomplete="off">' +
      '<label for="shMsg">Message</label><textarea id="shMsg" maxlength="4000" placeholder="Tell us what happened and what you expected. Never include passwords or access tokens."></textarea>' +
      '<div class="sh-row"><button type="submit" class="sh-send" id="shSend">Send message</button><span class="sh-msg" id="shNote" role="status"></span></div></form>' +
      '<p class="sh-mail" id="shMail" style="margin:14px 0 0;color:var(--muted,#64748b)"></p></div>';
    overlay.appendChild(box); document.body.appendChild(overlay);

    var faq = box.querySelector('#shFaq');
    FAQ.forEach(function (q) { var d = el('details'); d.appendChild(el('summary', null, '')); d.firstChild.textContent = q[0]; d.appendChild(el('div', null, q[1])); faq.appendChild(d); });
    var cat = box.querySelector('#shCat');
    CATEGORIES.forEach(function (c) { var o = el('option'); o.value = c[0]; o.textContent = c[1]; cat.appendChild(o); });

    box.querySelector('.sh-x').onclick = close;
    overlay.addEventListener('mousedown', function (e) { if (e.target === overlay) close(); });
    document.addEventListener('keydown', onKey, true);

    var note = box.querySelector('#shNote'), send = box.querySelector('#shSend');
    function say(t, cls) { note.textContent = t; note.className = 'sh-msg ' + (cls || ''); }
    box.querySelector('#shForm').addEventListener('submit', function (e) {
      e.preventDefault();
      var subject = box.querySelector('#shSub').value.trim(), message = box.querySelector('#shMsg').value.trim();
      if (subject.length < 3) { say('Add a short subject (at least 3 characters).', 'bad'); return; }
      if (message.length < 10) { say('Please describe the problem in a little more detail (at least 10 characters).', 'bad'); return; }
      send.disabled = true; say('Sending…');
      fetch(base() + '/support/requests', { method: 'POST', headers: authHeaders(),
        body: JSON.stringify({ category: cat.value, subject: subject, message: message }) })
        .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return { r: r, j: j }; }); })
        .then(function (x) {
          if (x.r.ok) {
            say(x.j.detail || 'Thanks, your message was sent.', 'ok');
            box.querySelector('#shSub').value = ''; box.querySelector('#shMsg').value = '';
          } else if (x.r.status === 429) { say('You have sent several messages just now. Please wait a few minutes.', 'bad'); }
          else if (x.r.status === 422) { say('Please check the subject and message and try again.', 'bad'); }
          else { say(typeof x.j.detail === 'string' ? x.j.detail : 'Could not send your message. Please try again.', 'bad'); }
        })
        .catch(function () { say('Could not reach the server. Please try again.', 'bad'); })
        .then(function () { send.disabled = false; });
    });

    fetch(base() + '/support/info', { headers: authHeaders() }).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        var p = box.querySelector('#shMail');
        if (j && j.email) { p.textContent = 'Prefer e-mail? Write to '; var a = el('a'); a.href = 'mailto:' + j.email; a.textContent = j.email; p.appendChild(a); p.appendChild(document.createTextNode('.')); }
      }).catch(function () {});
    box.querySelector('.sh-x').focus();
  }

  // Intercept the sidebar button before the page's own placeholder handler runs.
  document.addEventListener('click', function (e) {
    var t = e.target && e.target.closest ? e.target.closest('#saHelp, [data-help]') : null;
    if (t) { e.preventDefault(); e.stopImmediatePropagation(); open(); }
  }, true);
  window.SecureAIHelp = { open: open, close: close };
})();
