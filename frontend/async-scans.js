/*
 * async-scans.js — makes the dashboard use the queued scan API.
 *
 * Include once, AFTER the page's main script, in dashboard.html and history.html:
 *     <script src="async-scans.js"></script>
 *
 * It wraps window.fetch so the existing runScan() keeps working unchanged:
 *   POST /repositories/{id}/scan   ->  POST ...?async=true (202 queued), then polls
 *   GET  /scans/{id} until the scan is completed/failed, and hands the original code
 *   a normal 200 response containing the finished scan.
 * Against an older server (no 202) it falls straight through to the old behaviour.
 */
(function () {
  if (window.__saAsyncScans) return;
  window.__saAsyncScans = true;
  var realFetch = window.fetch.bind(window);
  var SCAN = /\/repositories\/[^/?#]+\/scan(\?|#|$)/;
  var MAX_WAIT_MS = 15 * 60 * 1000;

  function json(body, status) {
    return new Response(JSON.stringify(body), {
      status: status || 200, headers: { 'Content-Type': 'application/json' }
    });
  }
  function status(text) {
    if (typeof window.setScanStatus === 'function') window.setScanStatus(text, true);
  }

  window.fetch = async function (input, init) {
    var url = typeof input === 'string' ? input : (input && input.url) || '';
    var method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
    if (method !== 'POST' || !SCAN.test(url) || /[?&]async=/.test(url)) return realFetch(input, init);

    var start = await realFetch(url + (url.indexOf('?') >= 0 ? '&' : '?') + 'async=true', init);
    if (start.status !== 202) return start;            // error, quota, or old server: behave as before

    var scan = await start.clone().json();
    var base = url.replace(/\/repositories\/.*$/, '');
    var headers = init && init.headers;
    var deadline = Date.now() + MAX_WAIT_MS, delay = 1000;
    for (;;) {
      await new Promise(function (r) { setTimeout(r, delay); });
      delay = Math.min(Math.round(delay * 1.4), 5000);
      var poll = await realFetch(base + '/scans/' + encodeURIComponent(scan.id), { headers: headers });
      if (!poll.ok) return poll;                       // e.g. 401 after logout: surface it
      var cur = await poll.clone().json();
      if (cur.status === 'completed' || cur.status === 'failed') return json(cur);
      status(cur.status === 'queued'
        ? 'Queued — waiting for a free scanner…'
        : 'Scanning repository — this can take a moment…');
      if (Date.now() > deadline) {
        return json(Object.assign({}, cur, { status: 'failed', error: 'Timed out waiting for the scan.' }));
      }
    }
  };
})();