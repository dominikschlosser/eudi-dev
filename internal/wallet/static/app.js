(function() {
  'use strict';

  // Theme toggle
  const themeBtn = document.getElementById('theme-toggle');
  const saved = localStorage.getItem('wallet-theme');
  if (saved === 'light') document.documentElement.setAttribute('data-theme', 'light');
  themeBtn.addEventListener('click', () => {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    document.documentElement.setAttribute('data-theme', isLight ? '' : 'light');
    localStorage.setItem('wallet-theme', isLight ? '' : 'light');
  });

  // State
  let credentials = [];
  let pendingRequests = [];

  // Elements
  const credContainer = document.getElementById('credentials');
  const credEmpty = document.getElementById('cred-empty');
  const credCount = document.getElementById('cred-count');
  const logContainer = document.getElementById('log');
  const logEmpty = document.getElementById('log-empty');
  const offerInput = document.getElementById('offer-input');
  const processBtn = document.getElementById('process-btn');
  const importBtn = document.getElementById('import-btn');
  const importOverlay = document.getElementById('import-overlay');
  const importCancel = document.getElementById('import-cancel');
  const importSubmit = document.getElementById('import-submit');
  const importTextarea = document.getElementById('import-textarea');
  const consentOverlay = document.getElementById('consent-overlay');
  const consentDialog = document.getElementById('consent-dialog');

  // Load credentials
  async function loadCredentials() {
    try {
      const resp = await fetch('/api/credentials');
      credentials = await resp.json();
      renderCredentials();
    } catch (e) {
      console.error('Failed to load credentials:', e);
    }
  }

  function renderCredentials() {
    credCount.textContent = credentials.length + ' credential' + (credentials.length !== 1 ? 's' : '');
    if (credentials.length === 0) {
      credEmpty.style.display = '';
      credContainer.querySelectorAll('.credential-card').forEach(el => el.remove());
      return;
    }
    credEmpty.style.display = 'none';
    // Clear existing cards
    credContainer.querySelectorAll('.credential-card').forEach(el => el.remove());

    credentials.forEach(cred => {
      const card = document.createElement('div');
      card.className = 'credential-card';

      const formatClass = cred.format === 'dc+sd-jwt' ? 'format-sdjwt' : cred.format === 'jwt_vc_json' ? 'format-jwt' : 'format-mdoc';
      const formatLabel = cred.format === 'dc+sd-jwt' ? 'SD-JWT' : cred.format === 'jwt_vc_json' ? 'JWT VC' : 'mDoc';
      const typeLabel = cred.vct || cred.doctype || cred.format;

      const claimKeys = Object.keys(cred.claims || {}).slice(0, 6);
      const claimTags = claimKeys.map(k => '<span class="claim-tag">' + escHtml(k) + '</span>').join('');
      const moreCount = Object.keys(cred.claims || {}).length - claimKeys.length;
      const moreTag = moreCount > 0 ? '<span class="claim-tag">+' + moreCount + ' more</span>' : '';

      card.innerHTML = '<span class="format-badge ' + formatClass + '">' + formatLabel + '</span>' +
        '<div class="credential-info">' +
          '<div class="credential-type">' + escHtml(typeLabel) + '</div>' +
          '<div class="credential-claims">' + claimTags + moreTag + '</div>' +
        '</div>' +
        '<div class="credential-actions">' +
          '<button class="btn btn-danger btn-sm" data-delete="' + cred.id + '">Delete</button>' +
        '</div>';

      card.querySelector('[data-delete]').addEventListener('click', () => deleteCredential(cred.id));
      credContainer.appendChild(card);
    });
  }

  async function deleteCredential(id) {
    try {
      await fetch('/api/credentials/' + id, { method: 'DELETE' });
      await loadCredentials();
    } catch (e) {
      console.error('Failed to delete credential:', e);
    }
  }

  // Process URI (auto-detect VP or VCI)
  processBtn.addEventListener('click', async () => {
    const uri = offerInput.value.trim();
    if (!uri) return;

    processBtn.disabled = true;
    processBtn.textContent = 'Processing...';

    try {
      // Detect type
      const isVCI = uri.includes('credential_offer') ||
        uri.startsWith('openid-credential-offer://') ||
        uri.startsWith('haip-vci://');
      const endpoint = isVCI ? '/api/offers' : '/api/presentations';

      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ uri: uri })
      });

      const result = await resp.json();
      if (result.error) {
        alert('Error: ' + result.error);
      } else {
        offerInput.value = '';
        await loadCredentials();
        await loadLog();
      }
    } catch (e) {
      alert('Request failed: ' + e.message);
    } finally {
      processBtn.disabled = false;
      processBtn.textContent = 'Process';
    }
  });

  // Import credential
  importBtn.addEventListener('click', () => {
    importOverlay.classList.add('active');
    importTextarea.value = '';
    importTextarea.focus();
  });

  importCancel.addEventListener('click', () => {
    importOverlay.classList.remove('active');
  });

  importSubmit.addEventListener('click', async () => {
    const raw = importTextarea.value.trim();
    if (!raw) return;

    try {
      const resp = await fetch('/api/credentials', {
        method: 'POST',
        body: raw
      });
      if (!resp.ok) {
        const err = await resp.json();
        alert('Import failed: ' + (err.error || 'unknown error'));
        return;
      }
      importOverlay.classList.remove('active');
      await loadCredentials();
    } catch (e) {
      alert('Import failed: ' + e.message);
    }
  });

  // Load activity log
  async function loadLog() {
    try {
      const resp = await fetch('/api/log');
      const log = await resp.json();
      renderLog(log);
    } catch (e) {
      console.error('Failed to load log:', e);
    }
  }

  function renderLog(log) {
    logContainer.querySelectorAll('.log-entry').forEach(el => el.remove());
    if (!log || log.length === 0) {
      logEmpty.style.display = '';
      return;
    }
    logEmpty.style.display = 'none';

    log.slice().reverse().forEach(entry => {
      const el = document.createElement('div');
      el.className = 'log-entry';
      const time = new Date(entry.time).toLocaleTimeString();
      el.innerHTML = '<span class="log-time">' + time + '</span>' +
        '<span class="log-action ' + entry.action + '">' + escHtml(entry.action) + '</span>' +
        '<span class="log-detail">' + escHtml(entry.detail) + '</span>' +
        '<span class="log-status ' + (entry.success ? 'success' : 'failure') + '">' +
          (entry.success ? 'OK' : 'FAIL') + '</span>';
      logContainer.appendChild(el);
    });
  }

  // Load any existing pending consent requests
  async function loadPendingRequests() {
    try {
      const resp = await fetch('/api/requests');
      const requests = await resp.json();
      if (requests && requests.length > 0) {
        showConsentDialog(requests[0]);
        return;
      }
    } catch (e) {
      console.error('Failed to load pending requests:', e);
    }

    // No pending consent request — check for a recent error
    try {
      const resp = await fetch('/api/error');
      const err = await resp.json();
      if (err && err.message) {
        showErrorDialog(err.message, err.detail);
      }
    } catch (e) {
      console.error('Failed to load last error:', e);
    }
  }

  // SSE for consent requests and errors
  function connectSSE() {
    const es = new EventSource('/api/requests/stream');
    es.addEventListener('consent', (event) => {
      try {
        const req = JSON.parse(event.data);
        showConsentDialog(req);
      } catch (e) {
        console.error('SSE parse error:', e);
      }
    });
    es.addEventListener('error', (event) => {
      try {
        const err = JSON.parse(event.data);
        showErrorDialog(err.message, err.detail);
      } catch (e) {
        console.error('SSE error parse error:', e);
      }
    });
    es.onerror = () => {
      es.close();
      setTimeout(connectSSE, 3000);
    };
  }

  function showErrorDialog(message, detail) {
    consentOverlay.classList.add('active');

    var html = '<div class="consent-title" style="color:var(--danger)">Error</div>' +
      '<div class="consent-verifier">' + escHtml(message) + '</div>';

    if (detail) {
      html += '<pre class="error-detail">' + escHtml(detail) + '</pre>';
    }

    html += '<div class="consent-buttons">' +
      '<button class="btn btn-primary" id="error-dismiss">Dismiss</button>' +
    '</div>';

    consentDialog.innerHTML = html;
    document.getElementById('error-dismiss').addEventListener('click', () => {
      consentOverlay.classList.remove('active');
      fetch('/api/error', { method: 'DELETE' }).catch(() => {});
      loadLog();
    });
  }

  function showSubmissionResult(result) {
    // Only redirect on success — never redirect on error
    if (result.redirect_uri && !result.error) {
      window.location.href = result.redirect_uri;
      return;
    }

    consentOverlay.classList.add('active');

    var isSuccess = result.status_code && result.status_code < 400 && !result.error;
    var titleColor = isSuccess ? 'var(--success, #22c55e)' : 'var(--danger)';
    var titleText = isSuccess ? 'Success' : 'Verifier Error';

    var html = '<div class="consent-title" style="color:' + titleColor + '">' + titleText + ' (HTTP ' + (result.status_code || '?') + ')</div>';

    if (result.error) {
      // Try to parse as JSON for pretty display
      var errorBody = result.error;
      try {
        var parsed = JSON.parse(errorBody);
        errorBody = JSON.stringify(parsed, null, 2);
      } catch (e) { /* keep as-is */ }
      html += '<pre class="error-detail">' + escHtml(errorBody) + '</pre>';
    }

    html += '<div class="consent-buttons">' +
      '<button class="btn btn-primary" id="result-dismiss">Dismiss</button>' +
    '</div>';

    consentDialog.innerHTML = html;
    document.getElementById('result-dismiss').addEventListener('click', () => {
      consentOverlay.classList.remove('active');
      loadLog();
    });
  }

  function showConsentDialog(req) {
    consentOverlay.classList.add('active');

    const isIssuance = req.type === 'issuance';
    let html = '<div class="consent-title">' + (isIssuance ? 'Credential Offer' : 'Presentation Request') + '</div>' +
      '<div class="consent-verifier">' + (isIssuance ? 'Issuer: ' : 'Verifier: ') + escHtml(req.client_id) + '</div>';

    if (isIssuance && req.offer_configs && req.offer_configs.length > 0) {
      html += '<div class="consent-credential">' +
        '<div class="consent-credential-header">' +
          '<span style="font-size:12px;font-weight:600;">Credential configuration</span>' +
        '</div>' +
        '<div class="consent-claims">';
      req.offer_configs.forEach(cfg => {
        html += '<div class="consent-claim"><span class="consent-claim-name">' + escHtml(cfg) + '</span></div>';
      });
      html += '</div></div>';
    }

    if (!isIssuance && req.matched_credentials && req.matched_credentials.length > 0) {
      req.matched_credentials.forEach((mc, idx) => {
        const formatClass = mc.format === 'dc+sd-jwt' ? 'format-sdjwt' : mc.format === 'jwt_vc_json' ? 'format-jwt' : 'format-mdoc';
        const formatLabel = mc.format === 'dc+sd-jwt' ? 'SD-JWT' : mc.format === 'jwt_vc_json' ? 'JWT VC' : 'mDoc';
        const typeLabel = mc.vct || mc.doctype || mc.format;

        html += '<div class="consent-credential">' +
          '<div class="consent-credential-header">' +
            '<span class="format-badge ' + formatClass + '">' + formatLabel + '</span>' +
            '<span style="font-size:12px;font-weight:600;">' + escHtml(typeLabel) + '</span>' +
          '</div>' +
          '<div class="consent-claims">';

        const claims = mc.claims || {};
        Object.keys(claims).forEach(key => {
          const val = typeof claims[key] === 'object' ? JSON.stringify(claims[key]) : String(claims[key]);
          html += '<label class="consent-claim">' +
            '<input type="checkbox" checked data-cred="' + mc.credential_id + '" data-claim="' + escHtml(key) + '">' +
            '<span class="consent-claim-name">' + escHtml(key) + '</span>' +
            '<span class="consent-claim-value">' + escHtml(val) + '</span>' +
          '</label>';
        });

        html += '</div></div>';
      });
    }

    html += '<div class="consent-buttons">' +
      '<button class="btn btn-danger" id="consent-deny">Deny</button>' +
      '<button class="btn btn-primary" id="consent-approve">Approve</button>' +
    '</div>';

    consentDialog.innerHTML = html;

    document.getElementById('consent-approve').addEventListener('click', async () => {
      // Gather selected claims
      const selected = {};
      consentDialog.querySelectorAll('input[type="checkbox"]').forEach(cb => {
        if (cb.checked) {
          const credId = cb.dataset.cred;
          const claim = cb.dataset.claim;
          if (!selected[credId]) selected[credId] = [];
          selected[credId].push(claim);
        }
      });

      const approveBtn = document.getElementById('consent-approve');
      const denyBtn = document.getElementById('consent-deny');
      approveBtn.disabled = true;
      approveBtn.textContent = 'Submitting...';
      denyBtn.disabled = true;

      try {
        const approveBody = isIssuance ? {} : { selected_claims: selected };
        const resp = await fetch('/api/requests/' + req.id + '/approve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(approveBody)
        });
        const result = await resp.json();
        if (isIssuance) {
          if (!resp.ok || result.error || (result.status_code && result.status_code >= 400)) {
            const detail = result.error || ('HTTP ' + (result.status_code || resp.status));
            showErrorDialog('Credential issuance failed', detail);
            return;
          }
          consentOverlay.classList.remove('active');
          await loadCredentials();
          await loadLog();
          return;
        }
        showSubmissionResult(result);
      } catch (e) {
        console.error('Approve failed:', e);
        showErrorDialog('Approve request failed', e.message);
      }
    });

    document.getElementById('consent-deny').addEventListener('click', async () => {
      try {
        await fetch('/api/requests/' + req.id + '/deny', { method: 'POST' });
      } catch (e) {
        console.error('Deny failed:', e);
      }
      consentOverlay.classList.remove('active');
      await loadLog();
    });
  }

  function escHtml(s) {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  // Initialize
  if (new URLSearchParams(window.location.search).get('focus') === 'overview') {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    window.history.replaceState({}, document.title, window.location.pathname);
  }
  loadCredentials();
  loadLog();
  loadPendingRequests();
  connectSSE();
})();
