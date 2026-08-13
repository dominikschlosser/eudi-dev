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

  // Header menu toggle (narrow screens). The links are a horizontal row on
  // wide screens and a drop-down list behind this button when they no longer
  // fit; CSS decides which via the media query, this only flips the state.
  const menuToggle = document.getElementById('header-menu-toggle');
  const headerLinks = document.getElementById('header-links');
  if (menuToggle && headerLinks) {
    menuToggle.addEventListener('click', () => {
      const open = headerLinks.classList.toggle('open');
      menuToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    // Tapping a link closes the menu so it does not stay open over content.
    headerLinks.addEventListener('click', (e) => {
      if (e.target.tagName === 'A') {
        headerLinks.classList.remove('open');
        menuToggle.setAttribute('aria-expanded', 'false');
      }
    });
  }

  // The wallet is shared, so anything meant for the visitor who started a flow
  // has to reach that tab and no other: the consent dialog, the issuer
  // sign-in, the error report. A claim is how a tab says the next one is
  // hers. Single use and short lived, so a stale marker never collects
  // someone else's.
  function createClaim(windowMs, claimedNow) {
    let until = claimedNow ? Date.now() + windowMs : 0;
    return {
      expect() {
        until = Date.now() + windowMs;
      },
      take() {
        if (!until || Date.now() > until) return false;
        until = 0;
        return true;
      },
    };
  }

  // A scheme dispatch (openid4vp:// or credential-offer:// handled by the OS)
  // opens this UI itself and only then submits the request, so this tab
  // started the flow even though no request id can be in its URL yet. The
  // marker says so, which is what separates it from the uninvolved tabs the
  // pending banner exists for. It covers the resulting error too.
  const params = new URLSearchParams(window.location.search);
  const schemeDispatch = params.get('consent') === 'await';
  // Coming back from an issuer sign-in: this tab started that flow, so its
  // outcome is this tab's to report.
  const returnedFromSignIn = params.get('signin') === 'done';

  const consentClaim = createClaim(90000, schemeDispatch);
  // Longer, because both run past a round trip to the issuer.
  const authorizeClaim = createClaim(120000);
  const errorClaim = createClaim(120000, schemeDispatch || returnedFromSignIn);

  // State
  let credentials = [];
  let pendingRequests = [];
  // A shared demo can accumulate a lot of credentials, so the list is
  // windowed server side rather than rendering everything.
  const CREDENTIALS_PER_PAGE = 10;
  let credentialPage = 0;
  let credentialTotal = 0;

  // Elements
  const credContainer = document.getElementById('credentials');
  const credEmpty = document.getElementById('cred-empty');
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
  // Credentials an issuer deferred. The wallet collects them on the issuer's
  // own interval; the buttons are for going faster than that, or giving up.
  async function loadDeferred() {
    try {
      const resp = await fetch('/api/deferred');
      const pending = await resp.json();
      const section = document.getElementById('deferred-section');
      const list = document.getElementById('deferred-list');
      if (!section || !list) return;
      if (!Array.isArray(pending) || pending.length === 0) {
        section.hidden = true;
        list.innerHTML = '';
        return;
      }
      section.hidden = false;
      list.innerHTML = pending.map(p => {
        const name = p.vct || p.doctype || p.credential_configuration_id || p.format || 'Credential';
        const next = p.next_attempt_at ? new Date(p.next_attempt_at) : null;
        const when = next && !isNaN(next) ? next.toLocaleTimeString() : '';
        return '<div class="deferred-item" data-id="' + escHtml(p.id) + '">' +
          '<div class="deferred-item-head">' +
            '<span class="deferred-badge">Deferred</span>' +
            '<span class="deferred-name">' + escHtml(name) + '</span>' +
          '</div>' +
          '<div class="deferred-meta">' + escHtml(p.issuer || '') + '</div>' +
          '<div class="deferred-meta">' +
            'The issuer asked the wallet to check back every ' + escHtml(p.interval || '') +
            (when ? '. Next attempt at ' + escHtml(when) : '') +
            (p.attempts ? ' (' + escHtml(p.attempts) + ' so far)' : '') +
          '</div>' +
          (p.last_error ? '<div class="deferred-meta deferred-error">' + escHtml(p.last_error) + '</div>' : '') +
          '<div class="deferred-actions">' +
            '<button class="btn btn-sm deferred-check" data-id="' + escHtml(p.id) + '">Check now</button>' +
            '<button class="btn btn-sm btn-danger deferred-abandon" data-id="' + escHtml(p.id) + '">Abandon</button>' +
          '</div>' +
        '</div>';
      }).join('');

      // Check asks the issuer now instead of at the next scheduled attempt.
      // Abandon stops the wallet asking at all.
      list.querySelectorAll('.deferred-check').forEach(btn => {
        btn.addEventListener('click', async () => {
          btn.disabled = true;
          btn.textContent = 'Checking...';
          try {
            const resp = await fetch('/api/deferred/' + encodeURIComponent(btn.dataset.id) + '/collect', { method: 'POST' });
            const result = await resp.json();
            if (result.abandoned) {
              showErrorDialog('Deferred credential was not issued', result.reason || 'The issuer refused it.');
            }
            await loadDeferred();
            await loadCredentials();
            await loadLog();
          } catch (e) {
            console.error('Checking a deferred credential failed:', e);
            btn.disabled = false;
            btn.textContent = 'Check now';
          }
        });
      });
      list.querySelectorAll('.deferred-abandon').forEach(btn => {
        btn.addEventListener('click', async () => {
          btn.disabled = true;
          try {
            await fetch('/api/deferred/' + encodeURIComponent(btn.dataset.id), { method: 'DELETE' });
            await loadDeferred();
            await loadLog();
          } catch (e) {
            console.error('Abandoning a deferred credential failed:', e);
            btn.disabled = false;
          }
        });
      });
    } catch (e) {
      console.error('Loading deferred issuances failed:', e);
    }
  }

  async function loadCredentials() {
    try {
      const offset = credentialPage * CREDENTIALS_PER_PAGE;
      const resp = await fetch('/api/credentials?limit=' + CREDENTIALS_PER_PAGE + '&offset=' + offset);
      credentials = await resp.json();
      credentialTotal = parseInt(resp.headers.get('X-Total-Count') || '0', 10);
      // Deleting the last credential of a page (or a reset) can leave us
      // past the end: step back instead of showing an empty list.
      if (credentials.length === 0 && credentialPage > 0) {
        credentialPage = Math.max(0, Math.ceil(credentialTotal / CREDENTIALS_PER_PAGE) - 1);
        return loadCredentials();
      }
      renderCredentials();
      renderPager();
      // Issuance can add trust list groups, so keep the links in sync.
      loadTrustLists();
    } catch (e) {
      console.error('Failed to load credentials:', e);
    }
  }

  function renderPager() {
    const pager = document.getElementById('cred-pager');
    const pages = Math.ceil(credentialTotal / CREDENTIALS_PER_PAGE);
    if (pages <= 1) {
      pager.hidden = true;
      return;
    }
    const first = credentialPage * CREDENTIALS_PER_PAGE + 1;
    const last = first + credentials.length - 1;
    document.getElementById('cred-range').textContent =
      first + '\u2013' + last + ' of ' + credentialTotal;
    document.getElementById('cred-prev').disabled = credentialPage === 0;
    document.getElementById('cred-next').disabled = credentialPage >= pages - 1;
    pager.hidden = false;
  }

  document.getElementById('cred-prev').addEventListener('click', () => {
    if (credentialPage === 0) return;
    credentialPage--;
    loadCredentials();
  });
  document.getElementById('cred-next').addEventListener('click', () => {
    if ((credentialPage + 1) * CREDENTIALS_PER_PAGE >= credentialTotal) return;
    credentialPage++;
    loadCredentials();
  });

  // What a credential carries, in the shape the credential has it.
  //
  // mdoc elements are keyed "namespace:element", and two credentials can share
  // a doctype while differing only in the namespaces they use: the German PID
  // keeps its national elements in eu.europa.ec.eudi.pid.de.1 beside the
  // eu.europa.ec.eudi.pid.1 elements every PID has. So the extra namespaces are
  // what the card has to show, and only those: the credential's own namespace
  // is the doctype in the headline already, and repeating it says nothing.
  // SD-JWT claims have no namespace and stay a plain list.
  function claimTagsFor(cred) {
    const names = Object.keys(cred.claims || {});
    if (names.length === 0) return '';

    const groups = new Map();
    for (const name of names) {
      const sep = name.indexOf(':');
      const ns = sep === -1 ? '' : name.slice(0, sep);
      const element = sep === -1 ? name : name.slice(sep + 1);
      if (!groups.has(ns)) groups.set(ns, []);
      groups.get(ns).push(element);
    }
    if (groups.size === 1 && groups.has('')) return claimTagList(groups.get(''), 6);

    // Shortest first: a domestic namespace extends the one it is built from
    // (eu.europa.ec.eudi.pid.1 then eu.europa.ec.eudi.pid.de.1), and reading
    // them in that order says which is which.
    const namespaces = [...groups.keys()].sort((a, b) => a.length - b.length || a.localeCompare(b));
    const base = namespaces.includes(cred.doctype) ? cred.doctype : namespaces[0];

    return namespaces.map(ns => {
      const elements = groups.get(ns).sort();
      // The doctype namespace needs no label, the headline is it. Any other
      // primary one does, because then the elements are not where the doctype
      // says (an mDL keeps org.iso.18013.5.1.mDL elements in org.iso.18013.5.1).
      if (ns === base) {
        const label = ns === cred.doctype ? '' : namespaceChip(ns, ns, elements);
        return label + claimTagList(elements, namespaces.length > 1 ? 4 : 6);
      }
      return namespaceChip(ns, base, elements) + claimTagList(elements, 3);
    }).join('');
  }

  // A namespace beside the credential's own, named by what it adds to it:
  // "+de.1" for eu.europa.ec.eudi.pid.de.1 next to eu.europa.ec.eudi.pid.1.
  // Spelling it out in full would repeat the base namespace, which is what
  // made two different credentials look alike in the first place.
  function namespaceChip(ns, base, elements) {
    const title = elements.length + (elements.length === 1 ? ' element in ' : ' elements in ') + ns;
    return '<span class="claim-namespace" title="' + escHtml(title) + '" data-namespace="' + escHtml(ns) + '">' +
      escHtml(namespaceDelta(ns, base)) + '</span>';
  }

  // What a namespace adds to the one it is built from, by dotted segment. A
  // domestic namespace either appends to the full identifier
  // (org.iso.18013.5.1 -> org.iso.18013.5.1.US) or replaces its version
  // (eu.europa.ec.eudi.pid.1 -> eu.europa.ec.eudi.pid.de.1), and the segments
  // they share cover both. Namespaces that only happen to start alike are not
  // in that relationship, so they keep their full name.
  function namespaceDelta(ns, base) {
    if (ns === base) return ns;
    const parts = ns.split('.');
    const baseParts = base.split('.');
    let shared = 0;
    while (shared < parts.length && shared < baseParts.length && parts[shared] === baseParts[shared]) shared++;
    if (shared < 2 || shared < baseParts.length - 1) return ns;
    return '+' + parts.slice(shared).join('.');
  }

  // Up to max names, then a count of what is left.
  function claimTagList(names, max) {
    const shown = names.slice(0, max)
      .map(name => '<span class="claim-tag">' + escHtml(name) + '</span>').join('');
    const rest = names.length - Math.min(names.length, max);
    return shown + (rest > 0 ? '<span class="claim-tag">+' + rest + ' more</span>' : '');
  }

  function renderCredentials() {
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
      const isProtected = cred.protected === true;

      const claimSummary = claimTagsFor(cred);

      // Stable identity and selection hooks for UI automation
      card.id = 'credential-' + cred.id;
      card.dataset.credentialId = cred.id;
      card.dataset.format = formatLabel === 'SD-JWT' ? 'sdjwt' : formatLabel === 'JWT VC' ? 'jwt' : 'mdoc';
      if (isProtected) card.dataset.protected = 'true';
      if (cred.vct) card.dataset.vct = cred.vct;
      if (cred.doctype) card.dataset.doctype = cred.doctype;

      // Status badge: managed entries show live status, foreign status lists
      // get a badge plus an explicit check action.
      const st = cred.status;
      let statusBadge = '';
      let revokeBtn = '';
      // Protected credentials are the shared baseline: the server refuses to
      // delete or revoke them, so do not offer buttons that would only 403.
      const protectedBadge = isProtected
        ? '<span class="status-badge status-protected" id="protected-' + cred.id + '"' +
          ' title="Part of this wallet\'s baseline. It cannot be deleted or revoked' +
          ' through the UI or the API, only by editing the wallet file.">Protected</span>'
        : '';
      if (st && st.managed) {
        const revoked = st.status === 1;
        card.dataset.status = revoked ? 'revoked' : 'active';
        statusBadge = '<span class="status-badge ' + (revoked ? 'status-revoked' : 'status-active') + '" id="status-' + cred.id + '" title="Status list: ' + escHtml(st.uri || '') + ' idx ' + st.idx + '">' + (revoked ? 'Revoked' : 'Active') + '</span>';
        if (!isProtected) {
          revokeBtn = '<button class="btn btn-sm" id="revoke-' + cred.id + '" data-revoke="' + cred.id + '">' + (revoked ? 'Activate' : 'Revoke') + '</button>';
        }
      } else if (st && st.uri) {
        card.dataset.status = 'external';
        statusBadge = '<span class="status-badge status-external" id="status-' + cred.id + '" title="External status list: ' + escHtml(st.uri) + ' idx ' + st.idx + '">External status</span>';
        revokeBtn = '<button class="btn btn-sm" id="status-check-' + cred.id + '" data-check-status="' + cred.id + '">Check status</button>';
      } else {
        card.dataset.status = 'none';
      }

      // How long the credential is still good for. The wallet renews what it
      // can shortly before this, so a date here is not always a deadline.
      const expiry = expiryInfo(cred.expires_at);
      let expiryBadge = '';
      if (expiry) {
        card.dataset.expiry = expiry.state;
        expiryBadge = '<span class="status-badge status-' + expiry.state + '" id="expiry-' + cred.id +
          '" title="' + escHtml(expiry.title) + '">' + escHtml(expiry.label) + '</span>';
      }

      card.innerHTML = '<span class="format-badge ' + formatClass + '">' + formatLabel + '</span>' +
        '<div class="credential-info" title="Open in decoder">' +
          '<div class="credential-type">' + escHtml(typeLabel) + statusBadge + expiryBadge + protectedBadge + '</div>' +
          '<div class="credential-claims">' + claimSummary + '</div>' +
        '</div>' +
        '<div class="credential-actions">' +
          revokeBtn +
          '<button class="btn btn-sm" id="show-' + cred.id + '" data-show="' + cred.id + '">Show</button>' +
          (isProtected ? '' : '<button class="btn btn-danger btn-sm" id="delete-' + cred.id + '" data-delete="' + cred.id + '">Delete</button>') +
        '</div>';

      const openDecoder = () => {
        // By id: the decoder is mounted on this wallet and can look the
        // credential up, which keeps the link short enough to share.
        window.open('/decoder/?id=' + encodeURIComponent(cred.id), '_blank');
      };
      card.querySelector('[data-show]').addEventListener('click', openDecoder);
      card.querySelector('.credential-info').addEventListener('click', openDecoder);
      const del = card.querySelector('[data-delete]');
      if (del) {
        del.addEventListener('click', () => deleteCredential(cred.id));
      }
      const revoke = card.querySelector('[data-revoke]');
      if (revoke) {
        revoke.addEventListener('click', () => setCredentialStatus(cred.id, st.status === 1 ? 0 : 1));
      }
      const check = card.querySelector('[data-check-status]');
      if (check) {
        check.addEventListener('click', () => checkCredentialStatus(cred.id));
      }
      credContainer.appendChild(card);
    });
  }

  // expiryInfo turns an RFC 3339 expiry into what the badge shows: how long
  // is left, because "in 3 days" answers the question the absolute date only
  // implies. The exact time stays on the tooltip. Returns null for a
  // credential that states no lifetime, which then gets no badge at all.
  function expiryInfo(value) {
    if (!value) return null;
    const when = new Date(value);
    if (isNaN(when.getTime())) return null;

    const absolute = when.toLocaleString();
    const seconds = (when.getTime() - Date.now()) / 1000;
    if (seconds <= 0) {
      return { state: 'expired', label: 'Expired', title: 'Expired ' + absolute };
    }
    // Under a day is worth pointing at: the wallet renews shortly before
    // expiry, and a credential this close is either about to be renewed or
    // cannot be.
    const state = seconds < 24 * 3600 ? 'expiring' : 'valid';
    return { state: state, label: 'Valid ' + humanizeDuration(seconds), title: 'Valid until ' + absolute };
  }

  // humanizeDuration renders seconds as the one unit worth reading.
  function humanizeDuration(seconds) {
    const units = [
      [365 * 24 * 3600, 'year'],
      [30 * 24 * 3600, 'month'],
      [24 * 3600, 'day'],
      [3600, 'hour'],
      [60, 'minute'],
    ];
    for (const [size, name] of units) {
      if (seconds >= size) {
        const count = Math.floor(seconds / size);
        return 'for ' + count + ' ' + name + (count === 1 ? '' : 's');
      }
    }
    return 'for less than a minute';
  }

  // Revoke (status 1) or re-activate (status 0) a credential on the wallet's
  // own status list.
  async function setCredentialStatus(id, status) {
    try {
      const resp = await fetch('/api/credentials/' + id + '/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: status })
      });
      if (!resp.ok) {
        const result = await resp.json().catch(() => ({}));
        alert('Setting status failed: ' + (result.error || 'HTTP ' + resp.status));
        return;
      }
      await loadCredentials();
      await loadLog();
    } catch (e) {
      alert('Setting status failed: ' + e.message);
    }
  }

  // Resolve the live status of a credential on an external status list.
  async function checkCredentialStatus(id) {
    const badge = document.getElementById('status-' + id);
    if (badge) badge.textContent = 'Checking...';
    try {
      const resp = await fetch('/api/credentials/' + id + '/status');
      const result = await resp.json();
      if (!badge) return;
      if (!resp.ok) {
        badge.textContent = 'Check failed';
        badge.title = result.error || ('HTTP ' + resp.status);
        return;
      }
      const revoked = result.status === 1;
      badge.textContent = revoked ? 'Revoked' : 'Active';
      badge.classList.remove('status-external');
      badge.classList.add(revoked ? 'status-revoked' : 'status-active');
      const card = document.getElementById('credential-' + id);
      if (card) card.dataset.status = revoked ? 'revoked' : 'active';
    } catch (e) {
      if (badge) {
        badge.textContent = 'Check failed';
        badge.title = e.message;
      }
    }
  }

  async function deleteCredential(id) {
    try {
      await fetch('/api/credentials/' + id, { method: 'DELETE' });
      await loadCredentials();
      await loadLog();
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
      // Submitting an offer here may lead to an issuer login, and this tab
      // asked for it, so it is the one allowed to follow.
      if (isVCI) authorizeClaim.expect();
      // This tab pasted the request, so it reviews it: claim the consent so the
      // dialog opens here (on a shared demo it would otherwise show only the
      // banner) rather than auto-accepting.
      consentClaim.expect();
      // Whatever goes wrong with this submission is this tab's to report.
      expectError();

      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ uri: uri, interactive: true })
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

  // Issue credential
  const issueBtn = document.getElementById('issue-btn');
  const issueOverlay = document.getElementById('issue-overlay');
  const issueForm = document.getElementById('issue-form');
  const issueError = document.getElementById('issue-error');
  const issueSubmit = document.getElementById('issue-submit');
  const issueFormat = document.getElementById('issue-format');
  const issueClaimRows = document.getElementById('issue-claim-rows');
  const issueClaimsTextarea = document.getElementById('issue-claims');
  const issueTemplateSelect = document.getElementById('issue-template');
  const issueAlwaysDisclosed = document.getElementById('issue-always-disclosed');
  let claimRowCounter = 0;
  let templatesCache = null;

  function addClaimRow(ns, key, value, sd) {
    const idx = claimRowCounter++;
    const row = document.createElement('div');
    row.className = 'claim-row';
    row.id = 'issue-claim-row-' + idx;
    row.innerHTML =
      '<input type="text" class="form-input claim-ns" id="issue-claim-ns-' + idx + '" placeholder="namespace (default: doc type)">' +
      '<input type="text" class="form-input" id="issue-claim-key-' + idx + '" placeholder="claim name">' +
      '<input type="text" class="form-input" id="issue-claim-value-' + idx + '" placeholder="value (text or JSON)">' +
      '<label class="claim-sd" title="Selectively disclosable (uncheck to embed the claim plainly in the payload)"><input type="checkbox" id="issue-claim-sd-' + idx + '" checked> SD</label>' +
      '<button type="button" class="btn btn-sm" id="issue-claim-remove-' + idx + '" title="Remove claim">&times;</button>';
    row.querySelector('input[id^="issue-claim-ns-"]').value = ns || '';
    row.querySelector('input[id^="issue-claim-key-"]').value = key || '';
    row.querySelector('input[id^="issue-claim-value-"]').value = value || '';
    row.querySelector('input[id^="issue-claim-sd-"]').checked = sd !== false;
    row.querySelector('input[id^="issue-claim-sd-"]').addEventListener('change', syncAlwaysDisclosedFromRows);
    row.querySelector('button').addEventListener('click', () => row.remove());
    issueClaimRows.appendChild(row);
  }

  function alwaysDisclosedList() {
    return issueAlwaysDisclosed.value.split(',').map(s => s.trim()).filter(Boolean);
  }

  // The "Always visible" input is the source of truth for always-disclosed
  // claims. The per-row SD checkboxes are a convenience view over its
  // top-level entries; dotted paths (nested claims) only live in the input.
  function syncAlwaysDisclosedFromRows() {
    const nested = alwaysDisclosedList().filter(p => p.indexOf('.') !== -1);
    const plain = [];
    issueClaimRows.querySelectorAll('.claim-row').forEach(row => {
      const key = row.querySelector('input[id^="issue-claim-key-"]').value.trim();
      const sd = row.querySelector('input[id^="issue-claim-sd-"]').checked;
      if (key && !sd) plain.push(key);
    });
    issueAlwaysDisclosed.value = plain.concat(nested).join(', ');
  }

  function syncRowsFromAlwaysDisclosed() {
    const list = alwaysDisclosedList();
    issueClaimRows.querySelectorAll('.claim-row').forEach(row => {
      const key = row.querySelector('input[id^="issue-claim-key-"]').value.trim();
      row.querySelector('input[id^="issue-claim-sd-"]').checked = list.indexOf(key) === -1;
    });
  }

  // Builder claims use "namespace:element" keys for mdoc rows that set a
  // namespace, matching the server-side claim key convention.
  function builderClaims() {
    const claims = {};
    issueClaimRows.querySelectorAll('.claim-row').forEach(row => {
      let key = row.querySelector('input[id^="issue-claim-key-"]').value.trim();
      if (!key) return;
      const ns = row.querySelector('input[id^="issue-claim-ns-"]').value.trim();
      if (ns && issueFormat.value === 'mdoc') key = ns + ':' + key;
      const rawVal = row.querySelector('input[id^="issue-claim-value-"]').value;
      let val = rawVal;
      try { val = JSON.parse(rawVal); } catch (e) { /* keep as string */ }
      claims[key] = val;
    });
    return claims;
  }

  function fillClaimRows(claims) {
    issueClaimRows.textContent = '';
    claimRowCounter = 0;
    Object.keys(claims || {}).forEach(key => {
      const val = claims[key];
      let ns = '';
      let name = key;
      if (issueFormat.value === 'mdoc') {
        const sep = key.indexOf(':');
        if (sep > 0) {
          ns = key.slice(0, sep);
          name = key.slice(sep + 1);
        }
      }
      addClaimRow(ns, name, typeof val === 'string' ? val : JSON.stringify(val));
    });
    if (claimRowCounter === 0) addClaimRow('', '', '');
  }

  function updateIssueFormatFields() {
    const fmt = issueFormat.value;
    issueForm.querySelectorAll('[data-formats]').forEach(el => {
      el.hidden = el.dataset.formats.split(' ').indexOf(fmt) === -1;
    });
    issueClaimRows.classList.toggle('show-ns', fmt === 'mdoc');
    issueClaimRows.classList.toggle('show-sd', fmt === 'sdjwt');
    updateAlwaysDisclosedVisibility();
  }

  // The per-row SD checkboxes and the "Always visible" input hold the same
  // list, so only one is shown at a time: checkboxes in builder mode, the
  // input (which also accepts dotted paths for nested claims) in JSON mode.
  function updateAlwaysDisclosedVisibility() {
    const show = issueFormat.value === 'sdjwt' &&
      document.getElementById('issue-claims-mode-json').checked;
    issueAlwaysDisclosed.hidden = !show;
    issueForm.querySelector('label[for="issue-always-disclosed"]').hidden = !show;
  }

  async function loadTemplates(force) {
    if (templatesCache && !force) return templatesCache;
    const resp = await fetch('/api/templates');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    templatesCache = await resp.json();
    return templatesCache;
  }

  async function fillIssueTemplateSelect() {
    let templates = [];
    try {
      templates = await loadTemplates(true);
    } catch (e) {
      return; // the dropdown just stays empty
    }
    const current = issueTemplateSelect.value;
    issueTemplateSelect.textContent = '';
    const none = document.createElement('option');
    none.value = '';
    none.textContent = '(none)';
    issueTemplateSelect.appendChild(none);
    templates.forEach(t => {
      const opt = document.createElement('option');
      opt.value = t.name;
      opt.textContent = t.name + (t.predefined ? ' (pre-defined)' : '');
      issueTemplateSelect.appendChild(opt);
    });
    issueTemplateSelect.value = current || '';
  }

  // Applies a template to the issue form: format, type identifiers, expiry,
  // claims, and always-disclosed claims. Everything stays editable; the form
  // contents are submitted as explicit values, so edits (including removed
  // claims) win over the template. Every template-controlled field is set
  // unconditionally (cleared when the template omits it), because otherwise
  // switching templates before issuing would submit a merge of all
  // previously selected templates.
  function applyIssueTemplate(name) {
    const tpl = (templatesCache || []).find(t => t.name === name);
    if (!tpl) return;
    if (tpl.format) issueFormat.value = tpl.format;
    updateIssueFormatFields();
    document.getElementById('issue-vct').value = tpl.vct || '';
    document.getElementById('issue-doctype').value = tpl.doctype || '';
    document.getElementById('issue-exp').value = tpl.exp || '';
    document.getElementById('issue-nbf').value = '';
    issueAlwaysDisclosed.value = (tpl.always_disclosed || []).join(', ');
    fillClaimRows(tpl.claims || {});
    syncRowsFromAlwaysDisclosed();
    issueClaimsTextarea.value = JSON.stringify(tpl.claims || {}, null, 2);
  }

  // Keeps both claim editors in sync: entering JSON mode serializes the
  // builder rows, entering builder mode re-parses the JSON into rows.
  function updateClaimsMode() {
    const jsonRadio = document.getElementById('issue-claims-mode-json');
    const jsonMode = jsonRadio.checked;
    if (jsonMode) {
      syncAlwaysDisclosedFromRows();
      issueClaimsTextarea.value = JSON.stringify(builderClaims(), null, 2);
    } else {
      const text = issueClaimsTextarea.value.trim();
      if (text) {
        try {
          const parsed = JSON.parse(text);
          if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
            throw new Error('expected a JSON object');
          }
          fillClaimRows(parsed);
          syncRowsFromAlwaysDisclosed();
          issueError.textContent = '';
        } catch (e) {
          issueError.textContent = 'Claims must be valid JSON: ' + e.message;
          jsonRadio.checked = true;
          return;
        }
      }
    }
    issueClaimRows.hidden = jsonMode;
    document.getElementById('issue-add-claim').hidden = jsonMode;
    issueClaimsTextarea.hidden = !jsonMode;
    updateAlwaysDisclosedVisibility();
  }

  // Clears everything except the selected format. Also used when the format
  // changes, because values do not translate between formats.
  function resetIssueFields() {
    document.getElementById('issue-vct').value = '';
    document.getElementById('issue-doctype').value = '';
    document.getElementById('issue-exp').value = '';
    document.getElementById('issue-nbf').value = '';
    document.getElementById('issue-save-template').value = '';
    document.getElementById('issue-status-list').value = 'auto';
    document.getElementById('issue-status-list-uri').value = '';
    document.getElementById('issue-status-list-uri').hidden = true;
    document.getElementById('issue-status-list-idx').value = '';
    document.getElementById('issue-status-list-idx').hidden = true;
    issueTemplateSelect.value = '';
    issueAlwaysDisclosed.value = '';
    document.getElementById('issue-claims-mode-builder').checked = true;
    issueClaimsTextarea.value = '';
    issueError.textContent = '';
    updateIssueFormatFields();
    fillClaimRows({});
    updateClaimsMode();
  }

  // The wallet only has an own status list when a base or issuer URL is
  // configured. Reflect the real state in the option instead of guessing.
  async function updateStatusListOption() {
    const autoOption = document.getElementById('issue-status-list-auto');
    try {
      const resp = await fetch('/api/config');
      const config = await resp.json();
      const configured = Boolean(config.status_list_url);
      autoOption.disabled = !configured;
      autoOption.textContent = configured ? 'Wallet status list' : 'Wallet status list (not configured)';
      if (!configured && document.getElementById('issue-status-list').value === 'auto') {
        document.getElementById('issue-status-list').value = 'none';
      }
    } catch (e) {
      /* keep the default option state */
    }
  }

  issueBtn.addEventListener('click', () => {
    issueForm.reset();
    resetIssueFields();
    issueOverlay.classList.add('active');
    fillIssueTemplateSelect();
    updateStatusListOption();
  });

  issueFormat.addEventListener('change', resetIssueFields);

  issueTemplateSelect.addEventListener('change', () => {
    if (issueTemplateSelect.value) {
      applyIssueTemplate(issueTemplateSelect.value);
    } else {
      // "(none)": back to a clean form instead of the last template's values.
      const format = issueFormat.value;
      issueForm.reset();
      issueFormat.value = format;
      resetIssueFields();
    }
  });

  issueAlwaysDisclosed.addEventListener('change', syncRowsFromAlwaysDisclosed);

  document.getElementById('issue-status-list').addEventListener('change', () => {
    const custom = document.getElementById('issue-status-list').value === 'custom';
    document.getElementById('issue-status-list-uri').hidden = !custom;
    document.getElementById('issue-status-list-idx').hidden = !custom;
  });

  document.getElementById('issue-add-claim').addEventListener('click', () => addClaimRow('', ''));

  document.getElementById('issue-claims-mode-builder').addEventListener('change', updateClaimsMode);
  document.getElementById('issue-claims-mode-json').addEventListener('change', updateClaimsMode);

  document.getElementById('issue-cancel').addEventListener('click', () => {
    issueOverlay.classList.remove('active');
  });

  issueForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    issueError.textContent = '';

    const body = { format: issueFormat.value };
    if (document.getElementById('issue-claims-mode-json').checked) {
      const claimsText = issueClaimsTextarea.value.trim();
      if (claimsText) {
        try {
          body.claims = JSON.parse(claimsText);
        } catch (e) {
          issueError.textContent = 'Claims must be valid JSON: ' + e.message;
          return;
        }
      }
    } else {
      syncAlwaysDisclosedFromRows();
      const claims = builderClaims();
      if (Object.keys(claims).length > 0) body.claims = claims;
    }
    const vct = document.getElementById('issue-vct').value.trim();
    if (vct) body.vct = vct;
    const doctype = document.getElementById('issue-doctype').value.trim();
    if (doctype) body.doctype = doctype;
    const exp = document.getElementById('issue-exp').value.trim();
    if (exp) body.exp = exp;
    const nbf = document.getElementById('issue-nbf').value.trim();
    if (nbf) body.nbf = nbf;
    const statusListMode = document.getElementById('issue-status-list').value;
    if (statusListMode === 'none') {
      body.status_list_uri = '';
    } else if (statusListMode === 'custom') {
      body.status_list_uri = document.getElementById('issue-status-list-uri').value.trim();
      const idx = document.getElementById('issue-status-list-idx').value.trim();
      if (idx) body.status_list_idx = parseInt(idx, 10);
    }
    if (issueFormat.value === 'sdjwt') {
      const always = alwaysDisclosedList();
      if (always.length > 0) body.always_disclosed = always;
    }
    const saveTemplate = document.getElementById('issue-save-template').value.trim();
    if (saveTemplate) body.save_as_template = saveTemplate;

    issueSubmit.disabled = true;
    issueSubmit.textContent = 'Issuing...';
    try {
      const resp = await fetch('/api/issue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const result = await resp.json();
      if (!resp.ok) {
        issueError.textContent = result.error || ('HTTP ' + resp.status);
        return;
      }
      issueOverlay.classList.remove('active');
      if (body.save_as_template) templatesCache = null;
      await loadCredentials();
      await loadLog();
    } catch (e) {
      issueError.textContent = 'Request failed: ' + e.message;
    } finally {
      issueSubmit.disabled = false;
      issueSubmit.textContent = 'Issue';
    }
  });

  // Templates manager
  const templatesOverlay = document.getElementById('templates-overlay');
  const templatesList = document.getElementById('templates-list');
  const templateForm = document.getElementById('template-form');
  const templateError = document.getElementById('template-error');
  const templateName = document.getElementById('template-name');
  const templateJSON = document.getElementById('template-json');

  function templateEditorFields(tpl) {
    // The name lives in its own input and predefined is server managed.
    const doc = Object.assign({}, tpl);
    delete doc.name;
    delete doc.predefined;
    return doc;
  }

  async function renderTemplatesList() {
    let templates = [];
    try {
      templates = await loadTemplates(true);
    } catch (e) {
      templateError.textContent = 'Failed to load templates: ' + e.message;
      return;
    }
    templatesList.textContent = '';
    templates.forEach(tpl => {
      const row = document.createElement('div');
      row.className = 'template-row';
      row.id = 'template-row-' + tpl.name;
      row.dataset.templateName = tpl.name;
      row.dataset.predefined = tpl.predefined ? 'true' : 'false';

      const label = document.createElement('span');
      label.className = 'template-row-name';
      label.textContent = tpl.name;
      row.appendChild(label);

      const meta = document.createElement('span');
      meta.className = 'template-row-meta';
      meta.textContent = (tpl.format || 'any') + (tpl.predefined ? ' · pre-defined' : '');
      row.appendChild(meta);

      const editBtn = document.createElement('button');
      editBtn.type = 'button';
      editBtn.className = 'btn btn-sm';
      editBtn.id = 'template-edit-' + tpl.name;
      editBtn.textContent = 'Edit';
      editBtn.addEventListener('click', () => {
        templateName.value = tpl.name;
        templateJSON.value = JSON.stringify(templateEditorFields(tpl), null, 2);
        templateError.textContent = '';
      });
      row.appendChild(editBtn);

      if (!tpl.predefined && !demoMode) {
        const deleteBtn = document.createElement('button');
        deleteBtn.type = 'button';
        deleteBtn.className = 'btn btn-sm';
        deleteBtn.id = 'template-delete-' + tpl.name;
        deleteBtn.textContent = 'Delete';
        deleteBtn.addEventListener('click', async () => {
          templateError.textContent = '';
          try {
            const resp = await fetch('/api/templates/' + encodeURIComponent(tpl.name), { method: 'DELETE' });
            if (!resp.ok) {
              const result = await resp.json();
              templateError.textContent = result.error || ('HTTP ' + resp.status);
              return;
            }
            await renderTemplatesList();
          } catch (e) {
            templateError.textContent = 'Request failed: ' + e.message;
          }
        });
        row.appendChild(deleteBtn);
      }

      templatesList.appendChild(row);
    });
  }

  document.getElementById('templates-btn').addEventListener('click', () => {
    templateName.value = '';
    templateJSON.value = '';
    templateError.textContent = '';
    templatesOverlay.classList.add('active');
    renderTemplatesList();
  });

  document.getElementById('template-close').addEventListener('click', () => {
    templatesOverlay.classList.remove('active');
  });

  templateForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    templateError.textContent = '';
    let doc;
    try {
      doc = JSON.parse(templateJSON.value);
      if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
        throw new Error('expected a JSON object');
      }
    } catch (e) {
      templateError.textContent = 'Template must be valid JSON: ' + e.message;
      return;
    }
    // A pasted template may carry its own name; the name input wins.
    const name = templateName.value.trim() || (typeof doc.name === 'string' ? doc.name.trim() : '');
    if (!name) {
      templateError.textContent = 'Template name is required';
      return;
    }
    try {
      const resp = await fetch('/api/templates/' + encodeURIComponent(name), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(doc)
      });
      const result = await resp.json();
      if (!resp.ok) {
        templateError.textContent = result.error || ('HTTP ' + resp.status);
        return;
      }
      templateName.value = '';
      templateJSON.value = '';
      await renderTemplatesList();
    } catch (e) {
      templateError.textContent = 'Request failed: ' + e.message;
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

  document.getElementById('clear-log-btn').addEventListener('click', async () => {
    try {
      await fetch('/api/log', { method: 'DELETE' });
      await loadLog();
    } catch (e) {
      console.error('Failed to clear log:', e);
    }
  });

  function renderLog(log) {
    logContainer.querySelectorAll('.log-entry').forEach(el => el.remove());
    if (!log || log.length === 0) {
      logEmpty.style.display = '';
      return;
    }
    logEmpty.style.display = 'none';

    log.slice().reverse().forEach(entry => {
      const el = document.createElement('div');
      const hasDetails = entry.details && Object.keys(entry.details).length > 0;
      el.className = 'log-entry' + (hasDetails ? ' has-details' : '');
      const time = new Date(entry.time).toLocaleTimeString();
      // Three states: a spec violation the wallet noted but did not fail on is
      // a warning, distinct from a plain OK or a hard FAIL.
      const warning = entry.severity === 'warning';
      const statusClass = warning ? 'warning' : (entry.success ? 'success' : 'failure');
      const statusLabel = warning ? '⚠ WARN' : (entry.success ? 'OK' : 'FAIL');
      let html = '<div class="log-header">' +
        '<span class="log-chevron">' + (hasDetails ? '▸' : '') + '</span>' +
        '<span class="log-time">' + time + '</span>' +
        '<span class="log-action ' + entry.action + '">' + escHtml(entry.action) + '</span>' +
        '<span class="log-detail" title="' + escHtml(entry.detail) + '">' + escHtml(entry.detail) + '</span>' +
        '<span class="log-status ' + statusClass + '">' + statusLabel + '</span>' +
        '</div>';
      if (hasDetails) {
        html += '<div class="log-details">' + renderLogDetails(entry.details) + '</div>';
      }
      el.innerHTML = html;
      if (hasDetails) {
        el.querySelector('.log-header').addEventListener('click', () => el.classList.toggle('expanded'));
      }
      logContainer.appendChild(el);
    });
  }

  const logKeyOrder = ['event', 'direction', 'source', 'method', 'url', 'status_code',
    'client_id', 'response_type', 'response_mode', 'response_uri', 'redirect_uri',
    'submission_uri', 'state', 'nonce'];

  function renderLogDetails(details) {
    const isObj = v => typeof v === 'object' && v !== null;
    const keys = Object.keys(details).sort((a, b) => {
      if (isObj(details[a]) !== isObj(details[b])) return isObj(details[a]) ? 1 : -1;
      const ia = logKeyOrder.indexOf(a), ib = logKeyOrder.indexOf(b);
      if (ia !== -1 || ib !== -1) return (ia === -1 ? logKeyOrder.length : ia) - (ib === -1 ? logKeyOrder.length : ib);
      return a.localeCompare(b);
    });
    let html = '<div class="log-fields">';
    for (const key of keys) {
      const val = details[key];
      html += '<span class="log-key">' + escHtml(key) + '</span>';
      if (isObj(val)) {
        html += '<span class="log-value"><pre>' + escHtml(JSON.stringify(val, null, 2)) + '</pre></span>';
      } else {
        html += '<span class="log-value">' + escHtml(String(val)) + '</span>';
      }
    }
    html += '</div>';
    return html;
  }

  // Show or hide the indicator for requests this browser did not start.
  function updatePendingBanner(requests) {
    const banner = document.getElementById('pending-banner');
    const count = (requests || []).length;
    if (count === 0 || consentOverlay.classList.contains('active')) {
      banner.hidden = true;
      return;
    }
    document.getElementById('pending-text').textContent = count === 1
      ? '1 request is waiting for consent.'
      : count + ' requests are waiting for consent.';
    banner.hidden = false;
  }

  async function refreshPendingBanner() {
    try {
      const resp = await fetch('/api/requests');
      updatePendingBanner(await resp.json());
    } catch (e) {
      /* leave the banner as it is */
    }
  }

  document.getElementById('pending-review').addEventListener('click', async () => {
    try {
      const resp = await fetch('/api/requests');
      const requests = await resp.json();
      if (requests && requests.length > 0) {
        showConsentDialog(requests[0]);
        document.getElementById('pending-banner').hidden = true;
        return;
      }
      updatePendingBanner(requests);
    } catch (e) {
      console.error('Failed to load pending requests:', e);
    }
  });

  // Load any existing pending consent requests
  async function loadPendingRequests() {
    try {
      const resp = await fetch('/api/requests');
      const requests = await resp.json();
      if (requests && requests.length > 0) {
        // Prefer the request this browser was redirected here for. On a
        // shared demo instance, never auto-open other visitors' requests.
        const wanted = new URLSearchParams(window.location.search).get('request');
        const own = requests.find((r) => r.id === wanted);
        if (own) {
          showConsentDialog(own);
          return;
        }
        // The request may already have been created while this page loaded.
        // A tab the scheme handler opened still owns it and opens it directly,
        // whether or not config has told us this is a demo yet.
        if (consentClaim.take()) {
          showConsentDialog(requests[0]);
          return;
        }
        // Config known and this is a local wallet: every flow is this user's.
        if (configLoaded && !demoMode) {
          showConsentDialog(requests[0]);
          return;
        }
        // Demo, or config not yet known: offer it in the banner rather than
        // forcing a dialog for a tab that had nothing to do with the request.
        updatePendingBanner(requests);
        return;
      }
    } catch (e) {
      console.error('Failed to load pending requests:', e);
    }

    // No pending consent request, so check for a recent error.
    try {
      const resp = await fetch('/api/error');
      presentError(await resp.json());
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
        // Shared demo: consent dialogs belong to the browser that started
        // the flow (it arrives via redirect, or opened this tab itself for a
        // scheme dispatch), not to every open tab. Other tabs get the
        // unobtrusive banner instead. Until config has loaded we treat the tab
        // as a demo visitor, so a stranger's request never flashes a dialog
        // before we know this is a demo; a local wallet re-opens it once
        // config settles.
        if ((!configLoaded || demoMode) && !consentClaim.take()) {
          refreshPendingBanner();
          return;
        }
        showConsentDialog(req);
      } catch (e) {
        console.error('SSE parse error:', e);
      }
    });
    let stateRefresh = null;
    es.addEventListener('state', () => {
      // Coalesce bursts (an issuance saves several times) into one refresh.
      clearTimeout(stateRefresh);
      stateRefresh = setTimeout(() => {
        loadCredentials();
        loadDeferred();
        loadLog();
        if (demoMode) refreshPendingBanner();
      }, 300);
    });
    // An issuance in progress needs the user to sign in at the issuer. The
    // wallet cannot do that for them, so this tab goes there; the issuer
    // redirects back to /callback, which resumes the flow and returns here.
    es.addEventListener('authorize', (event) => {
      try {
        const { url } = JSON.parse(event.data);
        if (!authorizeClaim.take()) return;
        if (navigable(url)) window.location.href = url;
      } catch (e) {
        console.error('SSE authorize parse error:', e);
      }
    });
    es.addEventListener('error', (event) => {
      try {
        presentError(JSON.parse(event.data));
      } catch (e) {
        console.error('SSE error parse error:', e);
      }
    });
    es.onerror = () => {
      es.close();
      setTimeout(connectSSE, 3000);
    };
  }

  // presentError is the one way a wallet error reaches the user, whether it
  // arrived on the stream or was found stored on load. The claim lives here so
  // both routes cannot disagree about who the error belongs to.
  // Claiming the next error also drops one still stored from before: a claim
  // says the next failure is this tab's, and an older one is not it. Without
  // this a later action inherits an error it had nothing to do with.
  function expectError() {
    errorClaim.expect();
    dropStoredError();
  }

  // The stored error survives a GET (the endpoint peeks rather than pops), so
  // anything that has decided not to show one has to drop it, or it surfaces
  // again later against whatever request happens to be on screen then.
  function dropStoredError() {
    fetch('/api/error', { method: 'DELETE' }).catch(() => {});
  }

  // Whether a consent request currently owns the dialog. An error belonging to
  // an earlier request must not take that dialog over, and must not be left
  // stored to reappear once this one closes.
  let consentRequestOpen = false;

  function presentError(err) {
    if (!err || !err.message) return;
    if (consentRequestOpen) {
      // A request the user is being asked about is on screen. This error is
      // not from it: the flow it belongs to ended before this one began.
      dropStoredError();
      return;
    }
    if (!errorClaim.take()) return;
    showErrorDialog(err.message, err.detail);
  }

  function showErrorDialog(message, detail) {
    consentRequestOpen = false;
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
      consentRequestOpen = false;
      consentOverlay.classList.remove('active');
      fetch('/api/error', { method: 'DELETE' }).catch(() => {});
      loadLog();
    });
  }

  // Whether a URL handed to us by an issuer or verifier may be navigated to.
  // javascript: and data: URLs would execute in the wallet's own origin, so a
  // verifier answering a presentation with {"redirect_uri":"javascript:..."}
  // must not be followed. The server refuses them too; this is the second
  // lock on the same door.
  function navigable(url) {
    try {
      const scheme = new URL(url, window.location.href).protocol;
      return scheme === 'http:' || scheme === 'https:';
    } catch (e) {
      return false;
    }
  }

  function showSubmissionResult(result) {
    // Only redirect on success, never on error
    if (result.redirect_uri && !result.error) {
      if (navigable(result.redirect_uri)) {
        window.location.href = result.redirect_uri;
        return;
      }
      console.error('refusing to navigate to', result.redirect_uri);
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
      consentRequestOpen = false;
      consentOverlay.classList.remove('active');
      loadLog();
    });
  }


  // What an issuer is offering. Everything except the offer itself comes from
  // the issuer's metadata, which is optional, so each part is rendered only
  // when it is actually known rather than as an empty row.
  function renderOfferDetails(req) {
    const details = req.offer_details || {};
    let html = '';

    const facts = [];
    if (details.grant) facts.push(['Flow', details.grant]);
    if (facts.length > 0) {
      html += '<div class="offer-facts" id="offer-facts">' + facts.map(([k, v]) =>
        '<div><span class="offer-fact-name">' + escHtml(k) + '</span>' +
        '<span class="offer-fact-value">' + escHtml(v) + '</span></div>'
      ).join('') + '</div>';
    }

    // An offer that requires a transaction code cannot be approved without
    // one. The issuer delivers it out of band, so ask for it here.
    if (details.tx_code) {
      const numeric = details.tx_code_input_mode !== 'text';
      html += '<div class="offer-tx-code">' +
        '<label for="offer-tx-code-input">Transaction code</label>' +
        '<input type="text" id="offer-tx-code-input" autocomplete="one-time-code"' +
        (numeric ? ' inputmode="numeric" pattern="[0-9]*"' : '') +
        (details.tx_code_length ? ' maxlength="' + escHtml(details.tx_code_length) + '"' : '') +
        ' placeholder="' + escHtml(details.tx_code_hint || 'code from the issuer') + '">' +
        (details.tx_code_description
          ? '<p class="dialog-hint" id="offer-tx-code-description">' + escHtml(details.tx_code_description) + '</p>'
          : '') +
      '</div>';
    }

    // The offer could not be fetched, so only its origin is known.
    if (details.resolve_error) {
      html += '<p class="dialog-hint" id="offer-resolve-error">This offer could not be retrieved, ' +
        'so only the issuer it names is shown. Approving will try again.</p>';
      return html;
    }

    const credentials = details.credentials || [];
    if (credentials.length === 0) {
      (req.offer_configs || []).forEach(cfg => {
        html += '<div class="consent-credential"><div class="consent-credential-header">' +
          '<span style="font-size:12px;font-weight:600;">' + escHtml(cfg) + '</span>' +
          '</div></div>';
      });
      return html;
    }

    credentials.forEach(cred => {
      const formatClass = cred.format === 'dc+sd-jwt' ? 'format-sdjwt'
        : cred.format === 'jwt_vc_json' ? 'format-jwt' : 'format-mdoc';
      const formatLabel = cred.format === 'dc+sd-jwt' ? 'SD-JWT'
        : cred.format === 'jwt_vc_json' ? 'JWT VC'
        : cred.format === 'mso_mdoc' ? 'mDoc' : '';
      const typeLabel = cred.vct || cred.doctype || cred.id;

      html += '<div class="consent-credential" data-config-id="' + escHtml(cred.id) + '">' +
        '<div class="consent-credential-header">' +
        (formatLabel ? '<span class="format-badge ' + formatClass + '">' + formatLabel + '</span>' : '') +
        '<span style="font-size:12px;font-weight:600;">' + escHtml(cred.name || typeLabel) + '</span>' +
        '</div>';
      if (cred.name && typeLabel !== cred.name) {
        html += '<div class="offer-type">' + escHtml(typeLabel) + '</div>';
      }
      if (cred.description) {
        html += '<div class="offer-description">' + escHtml(cred.description) + '</div>';
      }
      if (cred.claims && cred.claims.length > 0) {
        html += '<div class="consent-claims">' + cred.claims.map(claim =>
          '<div class="consent-claim"><span class="consent-claim-name">' + escHtml(claim) + '</span></div>'
        ).join('') + '</div>';
      }
      html += '</div>';
    });

    if (details.metadata_error) {
      html += '<p class="dialog-hint" id="offer-metadata-error">The issuer published no readable metadata, ' +
        'so only what the offer itself carries is shown.</p>';
    }
    return html;
  }

  function showConsentDialog(req) {
    consentRequestOpen = true;
    dropStoredError();
    consentOverlay.classList.add('active');

    const isIssuance = req.type === 'issuance';
    const issuerName = isIssuance && req.offer_details ? req.offer_details.issuer_name : '';
    let html = '<div class="consent-title">' + (isIssuance ? 'Credential Offer' : 'Presentation Request') + '</div>' +
      '<div class="consent-verifier">' + (isIssuance ? 'Issuer: ' : 'Verifier: ') +
      escHtml(issuerName || req.client_id) + '</div>' +
      (issuerName ? '<div class="offer-type" id="offer-issuer-origin">' + escHtml(req.client_id) + '</div>' : '');

    if (isIssuance) {
      html += renderOfferDetails(req);
    }

    if (!isIssuance && req.matched_credentials && req.matched_credentials.length > 0) {
      req.matched_credentials.forEach((mc, idx) => {
        const formatClass = mc.format === 'dc+sd-jwt' ? 'format-sdjwt' : mc.format === 'jwt_vc_json' ? 'format-jwt' : 'format-mdoc';
        const formatLabel = mc.format === 'dc+sd-jwt' ? 'SD-JWT' : mc.format === 'jwt_vc_json' ? 'JWT VC' : 'mDoc';
        const typeLabel = mc.vct || mc.doctype || mc.format;

        html += '<div class="consent-credential" id="consent-credential-' + mc.credential_id + '" data-credential-id="' + mc.credential_id + '" data-vct="' + escHtml(mc.vct || '') + '" data-doctype="' + escHtml(mc.doctype || '') + '">' +
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
      // Checked here so an empty code fails in the dialog, rather than as an
      // issuer error after the offer is spent.
      const txCodeField = document.getElementById('offer-tx-code-input');
      if (txCodeField && !txCodeField.value.trim()) {
        txCodeField.classList.add('input-error');
        txCodeField.focus();
        return;
      }
      if (txCodeField) txCodeField.classList.remove('input-error');

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
      // Approving an issuance is what may lead to an issuer login, so this
      // tab is the one allowed to follow it.
      if (isIssuance) authorizeClaim.expect();
      expectError();
      denyBtn.disabled = true;

      try {
        const txCodeInput = document.getElementById('offer-tx-code-input');
        const approveBody = isIssuance
          ? (txCodeInput ? { tx_code: txCodeInput.value.trim() } : {})
          : { selected_claims: selected };
        const resp = await fetch('/api/requests/' + req.id + '/approve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(approveBody)
        });
        const result = await resp.json();
        if (isIssuance) {
          // Deferred, not failed: the wallet keeps collecting it and the
          // credential appears once it arrives.
          if (result.pending) {
            consentRequestOpen = false;
            consentOverlay.classList.remove('active');
            await loadDeferred();
            await loadLog();
            return;
          }
          if (!resp.ok || result.error || (result.status_code && result.status_code >= 400)) {
            const detail = result.error || ('HTTP ' + (result.status_code || resp.status));
            showErrorDialog('Credential issuance failed', detail);
            return;
          }
          consentRequestOpen = false;
          consentOverlay.classList.remove('active');
          if (demoMode) refreshPendingBanner();
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
      consentRequestOpen = false;
      consentOverlay.classList.remove('active');
      await loadLog();
    });
  }

  // Escapes for both element content and quoted attribute values. The
  // textContent/innerHTML trick this used to do leaves " and ' untouched, so
  // any value interpolated into an attribute (a status list URI, a vct, a
  // claim name, a credential configuration id) could close the attribute and
  // add an event handler. On a shared wallet those values come from whoever
  // imported the credential or sent the offer, so they run in every other
  // visitor's browser.
  function escHtml(s) {
    return String(s === undefined || s === null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Footer: version, imprint link, demo note; demo mode also hides the
  // Templates button and template-write controls (the server rejects
  // writes with 403 anyway).
  let demoMode = false;
  // Until /api/config resolves we do not know whether this is a demo, so the
  // dialog-vs-banner decision waits for it: a request arriving in that window
  // is never forced into a dialog it might not belong to.
  let configLoaded = false;
  async function loadAppConfig() {
    try {
      const resp = await fetch('/api/config');
      const config = await resp.json();
      if (config.version) {
        document.getElementById('footer-version').textContent = 'eudi-dev ' + config.version;
      }
      if (config.imprint) {
        document.getElementById('imprint-link').hidden = false;
      }
      if (config.tls_listener === false) {
        // No built-in HTTPS listener (external TLS terminator serves the
        // issuer origin): the self-signed TLS leaf is never presented, so
        // offering it for download would only mislead.
        document.getElementById('tls-row-label').hidden = true;
        document.getElementById('tls-row').hidden = true;
      }
      // Determine demo mode before rendering the conformance panel: its note
      // and browser-only warning both branch on it.
      demoMode = !!(config.demo && config.demo.enabled);
      renderConformance(config);
      ['conf-mode-select', 'conf-haip-input', 'conf-encrypted-input'].forEach((id) => {
        const el = document.getElementById(id);
        if (el && !el.dataset.wired) {
          el.dataset.wired = '1';
          el.addEventListener('change', onConformanceChange);
        }
      });
      const confReset = document.getElementById('conf-reset');
      if (confReset && !confReset.dataset.wired) {
        confReset.dataset.wired = '1';
        confReset.addEventListener('click', resetConformance);
      }
      if (config.demo && config.demo.enabled) {
        demoMode = true;
        const note = document.getElementById('demo-note');
        const schedule = describeReset(config.demo);
        note.textContent = schedule
          ? 'Public demo, resets ' + schedule
          : 'Public demo, shared state';
        const bannerReset = document.getElementById('demo-banner-reset');
        bannerReset.textContent = schedule
          ? 'state resets ' + schedule
          : 'state is shared and never reset automatically';
        note.hidden = false;
        document.getElementById('issue-save-template').hidden = true;
        document.querySelector('label[for="issue-save-template"]').hidden = true;
        document.getElementById('template-form').hidden = true;
        document.getElementById('templates-btn').hidden = true;
        // The activity log is shared history on a demo, and the server
        // refuses to clear it. Leaving the button would offer an action that
        // can only fail.
        document.getElementById('clear-log-btn').hidden = true;
        if (!localStorage.getItem('demo-banner-dismissed')) {
          document.getElementById('demo-banner').hidden = false;
        }
        document.getElementById('demo-banner-dismiss').addEventListener('click', () => {
          localStorage.setItem('demo-banner-dismissed', '1');
          document.getElementById('demo-banner').hidden = true;
        });
        document.getElementById('demo-banner-cli-link').addEventListener('click', (event) => {
          event.preventDefault();
          cliOverlay.classList.add('active');
        });
      }
    } catch (e) {
      /* footer extras are optional */
    } finally {
      // demoMode is settled now (or defaulted to false on a failed load, which
      // reads as a local wallet). Re-evaluate any request that arrived while
      // config was still loading, so a local wallet still opens its dialog.
      configLoaded = true;
      loadPendingRequests();
    }
  }

  // "daily at 00:00 CET", "every hour", or null when resets are disabled.
  // Shows what an incoming request has to satisfy. The wording is
  // deliberately about consequences rather than flag names: "enforced" only
  // means something if you can see what it rejects.
  // Conformance is the wallet's own process-level setting, reported by
  // /api/config. Only a locally-hosted wallet can change it (PUT/DELETE
  // /api/config/conformance); the public demo shows it read-only.
  let conformanceDefaults = { validation_mode: 'debug', require_haip: true, require_encrypted_request: false };

  function effectiveConformance() {
    return {
      mode: conformanceDefaults.validation_mode === 'strict' ? 'strict' : 'debug',
      haip: !!conformanceDefaults.require_haip,
      encrypted: !!conformanceDefaults.require_encrypted_request,
    };
  }

  function applyConformanceToControls() {
    const eff = effectiveConformance();
    const mode = document.getElementById('conf-mode-select');
    const haip = document.getElementById('conf-haip-input');
    const enc = document.getElementById('conf-encrypted-input');
    if (mode) { mode.value = eff.mode === 'strict' ? 'strict' : 'debug'; mode.disabled = demoMode; }
    if (haip) { haip.checked = eff.haip; haip.disabled = demoMode; }
    if (enc) { enc.checked = eff.encrypted; enc.disabled = demoMode; }
  }

  function currentControlValues() {
    const mode = document.getElementById('conf-mode-select');
    const haip = document.getElementById('conf-haip-input');
    const enc = document.getElementById('conf-encrypted-input');
    return {
      mode: mode ? mode.value : undefined,
      haip: haip ? haip.checked : undefined,
      encrypted: enc ? enc.checked : undefined,
    };
  }

  async function setServerConformance(values) {
    try {
      const resp = await fetch('/api/config/conformance', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(values),
      });
      if (resp.ok) conformanceDefaults = Object.assign({}, conformanceDefaults, await resp.json());
    } catch (e) { /* leave the controls as the user set them */ }
    applyConformanceToControls();
  }

  function onConformanceChange() {
    if (demoMode) return; // demo controls are read-only
    // Change this wallet's own setting so every flow reaching it honors it.
    setServerConformance(currentControlValues());
  }

  function resetConformance() {
    if (demoMode) return;
    fetch('/api/config/conformance', { method: 'DELETE' })
      .then((r) => (r.ok ? r.json() : null))
      .then((c) => { if (c) conformanceDefaults = Object.assign({}, conformanceDefaults, c); applyConformanceToControls(); })
      .catch(() => { applyConformanceToControls(); });
  }

  function renderConformance(config) {
    conformanceDefaults = config || conformanceDefaults;
    applyConformanceToControls();
    const set = (id, text, state) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = text;
      el.classList.toggle('conf-on', state === 'on');
      el.classList.toggle('conf-off', state === 'off');
    };
    set('conf-transcript', config.session_transcript || 'oid4vp', 'neutral');
    set('conf-format', config.preferred_format || 'no preference',
      config.preferred_format ? 'neutral' : 'off');
    // The demo's settings are read-only; say so in the intro so the disabled
    // controls make sense, rather than trailing the popup with more text.
    const intro = document.getElementById('conf-intro');
    if (intro) {
      const base = 'How this wallet checks incoming requests. A failed check is a warning in debug mode and rejects the request in strict mode.';
      intro.textContent = demoMode ? base + ' These are fixed on the public demo.' : base;
    }
    const reset = document.getElementById('conf-reset');
    if (reset) reset.hidden = demoMode;
  }

  function describeReset(demo) {
    if (demo.reset_daily_at) return 'daily at ' + demo.reset_daily_at;
    const secs = demo.reset_interval_seconds || 0;
    return secs > 0 ? 'every ' + formatInterval(secs) : null;
  }

  function formatInterval(secs) {
    if (secs % 3600 === 0) {
      const h = secs / 3600;
      return h === 1 ? 'hour' : h + ' hours';
    }
    const m = Math.round(secs / 60);
    return m + ' minutes';
  }

  // Trust list links: what a counterparty needs to trust this wallet, both a
  // verifier checking its self-issued credentials and an issuer checking its
  // wallet and key attestations (same CA anchor in every list). Groups can
  // change with issuance, so this is reloaded whenever credentials change.
  async function loadTrustLists() {
    const row = document.getElementById('trust-list-links');
    try {
      const resp = await fetch('/api/trustlists');
      const doc = await resp.json();
      const lists = (doc && doc.trust_lists) || [];
      row.querySelectorAll('.trust-items').forEach(el => el.remove());
      row.hidden = lists.length === 0;

      // Grouped by what each list anchors, so a reader looking for one kind
      // does not have to read past the other.
      const groups = new Map();
      lists.forEach(entry => {
        const category = entry.category || 'Other';
        if (!groups.has(category)) groups.set(category, []);
        groups.get(category).push(entry);
      });

      // Same shape as the certificates below: a bold label on the left, the
      // entries and their explanation on the right.
      const list = document.createElement('dl');
      list.className = 'trust-items';
      [...groups.keys()].sort().forEach(category => {
        const term = document.createElement('dt');
        term.textContent = category;
        list.appendChild(term);

        const detail = document.createElement('dd');
        groups.get(category)
          .slice()
          .sort((a, b) => (a.id || '').localeCompare(b.id || ''))
          .forEach(entry => {
            const url = entry.advertised_url || entry.url ||
              (entry.path ? window.location.origin + entry.path : '');
            if (!url) return;
            const links = document.createElement('span');
            links.className = 'trust-links';
            const link = document.createElement('a');
            link.href = url;
            link.textContent = entry.id || 'trust list';
            link.title = url;
            links.appendChild(link);
            if (entry.entityName) {
              const name = document.createElement('span');
              name.className = 'trust-list-name';
              name.textContent = entry.entityName;
              links.appendChild(name);
            }
            const copy = document.createElement('button');
            copy.type = 'button';
            copy.className = 'copy-btn';
            copy.textContent = '\u29C9';
            copy.title = 'Copy trust list URL';
            copy.addEventListener('click', async () => {
              try {
                await navigator.clipboard.writeText(url);
                copy.textContent = '\u2713';
                setTimeout(() => { copy.textContent = '\u29C9'; }, 1200);
              } catch (e) { /* clipboard unavailable */ }
            });
            links.appendChild(copy);
            detail.appendChild(links);
            if (entry.description) {
              const desc = document.createElement('span');
              desc.className = 'trust-item-hint';
              desc.textContent = entry.description;
              detail.appendChild(desc);
            }
          });
        list.appendChild(detail);
      });
      row.appendChild(list);
    } catch (e) {
      row.hidden = true;
    }
  }

  const trustOverlay = document.getElementById('trust-overlay');
  document.getElementById('trust-link').addEventListener('click', (event) => {
    event.preventDefault();
    loadTrustLists();
    trustOverlay.classList.add('active');
  });
  document.getElementById('trust-close').addEventListener('click', () => {
    trustOverlay.classList.remove('active');
  });

  // Conformance modal
  const conformanceOverlay = document.getElementById('conformance-overlay');
  document.getElementById('conformance-link').addEventListener('click', (event) => {
    event.preventDefault();
    conformanceOverlay.classList.add('active');
  });
  document.getElementById('conformance-close').addEventListener('click', () => {
    conformanceOverlay.classList.remove('active');
  });

  // Get-the-CLI modal
  const cliOverlay = document.getElementById('cli-overlay');
  document.getElementById('get-cli-link').addEventListener('click', (event) => {
    event.preventDefault();
    cliOverlay.classList.add('active');
  });
  document.getElementById('cli-close').addEventListener('click', () => {
    cliOverlay.classList.remove('active');
  });

  const howtoOverlay = document.getElementById('howto-overlay');
  document.getElementById('how-to-use-link').addEventListener('click', (event) => {
    event.preventDefault();
    document.querySelectorAll('.howto-origin').forEach((el) => {
      el.textContent = window.location.origin;
    });
    howtoOverlay.classList.add('active');
  });
  document.getElementById('howto-close').addEventListener('click', () => {
    howtoOverlay.classList.remove('active');
  });

  // Initialize
  if (new URLSearchParams(window.location.search).get('focus') === 'overview') {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    window.history.replaceState({}, document.title, window.location.pathname);
  }
  const loadAppConfigPromise = loadAppConfig();
  loadCredentials();
  loadDeferred();
  loadLog();
  loadAppConfigPromise.then(loadPendingRequests);
  connectSSE();
})();
