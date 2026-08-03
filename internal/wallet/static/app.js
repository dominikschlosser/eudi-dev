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
      // Issuance can add trust list groups, so keep the links in sync.
      loadTrustLists();
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

      // Stable identity and selection hooks for UI automation
      card.id = 'credential-' + cred.id;
      card.dataset.credentialId = cred.id;
      card.dataset.format = formatLabel === 'SD-JWT' ? 'sdjwt' : formatLabel === 'JWT VC' ? 'jwt' : 'mdoc';
      if (cred.vct) card.dataset.vct = cred.vct;
      if (cred.doctype) card.dataset.doctype = cred.doctype;

      // Status badge: managed entries show live status, foreign status lists
      // get a badge plus an explicit check action.
      const st = cred.status;
      let statusBadge = '';
      let revokeBtn = '';
      if (st && st.managed) {
        const revoked = st.status === 1;
        card.dataset.status = revoked ? 'revoked' : 'active';
        statusBadge = '<span class="status-badge ' + (revoked ? 'status-revoked' : 'status-active') + '" id="status-' + cred.id + '" title="Status list: ' + escHtml(st.uri || '') + ' idx ' + st.idx + '">' + (revoked ? 'Revoked' : 'Active') + '</span>';
        revokeBtn = '<button class="btn btn-sm" id="revoke-' + cred.id + '" data-revoke="' + cred.id + '">' + (revoked ? 'Activate' : 'Revoke') + '</button>';
      } else if (st && st.uri) {
        card.dataset.status = 'external';
        statusBadge = '<span class="status-badge status-external" id="status-' + cred.id + '" title="External status list: ' + escHtml(st.uri) + ' idx ' + st.idx + '">External status</span>';
        revokeBtn = '<button class="btn btn-sm" id="status-check-' + cred.id + '" data-check-status="' + cred.id + '">Check status</button>';
      } else {
        card.dataset.status = 'none';
      }

      card.innerHTML = '<span class="format-badge ' + formatClass + '">' + formatLabel + '</span>' +
        '<div class="credential-info" title="Open in decoder">' +
          '<div class="credential-type">' + escHtml(typeLabel) + statusBadge + '</div>' +
          '<div class="credential-claims">' + claimTags + moreTag + '</div>' +
        '</div>' +
        '<div class="credential-actions">' +
          revokeBtn +
          '<button class="btn btn-sm" id="show-' + cred.id + '" data-show="' + cred.id + '">Show</button>' +
          '<button class="btn btn-danger btn-sm" id="delete-' + cred.id + '" data-delete="' + cred.id + '">Delete</button>' +
        '</div>';

      const openDecoder = () => {
        window.open('/decoder/?credential=' + encodeURIComponent(cred.raw || ''), '_blank');
      };
      card.querySelector('[data-show]').addEventListener('click', openDecoder);
      card.querySelector('.credential-info').addEventListener('click', openDecoder);
      card.querySelector('[data-delete]').addEventListener('click', () => deleteCredential(cred.id));
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
  // unconditionally (cleared when the template omits it) — otherwise
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
      let html = '<div class="log-header">' +
        '<span class="log-chevron">' + (hasDetails ? '▸' : '') + '</span>' +
        '<span class="log-time">' + time + '</span>' +
        '<span class="log-action ' + entry.action + '">' + escHtml(entry.action) + '</span>' +
        '<span class="log-detail">' + escHtml(entry.detail) + '</span>' +
        '<span class="log-status ' + (entry.success ? 'success' : 'failure') + '">' +
          (entry.success ? 'OK' : 'FAIL') + '</span>' +
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

  // Footer: version, imprint link, demo note; demo mode also hides the
  // template-write controls (the server rejects them with 403 anyway).
  let demoMode = false;
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
      if (config.demo && config.demo.enabled) {
        demoMode = true;
        const note = document.getElementById('demo-note');
        const secs = config.demo.reset_interval_seconds || 0;
        note.textContent = secs > 0
          ? 'Public sandbox — resets every ' + formatInterval(secs)
          : 'Public sandbox — shared state';
        note.hidden = false;
        document.getElementById('issue-save-template').hidden = true;
        document.querySelector('label[for="issue-save-template"]').hidden = true;
        document.getElementById('template-form').hidden = true;
      }
    } catch (e) {
      /* footer extras are optional */
    }
  }

  function formatInterval(secs) {
    if (secs % 3600 === 0) {
      const h = secs / 3600;
      return h === 1 ? 'hour' : h + ' hours';
    }
    const m = Math.round(secs / 60);
    return m + ' minutes';
  }

  // Trust list links: what a verifier needs to trust this wallet's
  // self-issued credentials. Groups can change with issuance, so this is
  // reloaded whenever credentials change.
  async function loadTrustLists() {
    const row = document.getElementById('trust-list-links');
    try {
      const resp = await fetch('/api/trustlists');
      const doc = await resp.json();
      const lists = (doc && doc.trust_lists) || [];
      row.querySelectorAll('.trust-list-item').forEach(el => el.remove());
      row.hidden = lists.length === 0;
      lists.forEach(entry => {
        const url = entry.advertised_url || entry.url ||
          (entry.path ? window.location.origin + entry.path : '');
        if (!url) return;
        const item = document.createElement('span');
        item.className = 'trust-list-item';
        const link = document.createElement('a');
        link.href = url;
        link.textContent = entry.id || 'trust list';
        link.title = url;
        item.appendChild(link);
        const copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'copy-btn';
        copy.textContent = '⧉';
        copy.title = 'Copy trust list URL';
        copy.addEventListener('click', async () => {
          try {
            await navigator.clipboard.writeText(url);
            copy.textContent = '✓';
            setTimeout(() => { copy.textContent = '⧉'; }, 1200);
          } catch (e) { /* clipboard unavailable */ }
        });
        item.appendChild(copy);
        row.appendChild(item);
      });
    } catch (e) {
      row.hidden = true;
    }
  }

  // Get-the-CLI modal
  const cliOverlay = document.getElementById('cli-overlay');
  document.getElementById('get-cli-link').addEventListener('click', (event) => {
    event.preventDefault();
    cliOverlay.classList.add('active');
  });
  document.getElementById('cli-close').addEventListener('click', () => {
    cliOverlay.classList.remove('active');
  });

  // Initialize
  if (new URLSearchParams(window.location.search).get('focus') === 'overview') {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    window.history.replaceState({}, document.title, window.location.pathname);
  }
  loadAppConfig();
  loadCredentials();
  loadLog();
  loadPendingRequests();
  connectSSE();
})();
