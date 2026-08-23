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

  const pageParams = new URLSearchParams(window.location.search);
  // A client that submits a flow on this page's behalf (the URL handler, the
  // CLI) names the page in the URL it opens and on the call it makes, so the
  // request it creates reaches this page. Kept for the tab rather than read
  // from the address bar each time, so a reload mid-flow still answers for it
  // and the name does not sit in a URL anyone can copy.
  const actingOwner = readActingOwner();
  // The request this page was opened for, read here because the address bar is
  // cleaned before anything asks what is pending.
  const openedForRequest = pageParams.get('request') || '';

  // Answering names the request this page was opened for, so a browser that
  // keeps no cookie can act on the dialog the wallet redirected it to.
  function approveURL(id, action) {
    const named = id === openedForRequest ? '?request=' + encodeURIComponent(id) : '';
    return '/api/requests/' + id + action + named;
  }

  function readActingOwner() {
    const named = pageParams.get('owner') || '';
    try {
      if (named) sessionStorage.setItem('eudi_owner', named);
      return named || sessionStorage.getItem('eudi_owner') || '';
    } catch (e) {
      return named;
    }
  }

  // Name this client on every call it makes, the way the CLI and the URL
  // handler do. The page is served by the wallet it talks to, so it is never
  // the stale one, but the wallet reads the same header from everybody.
  const CLIENT_NAME = 'eudi-ui';
  const CLIENT_HEADER = 'X-Eudi-Client';
  const OWNER_HEADER = 'X-Eudi-Owner';
  (function nameThisClient() {
    const original = window.fetch;
    window.fetch = function (input, init) {
      const raw = typeof input === 'string' ? input : String((input && (input.url || input.href)) || '');
      // Same-origin absolute URLs and Request objects count too: a call that
      // reaches the wallet's API carries the same name whatever shape it took.
      const url = raw.startsWith(window.location.origin) ? raw.slice(window.location.origin.length) : raw;
      if (!url.startsWith('/api/')) return original(input, init);
      const opts = Object.assign({}, init);
      const headers = new Headers(opts.headers || (typeof input === 'object' ? input.headers : undefined));
      headers.set(CLIENT_HEADER, CLIENT_NAME + '/' + (window.EUDI_VERSION || 'dev'));
      if (actingOwner) headers.set(OWNER_HEADER, actingOwner);
      opts.headers = headers;
      return original(input, opts);
    };
  })();

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
        const display = p.display || {};
        const typeLabel = p.vct || p.doctype || p.credential_configuration_id || p.format || 'Credential';
        const name = display.name || typeLabel;
        const formatLabel = formatLabelFor(p);
        const next = p.next_attempt_at ? new Date(p.next_attempt_at) : null;
        const when = next && !isNaN(next) ? next.toLocaleTimeString() : '';
        // The same card face as a delivered credential, painted by
        // applyCredentialDisplay below, so an awaiting item already shows the
        // art the offer declared instead of a bare badge.
        const logoImg = display.logo_uri
          ? '<img class="credential-logo" src="' + escHtml(display.logo_uri) + '" alt="' + escHtml(display.logo_alt_text || '') + '">'
          : '';
        const faceHtml = '<div class="card-face">' +
            '<span class="format-badge format-badge-face">' + formatLabel + '</span>' +
            logoImg +
            '<div class="face-name">' + escHtml(name) + '</div>' +
          '</div>';
        return '<div class="deferred-item" data-id="' + escHtml(p.id) + '">' +
          faceHtml +
          '<div class="deferred-body">' +
            '<div class="deferred-item-head">' +
              '<span class="format-badge format-badge-row">' + formatLabel + '</span>' +
              '<span class="deferred-name">' + escHtml(name) + '</span>' +
              '<span class="status-badge deferred-awaiting">Awaiting issuance</span>' +
            '</div>' +
            '<div class="deferred-meta deferred-status">' +
              '<span class="deferred-spinner" aria-hidden="true"></span>' +
              'The issuer asked the wallet to check back every ' + escHtml(p.interval || '') +
              (when ? '. Next attempt at ' + escHtml(when) : '') +
              (p.attempts ? ' (' + escHtml(p.attempts) + ' so far)' : '') +
            '</div>' +
            (p.issuer ? '<div class="deferred-meta">' + escHtml(p.issuer) + '</div>' : '') +
            (p.last_error ? '<div class="deferred-meta deferred-error">' + escHtml(p.last_error) + '</div>' : '') +
            '<div class="deferred-actions">' +
              '<button class="btn btn-sm deferred-check" data-id="' + escHtml(p.id) + '">Check now</button>' +
              '<button class="btn btn-sm btn-danger deferred-abandon" data-id="' + escHtml(p.id) + '">Abandon</button>' +
            '</div>' +
          '</div>' +
        '</div>';
      }).join('');

      // Paint each face with the appearance the offer declared, the same call
      // the credential list uses.
      list.querySelectorAll('.deferred-item').forEach(item => {
        const p = pending.find(x => String(x.id) === item.dataset.id);
        if (p) applyCredentialDisplay(item, p.display);
      });

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

  // Whole credentials the consent dialog's Edit view needs for its candidate
  // cards, by credential id. Neither of the things already loaded can stand in
  // for them: a consent request carries only the claims the verifier asked
  // for, and the credential list holds one page. A credential that could not
  // be read is remembered as null, so its card falls back instead of the
  // dialog asking for it again on every render.
  const candidateDetails = new Map();

  async function loadCandidateDetails(ids) {
    const missing = ids.filter(id => !candidateDetails.has(id));
    if (missing.length === 0) return false;
    await Promise.all(missing.map(async id => {
      try {
        const resp = await fetch('/api/credentials/' + encodeURIComponent(id));
        candidateDetails.set(id, resp.ok ? await resp.json() : null);
      } catch (e) {
        console.error('Loading credential ' + id + ' failed:', e);
        candidateDetails.set(id, null);
      }
    }));
    return true;
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

  // relativeTime turns a timestamp into "3 min ago", the form the card leads
  // with, because how long ago answers the question an absolute date only
  // implies. Returns "" for a missing or unparseable value.
  function relativeTime(value) {
    if (!value) return '';
    const then = new Date(value);
    if (isNaN(then.getTime())) return '';
    const secs = Math.floor((Date.now() - then.getTime()) / 1000);
    const mins = Math.floor(secs / 60);
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + ' min ago';
    const hours = Math.floor(mins / 60);
    if (hours < 24) return hours + ' h ago';
    const days = Math.floor(hours / 24);
    if (days < 30) return days + ' d ago';
    const months = Math.floor(days / 30);
    if (months < 12) return months + ' mo ago';
    return Math.floor(months / 12) + ' y ago';
  }

  // shortCredentialId is the first 8 characters of the credential's UUID, a
  // visual handle for telling two same-type instances apart. The API and the
  // CLI key on the full id, so this short form is for reading, not for lookups.
  function shortCredentialId(id) {
    return String(id || '').slice(0, 8);
  }

  // credentialInitials builds a monogram from a display name (first letter of
  // up to three words), for a credential whose face has neither art nor color
  // nor a logo. A credential with no display name gets a generic glyph
  // instead, since the technical type has no meaningful initials.
  function credentialInitials(name) {
    const words = String(name || '').replace(/[()]/g, ' ').split(/\s+/).filter(w => /^[a-z0-9]/i.test(w));
    return words.slice(0, 3).map(w => w[0]).join('').toUpperCase();
  }

  const GENERIC_FACE_GLYPH = '<span class="face-generic"><svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><rect x="3" y="5" width="18" height="14" rx="2.2"/><circle cx="8" cy="11" r="2"/><path d="M13 10h5M13 13h4M6 15.6h6"/></svg></span>';

  // A lock as an inline SVG so it takes the pill's color (the 🔒 emoji keeps its
  // own yellow whatever the text color is).
  const LOCK_SVG = '<svg class="pill-ico" viewBox="0 0 24 24" width="11" height="11" fill="currentColor" aria-hidden="true"><path d="M12 1a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2h-1V6a5 5 0 0 0-5-5zm3 8H9V6a3 3 0 0 1 6 0v3z"/></svg>';

  function formatLabelFor(cred) {
    return cred.format === 'dc+sd-jwt' ? 'SD-JWT' : cred.format === 'jwt_vc_json' ? 'JWT VC' : 'mdoc';
  }

  function credentialCardBody(cred, idPrefix) {
    const formatLabel = formatLabelFor(cred);
    const typeLabel = cred.vct || cred.doctype || cred.format;
    const isProtected = cred.protected === true;

    // Stable identity and selection hooks for UI automation
    const dataset = {
      credentialId: cred.id,
      format: formatLabel === 'SD-JWT' ? 'sdjwt' : formatLabel === 'JWT VC' ? 'jwt' : 'mdoc',
      status: 'none',
    };
    if (isProtected) dataset.protected = 'true';
    if (cred.vct) dataset.vct = cred.vct;
    if (cred.doctype) dataset.doctype = cred.doctype;

    // Protected credentials are the shared baseline: the server refuses to
    // delete or revoke them, so do not offer buttons that would only 403.
    const protectedBadge = isProtected
      ? '<span class="status-badge status-protected" id="' + idPrefix + 'protected-' + cred.id + '"' +
        ' title="Part of this wallet\'s baseline. It cannot be deleted or revoked' +
        ' through the UI or the API, only by editing the wallet file.">' + LOCK_SVG + 'Protected</span>'
      : '';

    // Status badge: managed entries show live status, foreign status lists
    // get a badge of their own, and an entry with no status list says so.
    const st = cred.status;
    let statusBadge;
    if (st && st.managed) {
      const revoked = st.status === 1;
      dataset.status = revoked ? 'revoked' : 'active';
      statusBadge = '<span class="status-badge ' + (revoked ? 'status-revoked ico-block' : 'status-active ico-dot') + '" id="' + idPrefix + 'status-' + cred.id + '" title="' + (revoked ? 'The issuer has revoked this credential on its status list' : 'Not revoked on the issuer\'s status list') + ' (' + escHtml(st.uri || '') + ' idx ' + st.idx + ').">' + (revoked ? 'Revoked' : 'Active') + '</span>';
    } else if (st && st.uri) {
      dataset.status = 'external';
      statusBadge = '<span class="status-badge status-external ico-half" id="' + idPrefix + 'status-' + cred.id + '" title="Revocation is tracked on a status list this wallet does not manage, so its state is not read here (' + escHtml(st.uri) + ' idx ' + st.idx + ').">External list</span>';
    } else {
      statusBadge = '<span class="status-badge status-none ico-circle" id="' + idPrefix + 'status-' + cred.id + '" title="This credential carries no status list, so revocation cannot be checked.">No status</span>';
    }

    // How long the credential is still good for. The wallet renews what it
    // can shortly before this, so a date here is not always a deadline.
    const expiry = expiryInfo(cred.expires_at);
    let expiryBadge = '';
    if (expiry) {
      dataset.expiry = expiry.state;
      expiryBadge = '<span class="status-badge status-' + expiry.state + ' ico-clock" id="' + idPrefix + 'expiry-' + cred.id +
        '" title="' + escHtml(expiry.title) + '">' + escHtml(expiry.label) + '</span>';
    }

    // The issuer signature checked against only the key material embedded in
    // the credential (its x5c chain or embedded jwk), with no trust anchor. A
    // pass means self-consistent, never that the issuer is trusted (ADR-0009).
    let signatureBadge = '';
    const sig = cred.signature;
    if (sig && sig.algorithm) {
      if (sig.self_consistent) {
        signatureBadge = '<span class="status-badge status-active ico-check" id="' + idPrefix + 'signature-' + cred.id +
          '" title="The signature verifies against the key material the credential carries (its x5c certificate or embedded jwk, ' + escHtml(sig.algorithm) +
          '). It is not checked against any trust anchor, so it proves the credential is intact, not who the issuer is.">Self-consistent</span>';
      } else {
        const kind = cred.issuer && cred.issuer.kind ? ' · ' + escHtml(cred.issuer.kind.toUpperCase()) : '';
        signatureBadge = '<span class="status-badge status-revoked ico-x" id="' + idPrefix + 'signature-' + cred.id +
          '" title="The credential carries no key material this wallet can verify the signature against offline, so its integrity is unchecked here.">not verified' + kind + '</span>';
      }
    }

    // Holder binding: bound to a key this wallet holds (presentable), bound to
    // a key it does not hold (shown and decoded but never presentable), or no
    // binding at all. The unheld case keeps its own hook so a picker can warn.
    let keyBindingBadge = '';
    const binding = cred.holder_binding ||
      (cred.key_binding_not_held === true ? 'other_key' : '');
    if (binding === 'this_wallet') {
      dataset.keyBinding = 'this-wallet';
      keyBindingBadge = '<span class="status-badge status-active ico-check" id="' + idPrefix + 'key-binding-' + cred.id +
        '" title="Bound to a holder key this wallet holds, so it can be presented.">Bound to this wallet</span>';
    } else if (binding === 'other_key') {
      dataset.keyBinding = 'not-held';
      keyBindingBadge = '<span class="status-badge status-unheld-key ico-warn" id="' + idPrefix + 'key-binding-' + cred.id +
        '" title="Bound to a holder key this wallet does not hold. Presenting it fails the verifier\'s key binding check.">Bound to another key</span>';
    } else if (binding === 'none') {
      dataset.keyBinding = 'none';
      keyBindingBadge = '<span class="status-badge status-none" id="' + idPrefix + 'key-binding-' + cred.id +
        '" title="The credential names no holder key.">No key binding</span>';
    }

    // The issuer-declared appearance (§12.2.4), stored with the credential.
    const display = cred.display || {};
    const logoImg = display.logo_uri
      ? '<img class="credential-logo" src="' + escHtml(display.logo_uri) + '" alt="' + escHtml(display.logo_alt_text || '') + '">'
      : '';
    const faceLabel = display.name ? escHtml(display.name) : escHtml(typeLabel);

    // The card face: one background slot (art over color, or a solid color, or
    // a plain tile), painted by applyCredentialDisplay. The format badge and
    // the name overlay it, so on a phone the face reads like a wallet card.
    const faceHtml = '<div class="card-face">' +
      '<span class="format-badge format-badge-face">' + formatLabel + '</span>' +
      logoImg +
      '<div class="face-name">' + faceLabel + '</div>' +
      '</div>';

    // The headline is the display name, or the technical type when the issuer
    // declared no name. The type is not repeated: when a name leads, the type
    // moves to the meta row below, and when it is the headline the meta row
    // drops it.
    const nameHtml = '<span class="credential-name">' + faceLabel + '</span>';

    // The meta strip carries every technical fact in one line so the header can
    // be just the name: the short id (the per-instance handle), when it was
    // issued, the type a DCQL query matches on, the issuer as the format carries
    // it, and the claim count.
    const idMeta = '<span class="cred-meta-item cred-m-id"><span class="cred-meta-k">id</span> <span class="mono cred-shortid">#' + escHtml(shortCredentialId(cred.id)) + '</span></span>';

    const rel = relativeTime(cred.issued_at);
    const issuedMeta = rel ? '<span class="cred-meta-item cred-m-iat"><span class="cred-meta-k">iat</span> ' + escHtml(rel) + '</span>' : '';

    // The vct is shown once: it is the headline when the issuer declared no
    // name, and a meta item when a display name took the headline.
    const typeMeta = display.name
      ? '<span class="cred-meta-item cred-m-type"><span class="cred-meta-k">type</span> <span class="mono">' + escHtml(typeLabel) + '</span></span>'
      : '';

    // Issuer as the format actually carries it: iss for SD-JWT, the signing
    // certificate subject for mdoc, a DID otherwise.
    let issuerMeta = '';
    if (cred.issuer && cred.issuer.value) {
      issuerMeta = '<span class="cred-meta-item cred-m-iss"><span class="cred-meta-k">' + escHtml(cred.issuer.kind || 'iss') +
        '</span> <span class="mono">' + escHtml(cred.issuer.value) + '</span></span>';
    }

    const claimCount = Object.keys(cred.claims || {}).length;
    const countMeta = '<span class="cred-meta-item cred-m-claims">' + claimCount + ' claim' + (claimCount === 1 ? '' : 's') + '</span>';

    const bodyHtml = '<div class="credential-info">' +
        '<div class="credential-type cred-hdr">' +
          '<span class="format-badge format-badge-row">' + formatLabel + '</span>' +
          nameHtml +
        '</div>' +
        '<div class="cred-pills">' + protectedBadge + statusBadge + expiryBadge + signatureBadge + keyBindingBadge + '</div>' +
        '<div class="cred-meta">' +
          idMeta + issuedMeta + typeMeta + issuerMeta + countMeta +
        '</div>' +
      '</div>';

    return { html: faceHtml + bodyHtml, dataset: dataset };
  }

  // applyCredentialDisplay paints the issuer-declared appearance (§12.2.4)
  // onto the card face, which has one background slot the way a real wallet
  // card does: the background image over the background color as its base, or
  // a solid color when there is no image, or a plain tile with a monogram or a
  // generic glyph when the issuer declared neither. The color lives only in
  // the face, never as a row tint. Values were validated at issuance and are
  // assigned as style properties, never interpolated into a style sheet.
  function applyCredentialDisplay(card, display) {
    const face = card.querySelector('.card-face');
    if (!face) return;
    display = display || {};
    const textColor = String(display.text_color || '');
    const darkText = textColor.toLowerCase() === '#000' || textColor.toLowerCase() === '#000000';

    if (display.background_uri) {
      const scrim = darkText
        ? 'linear-gradient(0deg,rgba(255,255,255,.80),rgba(255,255,255,.12) 58%)'
        : 'linear-gradient(0deg,rgba(0,0,0,.62),rgba(0,0,0,.05) 58%)';
      // The image over the declared color as its base, so a transparent image
      // shows the color through it. url() takes the value as a plain string,
      // not a place a quote could break out of a rule.
      face.style.backgroundImage = scrim + ', url("' + display.background_uri.replace(/["\\]/g, '') + '")';
      if (display.background_color) face.style.backgroundColor = display.background_color;
      face.style.color = textColor || '#fff';
    } else if (display.background_color) {
      face.style.background = 'linear-gradient(135deg, ' + display.background_color +
        ', color-mix(in srgb, ' + display.background_color + ' 56%, #000))';
      face.style.color = textColor || '#fff';
    } else {
      // No art and no color. A logo still sits on the plain tile, otherwise a
      // monogram from the display name, or a generic glyph when there is not
      // even a name to initial.
      face.classList.add('plain');
      if (!face.querySelector('.credential-logo')) {
        const name = display.name || '';
        const initials = credentialInitials(name);
        const glyph = name && initials
          ? '<span class="face-init">' + escHtml(initials) + '</span>'
          : GENERIC_FACE_GLYPH;
        const nameEl = face.querySelector('.face-name');
        if (nameEl) nameEl.insertAdjacentHTML('beforebegin', glyph);
      }
    }

    // The overlaid format badge takes the declared text color so it reads as
    // part of the face, with a scrim that contrasts either way.
    const fb = face.querySelector('.format-badge-face');
    if (fb) {
      fb.style.color = textColor || '#fff';
      fb.style.background = darkText ? 'rgba(255,255,255,.62)' : 'rgba(0,0,0,.5)';
    }
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

      const isProtected = cred.protected === true;
      const body = credentialCardBody(cred, '');
      card.id = 'credential-' + cred.id;
      Object.assign(card.dataset, body.dataset);

      // What can be done about the status this card shows: revoke an entry on
      // the wallet's own list, re-check one on somebody else's.
      const st = cred.status;
      let revokeBtn = '';
      if (st && st.managed) {
        if (!isProtected) {
          revokeBtn = '<button class="btn btn-sm" id="revoke-' + cred.id + '" data-revoke="' + cred.id + '">' + (st.status === 1 ? 'Activate' : 'Revoke') + '</button>';
        }
      } else if (st && st.uri) {
        revokeBtn = '<button class="btn btn-sm" id="status-check-' + cred.id + '" data-check-status="' + cred.id + '">Check status</button>';
      }

      card.innerHTML = body.html +
        '<div class="credential-actions">' +
          revokeBtn +
          '<button class="btn btn-sm" id="show-' + cred.id + '" data-show="' + cred.id + '">Show</button>' +
          (isProtected ? '' : '<button class="btn btn-danger btn-sm" id="delete-' + cred.id + '" data-delete="' + cred.id + '">Delete</button>') +
        '</div>';
      card.querySelector('.credential-info').title = 'Open in decoder';
      applyCredentialDisplay(card, cred.display);

      const openDecoder = () => {
        // By id: the decoder is mounted on this wallet and can look the
        // credential up, which keeps the link short enough to share.
        window.open('/decoder/?id=' + encodeURIComponent(cred.id), '_blank');
      };
      card.querySelector('[data-show]').addEventListener('click', openDecoder);
      card.querySelector('.credential-info').addEventListener('click', openDecoder);
      card.querySelector('.card-face').addEventListener('click', openDecoder);
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

  // Display: keep each color picker and its text field in step, and load an
  // uploaded image into its text field as a data URI. The text field is the
  // value that is sent, so the picker and the upload are conveniences.
  function bindColorPicker(pickerId, textId) {
    const picker = document.getElementById(pickerId);
    const text = document.getElementById(textId);
    picker.addEventListener('input', () => { text.value = picker.value; });
    text.addEventListener('input', () => {
      if (/^#[0-9a-fA-F]{6}$/.test(text.value.trim())) picker.value = text.value.trim();
    });
  }
  bindColorPicker('issue-bg-color-picker', 'issue-bg-color');
  bindColorPicker('issue-text-color-picker', 'issue-text-color');

  function bindImageUpload(fileId, textId) {
    document.getElementById(fileId).addEventListener('change', (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => { document.getElementById(textId).value = reader.result; };
      reader.onerror = () => { issueError.textContent = 'Could not read the selected file.'; };
      reader.readAsDataURL(file);
    });
  }
  bindImageUpload('issue-logo-file', 'issue-logo');
  bindImageUpload('issue-bg-image-file', 'issue-bg-image');

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

    const display = {};
    const dName = document.getElementById('issue-display-name').value.trim();
    if (dName) display.name = dName;
    const dDesc = document.getElementById('issue-display-description').value.trim();
    if (dDesc) display.description = dDesc;
    const bgColor = document.getElementById('issue-bg-color').value.trim();
    if (bgColor) display.background_color = bgColor;
    const txtColor = document.getElementById('issue-text-color').value.trim();
    if (txtColor) display.text_color = txtColor;
    const logo = document.getElementById('issue-logo').value.trim();
    if (logo) display.logo = logo;
    const bgImage = document.getElementById('issue-bg-image').value.trim();
    if (bgImage) display.background_image = bgImage;
    if (Object.keys(display).length > 0) body.display = display;

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

  // The pending list, naming the request this page was opened for. A browser
  // that keeps no cookie reaches that one by id and nothing else.
  function requestsURL() {
    return '/api/requests' +
      (openedForRequest ? '?request=' + encodeURIComponent(openedForRequest) : '');
  }

  // Show or hide the indicator for the requests waiting off screen. The
  // dialog covers it, so while one is open the banner is hidden rather than
  // dimmed behind it with a button nothing can click. Every close path
  // refreshes it, so what is still waiting is offered the moment it is gone.
  function updatePendingBanner(requests) {
    const banner = document.getElementById('pending-banner');
    const pending = requests || [];
    if (pending.length === 0 || consentOverlay.classList.contains('active')) {
      banner.hidden = true;
      return;
    }
    // A request no client named a browser for is offered to everybody, so on
    // a wallet several people reach it is as likely to be a stranger's as
    // this visitor's. The count says which kind is waiting.
    const claimed = pending.some((req) => req.mine);
    document.getElementById('pending-text').textContent = pending.length === 1
      ? (claimed ? 'A request is waiting for consent.' : 'A request is waiting that no browser claimed.')
      : pending.length + (claimed ? ' requests are waiting for consent.' : ' requests are waiting that no browser claimed.');
    banner.hidden = false;
  }

  async function refreshPendingBanner() {
    try {
      const resp = await fetch(requestsURL());
      const all = await resp.json();
      // A dialog whose request is no longer pending can answer nothing, so it
      // is closed here (this is how another tab drops a dialog for a request
      // answered elsewhere). The tab with the answer in flight keeps its dialog
      // and closes it with the result instead. closeConsentOverlay refreshes the
      // banner again, this time with the dialog gone.
      if (consentRequestOpen && !consentSubmitting && consentRequestID != null &&
          !(all || []).some((req) => req.id === consentRequestID)) {
        closeConsentOverlay();
        return;
      }
      updatePendingBanner(reviewableRequests(all));
    } catch (e) {
      /* leave the banner as it is */
    }
  }

  // What the banner may offer: everything pending this caller can answer,
  // minus the one already on screen. The wallet scopes the list to the caller,
  // so a request that belongs to another browser is not in it to begin with.
  function reviewableRequests(requests) {
    return (requests || []).filter((req) => !(consentRequestOpen && req.id === consentRequestID));
  }

  document.getElementById('pending-review').addEventListener('click', async () => {
    try {
      const resp = await fetch(requestsURL());
      const requests = reviewableRequests(await resp.json());
      if (requests && requests.length > 0) {
        showConsentDialog(requests[0]);
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
      const resp = await fetch(requestsURL());
      const requests = await resp.json();
      if (requests && requests.length > 0) {
        const own = requests.find((r) => r.id === openedForRequest) || requests.find((r) => r.mine);
        // Not over a dialog the user is already answering: this runs again
        // after a dropped stream, and reopening would reset a selection they
        // are in the middle of making.
        if (own && !consentRequestOpen) {
          showConsentDialog(own);
          return;
        }
        // What is left was submitted by a client that named no browser, so it
        // is nobody's in particular and waits in the banner.
        updatePendingBanner(reviewableRequests(requests));
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
    const es = new EventSource('/api/requests/stream' +
      (actingOwner ? '?owner=' + encodeURIComponent(actingOwner) : ''));
    es.addEventListener('consent', (event) => {
      try {
        const req = JSON.parse(event.data);
        // A dialog belongs to the browser that started the flow. Anything
        // else waits in the banner, where it interrupts nobody.
        if (req.mine) {
          showConsentDialog(req);
          return;
        }
        refreshPendingBanner();
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
        refreshPendingBanner();
      }, 300);
    });
    // An issuance in progress needs the user to sign in at the issuer. The
    // wallet cannot do that for them, so this tab goes there; the issuer
    // redirects back to /callback, which resumes the flow and returns here.
    es.addEventListener('authorize', (event) => {
      try {
        const { url } = JSON.parse(event.data);
        if (navigable(url)) window.location.href = url;
      } catch (e) {
        console.error('SSE authorize parse error:', e);
      }
    });
    es.addEventListener('wallet-error', (event) => {
      try {
        presentError(JSON.parse(event.data));
      } catch (e) {
        console.error('SSE wallet-error parse error:', e);
      }
    });
    es.addEventListener('open', () => {
      // Events are not replayed, so a stream that dropped left a gap. Ask for
      // what arrived while it was down.
      if (streamDropped) {
        streamDropped = false;
        loadPendingRequests();
      }
    });
    es.onerror = () => {
      streamDropped = true;
      es.close();
      setTimeout(connectSSE, 3000);
    };
  }
  let streamDropped = false;

  // Starting something drops a stored error from before it, which a later
  // action would otherwise inherit.
  function expectError() {
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
  // Which request the dialog on screen belongs to. A late answer from a fetch
  // one dialog started must not redraw the dialog that replaced it.
  let consentRequestID = null;
  // Whether this tab has an approve or deny in flight. This tab's own dialog is
  // driven by that request, so the resolution reconciliation leaves it alone
  // and lets the handler close it with the result.
  let consentSubmitting = false;

  // Closing the dialog puts whatever is still pending back in the banner. A
  // second request arriving while one is on screen replaces it, so without
  // this the first one would be waiting where nothing shows it.
  function closeConsentOverlay() {
    consentRequestOpen = false;
    consentRequestID = null;
    consentOverlay.classList.remove('active');
    refreshPendingBanner();
  }

  function presentError(err) {
    if (!err || !err.message) return;
    if (consentRequestOpen) {
      // A request the user is being asked about is on screen. This error is
      // not from it: the flow it belongs to ended before this one began.
      dropStoredError();
      return;
    }
    showErrorDialog(err.message, err.detail);
  }

  function showErrorDialog(message, detail) {
    consentRequestOpen = false;
    consentOverlay.classList.add('active');

    var html = '<div class="dialog-title" style="color:var(--danger)">Error</div>' +
      '<div class="dialog-message">' + escHtml(message) + '</div>';

    if (detail) {
      html += '<pre class="error-detail">' + escHtml(detail) + '</pre>';
    }

    html += '<div class="consent-buttons">' +
      '<button class="btn btn-primary" id="error-dismiss">Dismiss</button>' +
    '</div>';

    consentDialog.innerHTML = html;
    document.getElementById('error-dismiss').addEventListener('click', () => {
      closeConsentOverlay();
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

    var html = '<div class="dialog-title" style="color:' + titleColor + '">' + titleText + ' (HTTP ' + (result.status_code || '?') + ')</div>';

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
      closeConsentOverlay();
      loadLog();
    });
  }


  // An offered credential configuration, as the same card the list and consent
  // render. It is not issued yet, so it carries no trust state (status, a
  // signature, holder binding): only the issuer-declared face, the name and
  // type, an optional description, and the claim names it would carry. The face
  // is painted by applyCredentialDisplay through the data-config-id hook.
  function offerCardHtml(cred) {
    const fmt = cred.format ? formatLabelFor(cred) : '';
    const typeLabel = cred.vct || cred.doctype || cred.id;
    const display = cred.display || {};
    const logoImg = display.logo_uri
      ? '<img class="credential-logo" src="' + escHtml(display.logo_uri) + '" alt="' + escHtml(display.logo_alt_text || '') + '">'
      : '';
    const faceBadge = fmt ? '<span class="format-badge format-badge-face">' + fmt + '</span>' : '';
    const rowBadge = fmt ? '<span class="format-badge format-badge-row">' + fmt + '</span>' : '';
    const faceName = cred.name || typeLabel;
    const nameHtml = '<span class="credential-name">' + escHtml(faceName) + '</span>';
    const typeMeta = cred.name
      ? '<div class="cred-meta"><span class="cred-meta-item"><span class="cred-meta-k">type</span> <span class="mono">' + escHtml(typeLabel) + '</span></span></div>'
      : '';
    const card = '<div class="credential-card">' +
        '<div class="card-face">' + faceBadge + logoImg + '<div class="face-name">' + escHtml(faceName) + '</div></div>' +
        '<div class="credential-info">' +
          '<div class="credential-type cred-hdr">' + rowBadge + nameHtml + '</div>' +
          typeMeta +
          (cred.description ? '<div class="offer-description">' + escHtml(cred.description) + '</div>' : '') +
        '</div>' +
      '</div>';
    let claims = '';
    if (cred.claims && cred.claims.length > 0) {
      claims = '<div class="cl-hd">↗ You will receive<span class="cl-count">' + cred.claims.length +
          ' claim' + (cred.claims.length === 1 ? '' : 's') + '</span></div>' +
        '<div class="consent-claims offer-claims">' + cred.claims.map(claim =>
          '<div class="consent-claim"><span class="consent-claim-name mono">' + escHtml(claim) + '</span></div>'
        ).join('') + '</div>';
    }
    return '<div class="consent-credential" data-config-id="' + escHtml(cred.id) + '">' + card + claims + '</div>';
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

    credentials.forEach(cred => { html += offerCardHtml(cred); });

    if (details.metadata_error) {
      html += '<p class="dialog-hint" id="offer-metadata-error">The issuer published no readable metadata, ' +
        'so only what the offer itself carries is shown.</p>';
    }
    return html;
  }

  function showConsentDialog(req) {
    consentRequestOpen = true;
    consentRequestID = req.id;
    consentSubmitting = false;
    dropStoredError();
    consentOverlay.classList.add('active');
    // This one is on screen now, and a request it replaced is not.
    refreshPendingBanner();

    const isIssuance = req.type === 'issuance';

    // The alternatives the request offers: per set its satisfiable options,
    // per query id its matching credentials. The selection starts on the
    // wallet's own choice (option 0, first candidate, every claim), so an
    // untouched Approve behaves exactly like before.
    const options = !isIssuance && req.credential_options &&
      (req.credential_options.queries || []).length > 0 ? req.credential_options : null;
    const selection = { editing: false, setChoices: [], picks: {}, claims: {} };
    let submitting = false;
    if (options) {
      selection.setChoices = (options.sets || []).map(() => 0);
      options.queries.forEach(q => {
        selection.picks[q.id] = q.candidates[0].credential_id;
        q.candidates.forEach(c => {
          // Merged, not replaced: a credential answering two queries keeps
          // one disclosure state, which is also how the approval applies it.
          const kept = selection.claims[c.credential_id] || [];
          Object.keys(c.claims || {}).forEach(key => {
            if (!kept.includes(key)) kept.push(key);
          });
          selection.claims[c.credential_id] = kept;
        });
      });
    }

    function queryById(id) { return options.queries.find(q => q.id === id); }
    function activeQueryIds() {
      if (!options.sets || options.sets.length === 0) return options.queries.map(q => q.id);
      const ids = [];
      options.sets.forEach((set, i) => {
        const choice = selection.setChoices[i];
        if (choice === -1) return;
        (set.options[choice] || []).forEach(id => { if (!ids.includes(id)) ids.push(id); });
      });
      return ids;
    }
    function activeCandidate(qid) {
      const q = queryById(qid);
      return q.candidates.find(c => c.credential_id === selection.picks[qid]) || q.candidates[0];
    }
    function hasAlternatives() {
      if (!options) return false;
      if ((options.sets || []).some(s => s.options.length > 1 || s.optional)) return true;
      return options.queries.some(q => q.candidates.length > 1);
    }
    function alternativeCount() {
      let n = 0;
      (options.sets || []).forEach(s => { n += s.options.length - 1 + (s.optional ? 1 : 0); });
      options.queries.forEach(q => { n += q.candidates.length - 1; });
      return n;
    }
    function isAutoSelection() {
      return selection.setChoices.every(c => c === 0) &&
        options.queries.every(q => selection.picks[q.id] === q.candidates[0].credential_id);
    }
    // The candidate cards want the whole credential, which the request does
    // not carry. Reading them when the Edit view opens keeps a consent that is
    // simply approved from asking for anything, and the cards render from the
    // match in the meantime, so there is nothing to wait for on screen.
    let loadingCandidates = false;
    // The credential ids the dialog shows, from the DCQL queries or, without
    // them, the matched credentials. Both surfaces render the issuer-declared
    // appearance, which travels with the fetched detail.
    function candidateIds() {
      const ids = [];
      const add = id => { if (id && !ids.includes(id)) ids.push(id); };
      if (options) {
        options.queries.forEach(q => q.candidates.forEach(c => add(c.credential_id)));
      } else if (req.matched_credentials) {
        req.matched_credentials.forEach(mc => add(mc.credential_id));
      }
      return ids;
    }
    function ensureCandidateDetails() {
      if (loadingCandidates) return;
      const ids = candidateIds().filter(id => !candidateDetails.has(id));
      if (ids.length === 0) return;
      loadingCandidates = true;
      loadCandidateDetails(ids).then(loaded => {
        loadingCandidates = false;
        if (loaded && consentRequestOpen && consentRequestID === req.id) renderDialog();
      });
    }

    // The party the request comes from. For a presentation it is the verifier
    // client_id, with the request-object authentication state beside it and the
    // self-asserted client_name (when any) as the visible name. For an offer it
    // is the issuer, named by its metadata when the issuer published one. The
    // authenticated id always sits on the line carrying #offer-issuer-origin.
    function whoBlock() {
      let name, cid, chip = '';
      if (isIssuance) {
        const d = req.offer_details || {};
        name = d.issuer_name || '';
        cid = d.issuer || req.client_id || '';
      } else {
        name = req.client_name || '';
        cid = req.client_id || '';
        const auth = req.client_auth;
        if (auth) {
          chip = auth.signed
            ? '<span class="who-chip who-ok" title="The request object is signed and the signature verifies against the key material it carries. Self-consistent, not checked against any trust anchor.">✓ Signed</span>'
            : '<span class="who-chip who-bad" title="' + escHtml(auth.detail || 'The request object is not signed, so the wallet cannot check who sent it. On a shared demo anyone can send a request.') + '">✗ Not authenticated</span>';
        }
      }
      const idLine = '<span class="mono">' + escHtml(cid) + '</span>';
      let nameHtml, sub;
      if (name) {
        nameHtml = '<span class="who-name">' + escHtml(name) + '</span>';
        sub = '<div class="who-cid" id="offer-issuer-origin">' + idLine + '</div>';
      } else {
        nameHtml = '<span class="who-name mono" id="offer-issuer-origin">' + escHtml(cid) + '</span>';
        sub = '';
      }
      return '<div class="who"><div class="who-nm">' + nameHtml + chip + '</div>' + sub + '</div>';
    }

    function headerHtml() {
      // Title text stays "Presentation Request" / "Credential Offer" (the
      // dialog is scanned for it), rendered as a small kicker above the who
      // block so the party asking leads.
      let html = '<div class="consent-title">' + (isIssuance ? 'Credential Offer' : 'Presentation Request') + '</div>' +
        whoBlock();

      // The purposes the verifier registered for this data request, read by the
      // wallet from the registration certificates in verifier_info (OpenID4VP
      // 1.0 section 5.1) and shown with the request they explain.
      if (!isIssuance && req.purposes) {
        req.purposes.forEach((text, idx) => {
          html += '<div class="consent-purpose" id="consent-purpose-' + idx + '">' +
            '<span class="consent-purpose-label">Purpose</span>' + escHtml(text) + '</div>';
        });
      }
      return html;
    }

    // The disclosed fields for a credential, as selective-disclosure
    // checkboxes. Every claim stays uncheckable, including required ones, so a
    // test wallet can withhold a field and see how the verifier reacts.
    function claimChecklist(credID, claims, kept) {
      const keys = Object.keys(claims || {});
      const shared = keys.filter(k => (kept ? kept.includes(k) : true)).length;
      let rows = '';
      keys.forEach(key => {
        const val = typeof claims[key] === 'object' ? JSON.stringify(claims[key]) : String(claims[key]);
        const checked = kept ? kept.includes(key) : true;
        rows += '<label class="consent-claim">' +
          '<input type="checkbox"' + (checked ? ' checked' : '') + ' data-cred="' + credID + '" data-claim="' + escHtml(key) + '">' +
          '<span class="consent-claim-name mono">' + escHtml(key) + '</span>' +
          '<span class="consent-claim-value mono">' + escHtml(val) + '</span>' +
        '</label>';
      });
      return '<div class="cl-hd">↗ Shared with the verifier<span class="cl-count">' +
          shared + ' of ' + keys.length + ' field' + (keys.length === 1 ? '' : 's') + '</span></div>' +
        '<div class="consent-claims">' + rows + '</div>';
    }

    // The summary card: the same card the credential list renders (reused from
    // credentialCardBody, laid out compactly in the dialog) with the disclosed
    // fields below it. Until the full credential has loaded it renders from the
    // match, which knows the type and format but only the requested claims.
    function credentialCardHtml(mc) {
      const detail = candidateDetails.get(mc.credential_id);
      const cred = detail || {
        id: mc.credential_id, format: mc.format, vct: mc.vct, doctype: mc.doctype, claims: mc.claims,
      };
      const body = credentialCardBody(cred, 'summary-');
      const kept = options ? selection.claims[mc.credential_id] : null;
      return '<div class="consent-credential" id="consent-credential-' + mc.credential_id + '" data-credential-id="' + mc.credential_id + '" data-vct="' + escHtml(mc.vct || '') + '" data-doctype="' + escHtml(mc.doctype || '') + '">' +
        '<div class="credential-card">' + body.html + '</div>' +
        claimChecklist(mc.credential_id, mc.claims, kept) +
      '</div>';
    }

    // The Edit view: the set options and, per query id of the chosen
    // options, the matching credentials. Changes apply immediately, Done
    // returns to the summary, and the bottom buttons stay the dialog's own
    // Deny/Approve on both screens.
    function editScreenHtml() {
      let html = headerHtml() +
        '<div class="consent-selection-row">Selection' +
        (isAutoSelection() ? '' : '<button class="link-btn" id="consent-selection-reset">reset to auto</button>') +
        '<button class="btn" id="consent-selection-done">Done</button></div>';

      (options.sets || []).forEach((set, i) => {
        if (set.options.length === 1 && !set.optional) return;
        html += '<div class="consent-sets" id="consent-set-' + i + '" data-set="' + i + '"><span class="consent-section-label">The verifier accepts one of</span>';
        set.options.forEach((opt, j) => {
          html += '<label class="consent-set-option">' +
            '<input type="radio" id="consent-set-' + i + '-option-' + j + '" name="consent-set-' + i + '" value="' + j + '"' + (selection.setChoices[i] === j ? ' checked' : '') + '>' +
            opt.map(id => '<span class="query-chip">' + escHtml(id) + '</span>').join(' + ') +
            (j === 0 ? ' <span class="auto-chip">auto</span>' : '') +
          '</label>';
        });
        if (set.optional) {
          // A presentation carries at least one credential, so the last
          // answered set cannot also be skipped.
          const othersAnswered = selection.setChoices.some((c, j) => j !== i && c !== -1);
          html += '<label class="consent-set-option">' +
            '<input type="radio" id="consent-set-' + i + '-none" name="consent-set-' + i + '" value="-1"' +
            (selection.setChoices[i] === -1 ? ' checked' : '') +
            (othersAnswered ? '' : ' disabled') +
            '><span class="query-chip">none</span></label>';
        }
        html += '</div>';
      });

      activeQueryIds().forEach(qid => {
        const q = queryById(qid);
        html += '<div class="consent-credential" id="consent-query-' + escHtml(qid) + '" data-query-id="' + escHtml(qid) + '" role="radiogroup" aria-label="Credential answering ' + escHtml(qid) + '">' +
          '<div class="consent-credential-header">' +
            '<span class="query-id-label">' + escHtml(qid) + '</span>' +
            '<span class="candidate-count">' + q.candidates.length +
              (q.candidates.length === 1 ? ' credential matches' : ' of your credentials match') + '</span>' +
          '</div>';
        q.candidates.forEach((c, i) => {
          const picked = selection.picks[qid] === c.credential_id;
          // The same card the credential list renders. Until the whole
          // credential is here the card is built from the match itself, which
          // knows the type and the format but only the claims the verifier
          // asked for, so the claim names wait for the rest.
          const detail = candidateDetails.get(c.credential_id);
          const body = credentialCardBody(detail || {
            id: c.credential_id, format: c.format, vct: c.vct, doctype: c.doctype, claims: c.claims,
          }, 'candidate-');
          html += '<div class="candidate' + (picked ? ' selected' : '') + '" id="consent-candidate-' + escHtml(qid) + '-' + c.credential_id + '" data-query="' + escHtml(qid) + '" data-cred="' + c.credential_id + '" tabindex="0" role="radio" aria-checked="' + picked + '" aria-label="' + escHtml(c.vct || c.doctype || c.format) + '">' +
            '<div class="candidate-row">' +
              '<input type="radio" name="consent-pick-' + escHtml(qid) + '"' + (picked ? ' checked' : '') + ' tabindex="-1" aria-hidden="true">' +
              '<div class="credential-card">' + body.html + '</div>' +
              '<div class="candidate-actions">' +
                (i === 0 ? '<span class="auto-chip">auto</span>' : '') +
                // By id, like the credential list's own decoder link, and in a
                // new tab: the consent is still pending and waiting for an
                // answer, so reading a credential must not navigate away from
                // the dialog that is asking.
                '<a class="btn btn-sm candidate-decode" id="consent-decode-' + escHtml(qid) + '-' + c.credential_id + '"' +
                  ' href="/decoder/?id=' + encodeURIComponent(c.credential_id) + '" target="_blank" rel="noopener"' +
                  ' title="Open in decoder">Show</a>' +
              '</div>' +
            '</div></div>';
        });
        html += '</div>';
      });

      return html;
    }

    function wireSelectionHandlers() {
      // The issuer-declared face on every consent card that names a credential,
      // so it looks the same being decided on as it does at rest. Presentation
      // summary cards carry data-credential-id, edit-view candidates carry
      // data-cred (both fetched into candidateDetails), and issuance offer cards
      // carry data-config-id (display in the offer details). The query-group
      // wrapper has none.
      consentDialog.querySelectorAll('[data-credential-id], .candidate[data-cred]').forEach(el => {
        const id = el.dataset.credentialId || el.dataset.cred;
        const detail = candidateDetails.get(id);
        if (detail && detail.display) applyCredentialDisplay(el, detail.display);
      });
      if (isIssuance && req.offer_details) {
        const byId = {};
        (req.offer_details.credentials || []).forEach(c => { byId[c.id] = c.display; });
        consentDialog.querySelectorAll('[data-config-id]').forEach(el => {
          const display = byId[el.dataset.configId];
          if (display) applyCredentialDisplay(el, display);
        });
      }

      const edit = document.getElementById('consent-edit-selection');
      if (edit) edit.addEventListener('click', () => { selection.editing = true; renderDialog(); });
      const done = document.getElementById('consent-selection-done');
      if (done) done.addEventListener('click', () => { selection.editing = false; renderDialog(); });
      const reset = document.getElementById('consent-selection-reset');
      if (reset) reset.addEventListener('click', () => {
        selection.setChoices = (options.sets || []).map(() => 0);
        options.queries.forEach(q => { selection.picks[q.id] = q.candidates[0].credential_id; });
        renderDialog();
      });
      consentDialog.querySelectorAll('.consent-sets input[type="radio"]').forEach(radio => {
        radio.addEventListener('change', () => {
          const setIdx = Number(radio.closest('.consent-sets').dataset.set);
          selection.setChoices[setIdx] = Number(radio.value);
          renderDialog();
        });
      });
      consentDialog.querySelectorAll('.candidate').forEach(el => {
        const choose = () => {
          if (selection.picks[el.dataset.query] !== el.dataset.cred) {
            selection.picks[el.dataset.query] = el.dataset.cred;
            renderDialog();
          }
        };
        el.addEventListener('click', choose);
        el.addEventListener('keydown', e => {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); choose(); }
        });
      });
      // The row it sits in selects the candidate, so the link keeps its own
      // click. Without this, picking a different candidate re-renders the
      // dialog while the browser is still following the anchor.
      consentDialog.querySelectorAll('.candidate-decode').forEach(link => {
        link.addEventListener('click', e => e.stopPropagation());
        link.addEventListener('keydown', e => e.stopPropagation());
      });
      if (options) {
        consentDialog.querySelectorAll('.consent-claim input[type="checkbox"]').forEach(cb => {
          cb.addEventListener('change', () => {
            const kept = selection.claims[cb.dataset.cred];
            const idx = kept.indexOf(cb.dataset.claim);
            if (cb.checked && idx < 0) kept.push(cb.dataset.claim);
            if (!cb.checked && idx >= 0) kept.splice(idx, 1);
          });
        });
      }

      // Keep each card's "X of Y fields" count in step with its checkboxes, so
      // withholding a field shows in the header at once.
      consentDialog.querySelectorAll('.consent-credential').forEach(credEl => {
        const countEl = credEl.querySelector('.cl-count');
        const boxes = credEl.querySelectorAll('.consent-claims input[type="checkbox"]');
        if (!countEl || boxes.length === 0) return;
        const total = boxes.length;
        const update = () => {
          const checked = [...boxes].filter(b => b.checked).length;
          countEl.textContent = checked + ' of ' + total + ' field' + (total === 1 ? '' : 's');
        };
        boxes.forEach(b => b.addEventListener('change', update));
      });
    }

    function renderDialog() {
    // A submission in flight owns the dialog: re-rendering would put a
    // fresh, enabled Approve on screen next to it.
    if (submitting) return;
    let html = headerHtml();

    if (isIssuance) {
      html += renderOfferDetails(req);
    }

    if (!isIssuance) {
      // Load the full detail behind every candidate so the cards can carry
      // the issuer's declared name, logo and colors, the same as the
      // credential list. A re-render follows when it arrives.
      ensureCandidateDetails();
    }

    if (!isIssuance && options) {
      // One quiet row announces the alternatives; the cards below stay
      // exactly the ones the current selection presents.
      if (hasAlternatives()) {
        const n = alternativeCount();
        html += '<div class="consent-selection-row" id="consent-selection-row">' +
          (isAutoSelection()
            ? 'Auto-selected · ' + n + (n === 1 ? ' alternative' : ' alternatives')
            : 'Your selection (auto-choice changed)') +
          '<button class="btn" id="consent-edit-selection">Edit</button></div>';
      }
      activeQueryIds().forEach(qid => { html += credentialCardHtml(activeCandidate(qid)); });
    } else if (!isIssuance && req.matched_credentials && req.matched_credentials.length > 0) {
      req.matched_credentials.forEach(mc => { html += credentialCardHtml(mc); });
    }

    if (options && selection.editing) {
      html = editScreenHtml();
    }

    html += '<div class="consent-buttons">' +
      '<button class="btn btn-danger" id="consent-deny">Deny</button>' +
      '<button class="btn btn-primary" id="consent-approve">Approve</button>' +
    '</div>';

    consentDialog.innerHTML = html;
    wireSelectionHandlers();

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

      // Gather selected claims: from the tracked selection when the request
      // offered alternatives (Approve also works from the Edit view, which
      // renders no claim checkboxes), from the checkboxes otherwise.
      const selected = {};
      if (options) {
        activeQueryIds().forEach(qid => {
          const c = activeCandidate(qid);
          selected[c.credential_id] = selection.claims[c.credential_id].slice();
        });
      } else {
        consentDialog.querySelectorAll('input[type="checkbox"]').forEach(cb => {
          if (cb.checked) {
            const credId = cb.dataset.cred;
            const claim = cb.dataset.claim;
            if (!selected[credId]) selected[credId] = [];
            selected[credId].push(claim);
          }
        });
      }

      const approveBtn = document.getElementById('consent-approve');
      const denyBtn = document.getElementById('consent-deny');
      submitting = true;
      consentSubmitting = true;
      approveBtn.disabled = true;
      approveBtn.textContent = 'Submitting...';
      expectError();
      denyBtn.disabled = true;

      try {
        const txCodeInput = document.getElementById('offer-tx-code-input');
        const approveBody = isIssuance
          ? (txCodeInput ? { tx_code: txCodeInput.value.trim() } : {})
          : { selected_claims: selected };
        if (options) {
          approveBody.picks = {};
          activeQueryIds().forEach(qid => { approveBody.picks[qid] = selection.picks[qid]; });
          approveBody.set_choices = selection.setChoices.slice();
        }
        const resp = await fetch(approveURL(req.id, '/approve'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(approveBody)
        });
        const result = await resp.json();
        // The wait for an answer can outlast this dialog: a presentation the
        // issuer asks for mid-issuance replaces it. Whatever comes back then
        // belongs to a request that is no longer on screen.
        if (consentRequestID !== req.id) return;
        if (!resp.ok) {
          showErrorDialog('This request could not be answered', result.error || 'The wallet refused the answer.');
          return;
        }
        if (isIssuance) {
          // Deferred, not failed: the wallet keeps collecting it and the
          // credential appears once it arrives.
          if (result.pending) {
            closeConsentOverlay();
            await loadDeferred();
            await loadLog();
            return;
          }
          if (result.error || (result.status_code && result.status_code >= 400)) {
            const detail = result.error || ('HTTP ' + result.status_code);
            showErrorDialog('Credential issuance failed', detail);
            return;
          }
          closeConsentOverlay();
          await loadCredentials();
          await loadLog();
          return;
        }
        showSubmissionResult(result);
      } catch (e) {
        submitting = false;
        console.error('Approve failed:', e);
        showErrorDialog('Approve request failed', e.message);
      } finally {
        consentSubmitting = false;
      }
    });

    document.getElementById('consent-deny').addEventListener('click', async () => {
      consentSubmitting = true;
      try {
        const resp = await fetch(approveURL(req.id, '/deny'), { method: 'POST' });
        if (!resp.ok) {
          const result = await resp.json().catch(() => ({}));
          showErrorDialog('This request could not be denied', result.error || 'The wallet refused the answer.');
          return;
        }
      } catch (e) {
        console.error('Deny failed:', e);
      } finally {
        consentSubmitting = false;
      }
      closeConsentOverlay();
      await loadLog();
    });
    }

    renderDialog();
  }

  // Escapes for both element content and quoted attribute values, including
  // " and '. A value interpolated into an attribute (a status list URI, a
  // vct, a claim name, a credential configuration id) could otherwise close
  // the attribute and add an event handler. On a shared wallet those values
  // come from whoever imported the credential or sent the offer, so they run
  // in every other visitor's browser.
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
  async function loadAppConfig() {
    try {
      const resp = await fetch('/api/config');
      const config = await resp.json();
      if (config.version) {
        window.EUDI_VERSION = config.version;
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
      // An auto-accept wallet never opens a consent dialog, and without a
      // hint the silence reads as a broken flow. A local wallet can flip the
      // setting from the header. The demo keeps its consent rules, so there
      // it only shows the state.
      renderAutoAccept(!!config.auto_accept);
      renderConformance(config);
      ['conf-mode-select', 'conf-haip-input', 'conf-encrypted-input', 'conf-vci-version-select'].forEach((id) => {
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
    }
  }

  function renderAutoAccept(enabled) {
    const toggle = document.getElementById('auto-accept-toggle');
    toggle.hidden = demoMode && !enabled;
    toggle.disabled = demoMode;
    toggle.classList.toggle('btn-primary', enabled);
    toggle.setAttribute('aria-pressed', enabled ? 'true' : 'false');
    toggle.dataset.enabled = enabled ? '1' : '0';
    toggle.title = enabled
      ? 'This wallet approves every presentation and offer without asking.'
      : 'This wallet asks for consent before presenting or accepting.';
    if (!demoMode) {
      toggle.title += ' Click to change.';
    }
    if (!toggle.dataset.wired) {
      toggle.dataset.wired = '1';
      toggle.addEventListener('click', async () => {
        if (toggle.disabled) return;
        const next = toggle.dataset.enabled !== '1';
        try {
          const resp = await fetch('/api/config/auto-accept', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: next }),
          });
          if (resp.ok) renderAutoAccept(next);
        } catch (e) {
          console.error('Changing auto-accept failed:', e);
        }
      });
    }
  }

  // "daily at 00:00 CET", "every hour", or null when resets are disabled.
  // Shows what an incoming request has to satisfy. The wording is
  // deliberately about consequences rather than flag names: "enforced" only
  // means something if you can see what it rejects.
  // Conformance is the wallet's own process-level setting, reported by
  // /api/config. Only a locally-hosted wallet can change it (PUT/DELETE
  // /api/config/conformance); the public demo shows it read-only.
  let conformanceDefaults = { validation_mode: 'debug', require_haip: true, require_encrypted_request: false, vci_version: '1.0' };

  function effectiveConformance() {
    return {
      mode: conformanceDefaults.validation_mode === 'strict' ? 'strict' : 'debug',
      haip: !!conformanceDefaults.require_haip,
      encrypted: !!conformanceDefaults.require_encrypted_request,
      vciVersion: conformanceDefaults.vci_version === '1.1' ? '1.1' : '1.0',
    };
  }

  function applyConformanceToControls() {
    const eff = effectiveConformance();
    const mode = document.getElementById('conf-mode-select');
    const haip = document.getElementById('conf-haip-input');
    const enc = document.getElementById('conf-encrypted-input');
    const vci = document.getElementById('conf-vci-version-select');
    if (mode) { mode.value = eff.mode === 'strict' ? 'strict' : 'debug'; mode.disabled = demoMode; }
    if (haip) { haip.checked = eff.haip; haip.disabled = demoMode; }
    if (enc) { enc.checked = eff.encrypted; enc.disabled = demoMode; }
    if (vci) { vci.value = eff.vciVersion; vci.disabled = demoMode; }
  }

  function currentControlValues() {
    const mode = document.getElementById('conf-mode-select');
    const haip = document.getElementById('conf-haip-input');
    const enc = document.getElementById('conf-encrypted-input');
    const vci = document.getElementById('conf-vci-version-select');
    return {
      mode: mode ? mode.value : undefined,
      haip: haip ? haip.checked : undefined,
      encrypted: enc ? enc.checked : undefined,
      vci_version: vci ? vci.value : undefined,
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
      const base = 'How this wallet checks incoming requests, and which OpenID4VCI version it uses when it asks an issuer for a credential. A failed check is a warning in debug mode and rejects the request in strict mode.';
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

  // Initialize. The owner and the request id answer for this page, so they
  // are read above and cleared from the address bar rather than left where a
  // copied link would carry them.
  if (pageParams.get('focus') === 'overview' || openedForRequest || actingOwner) {
    if (pageParams.get('focus') === 'overview') {
      window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    }
    window.history.replaceState({}, document.title, window.location.pathname);
  }
  const loadAppConfigPromise = loadAppConfig();
  loadCredentials();
  loadDeferred();
  loadLog();
  loadAppConfigPromise.then(loadPendingRequests);
  connectSSE();
})();
