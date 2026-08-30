(() => {
  "use strict";

  // Compute base path so API calls work when mounted under a sub-path (e.g. /decode/).
  const basePath = (() => {
    const path = window.location.pathname;
    // If path ends with /, use it; otherwise strip the last segment.
    return path.endsWith("/") ? path : path.substring(0, path.lastIndexOf("/") + 1);
  })();

  const input = document.getElementById("input");
  const outputEl = document.getElementById("output");
  const formatBadge = document.getElementById("format-badge");
  const clearBtn = document.getElementById("clear-btn");
  const shareBtn = document.getElementById("share-btn");
  const themeBtn = document.getElementById("theme-btn");
  const rawView = document.getElementById("raw-view");
  const EMPTY_OUTPUT_HTML = '<div class="placeholder">Paste a credential to see decoded output</div>';

  let decodeTimer = null;
  let decodeDueAt = 0;
  // Bumped per decode so a slow answer for text that has since changed is
  // dropped instead of overwriting what is on screen.
  let decodeSeq = 0;
  let renderedSeq = -1;
  let lastData = null;
  let lastValidation = null;
  let colorized = false; // true when showing colorized view instead of textarea
  // The credential currently shown, when it came from a wallet this decoder
  // is mounted on: {id, credential}. A link can then name it by id instead of
  // carrying kilobytes of base64url, and the share button keeps that form.
  let walletCredential = null;

  // Disclosure color palette size
  const DISC_COLORS = 8;

  // Well-known timestamp fields in JWT/SD-JWT payloads
  const TIMESTAMP_FIELDS = new Set(["exp", "iat", "nbf", "auth_time", "updated_at"]);

  // Theme toggle
  const savedTheme = localStorage.getItem("eudi-dev-theme");
  if (savedTheme === "light") document.documentElement.setAttribute("data-theme", "light");
  themeBtn.addEventListener("click", () => {
    const isLight = document.documentElement.getAttribute("data-theme") === "light";
    document.documentElement.setAttribute("data-theme", isLight ? "" : "light");
    localStorage.setItem("eudi-dev-theme", isLight ? "" : "light");
  });

  // Clear
  clearBtn.addEventListener("click", () => {
    input.value = "";
    resetOutput();
    history.replaceState(null, "", window.location.pathname);
    input.focus();
  });

  // Share: copy the URL with a ?credential= query param
  shareBtn.addEventListener("click", copyShareLink);

  function copyShareLink() {
    const text = input.value.trim();
    if (!text) return;
    const url = window.location.origin + buildCredentialURL(text);
    navigator.clipboard.writeText(url).then(() => {
      showToast("Link copied to clipboard");
    }).catch(() => {
      showToast("Failed to copy link");
    });
  }

  function resetOutput() {
    outputEl.innerHTML = EMPTY_OUTPUT_HTML;
    formatBadge.className = "badge hidden";
    lastData = null;
    lastValidation = null;
    renderedSeq = -1;
    hideColorized();
  }

  function buildCredentialURL(text) {
    if (!text) return window.location.pathname;
    // The short form, while what is shown is still the credential it named.
    if (walletCredential && walletCredential.credential === text) {
      return window.location.pathname + "?id=" + encodeURIComponent(walletCredential.id);
    }
    return window.location.pathname + "?credential=" + encodeURIComponent(text);
  }

  function applyCredential(text) {
    input.value = text;
    if (colorized) updateRawView();
    if (text.trim()) {
      decode();
      return;
    }
    resetOutput();
  }

  function navigateToEmbeddedCredential(text) {
    const next = (text || "").trim();
    if (!next) return;

    const current = input.value.trim();
    if (current === next) return;
    if (current) {
      history.replaceState({ credential: current }, "", buildCredentialURL(current));
    }
    history.pushState({ credential: next }, "", buildCredentialURL(next));
    applyCredential(next);
  }

  // Colorized input view, overlaid behind a transparent textarea
  function showColorized() {
    if (colorized) return;
    colorized = true;
    input.classList.add("colorized");
    rawView.style.display = "block";
    updateRawView();
  }

  function hideColorized() {
    if (!colorized) return;
    colorized = false;
    input.classList.remove("colorized");
    rawView.style.display = "none";
  }

  // Sync scroll between textarea and colorized view
  input.addEventListener("scroll", () => {
    if (colorized) {
      rawView.scrollTop = input.scrollTop;
      rawView.scrollLeft = input.scrollLeft;
    }
  });

  // Section offset map: built during updateRawView, maps character ranges
  // to section IDs for cross-highlighting without pointer-events hacks.
  let sectionRanges = []; // [{start, end, section}]

  function updateRawView() {
    const text = input.value.trim();
    sectionRanges = [];
    if (!text) {
      rawView.innerHTML = '<span style="color:var(--text-dim);font-style:italic">No input</span>';
      return;
    }

    // Try to colorize as JWT/SD-JWT
    const parts = text.split("~");
    const jwtPart = parts[0];
    const jwtSegments = jwtPart.split(".");

    if (jwtSegments.length >= 2) {
      let html = "";
      let pos = 0;

      // Header
      sectionRanges.push({ start: pos, end: pos + jwtSegments[0].length, section: "header" });
      html += '<span class="jwt-header" data-section="header">' + escapeHtml(jwtSegments[0]) + "</span>";
      pos += jwtSegments[0].length;

      // .
      html += '<span class="jwt-separator">.</span>';
      pos += 1;

      // Payload
      sectionRanges.push({ start: pos, end: pos + jwtSegments[1].length, section: "payload" });
      html += '<span class="jwt-payload" data-section="payload">' + escapeHtml(jwtSegments[1]) + "</span>";
      pos += jwtSegments[1].length;

      // Signature
      if (jwtSegments.length > 2) {
        html += '<span class="jwt-separator">.</span>';
        pos += 1;
        const sigText = jwtSegments.slice(2).join(".");
        sectionRanges.push({ start: pos, end: pos + sigText.length, section: "signature" });
        html += '<span class="jwt-signature" data-section="signature">' + escapeHtml(sigText) + "</span>";
        pos += sigText.length;
      }

      // SD-JWT disclosures, each in its own color
      // Detect KB-JWT: last non-empty part that contains dots (JWT structure)
      let kbJwtIndex = -1;
      if (parts.length > 1) {
        for (let i = parts.length - 1; i >= 1; i--) {
          if (parts[i] && parts[i].includes(".")) {
            kbJwtIndex = i;
            break;
          }
        }
      }

      let discIdx = 0;
      for (let i = 1; i < parts.length; i++) {
        html += '<span class="jwt-separator">~</span>';
        pos += 1; // ~
        if (parts[i]) {
          if (i === kbJwtIndex) {
            // KB-JWT: colorize its internal structure
            const kbSegs = parts[i].split(".");
            sectionRanges.push({ start: pos, end: pos + parts[i].length, section: "kb-jwt" });
            html += '<span data-section="kb-jwt">';
            html += '<span class="jwt-header">' + escapeHtml(kbSegs[0]) + "</span>";
            if (kbSegs.length > 1) {
              html += '<span class="jwt-separator">.</span>';
              html += '<span class="jwt-payload">' + escapeHtml(kbSegs[1]) + "</span>";
            }
            if (kbSegs.length > 2) {
              html += '<span class="jwt-separator">.</span>';
              html += '<span class="jwt-signature">' + escapeHtml(kbSegs.slice(2).join(".")) + "</span>";
            }
            html += "</span>";
            pos += parts[i].length;
          } else {
            const colorIdx = discIdx % DISC_COLORS;
            sectionRanges.push({ start: pos, end: pos + parts[i].length, section: "disc-" + discIdx });
            html += '<span class="jwt-disc-' + colorIdx + '" data-section="disc-' + discIdx + '">' + escapeHtml(parts[i]) + "</span>";
            pos += parts[i].length;
            discIdx++;
          }
        }
      }

      rawView.innerHTML = html;
    } else {
      // Non-JWT (e.g. mDOC hex/base64)
      rawView.innerHTML = escapeHtml(text);
    }
  }

  // Cross-highlight: use character position in textarea to find which
  // section the cursor is over, based on the offset map built during colorization.
  let lastHoveredSection = null;

  function clearHoverHighlight() {
    if (!lastHoveredSection) return;
    const sec = lastHoveredSection;
    lastHoveredSection = null;

    const span = rawView.querySelector('[data-section="' + sec + '"]');
    if (span) span.classList.remove("highlight");

    if (sec.startsWith("disc-")) {
      const idx = sec.replace("disc-", "");
      const item = outputEl.querySelector('.disclosure-item[data-disc-index="' + idx + '"]');
      if (item) item.classList.remove("highlight");
    } else {
      const target = outputEl.querySelector('.section[data-section="' + sec + '"]');
      if (target) target.classList.remove("highlight");
    }
  }

  function applyHoverHighlight(sec) {
    if (sec === lastHoveredSection) return;
    clearHoverHighlight();
    lastHoveredSection = sec;

    const span = rawView.querySelector('[data-section="' + sec + '"]');
    if (span) span.classList.add("highlight");

    if (sec.startsWith("disc-")) {
      const idx = sec.replace("disc-", "");
      const item = outputEl.querySelector('.disclosure-item[data-disc-index="' + idx + '"]');
      if (item) {
        item.classList.add("highlight");
        item.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
    } else {
      const target = outputEl.querySelector('.section[data-section="' + sec + '"]');
      if (target) {
        target.classList.add("highlight");
        target.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
    }
  }

  // Hit-test the rawView spans to find which section the mouse is over.
  // Briefly swaps pointer-events so elementFromPoint can reach the rawView layer.
  function sectionFromPoint(e) {
    input.style.pointerEvents = "none";
    rawView.style.pointerEvents = "auto";
    const el = document.elementFromPoint(e.clientX, e.clientY);
    input.style.pointerEvents = "";
    rawView.style.pointerEvents = "none";
    const span = el && el.closest("[data-section]");
    return span ? span.getAttribute("data-section") : null;
  }

  input.addEventListener("mousemove", (e) => {
    // Skip cross-highlighting while user is dragging to select text
    if (e.buttons !== 0) return;
    if (!colorized) return;
    const sec = sectionFromPoint(e);
    if (sec) {
      applyHoverHighlight(sec);
    } else {
      clearHoverHighlight();
    }
  });

  input.addEventListener("mouseleave", clearHoverHighlight);

  function showToast(msg) {
    let toast = document.querySelector(".toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.className = "toast";
      document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 2000);
  }

  function postValidate(body) {
    return fetch(basePath + "api/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then((res) => res.json());
  }

  // Two passes over the same input. The offline one carries the whole decode
  // and every check answerable from the credential itself, so the output is on
  // screen right away. The online one adds what only a lookup at the issuer can
  // answer (the status list, and an issuer key named by metadata), which is a
  // round trip to a counterparty that can take seconds.
  function decode() {
    const text = input.value.trim();
    if (!text) {
      resetOutput();
      return;
    }

    const seq = ++decodeSeq;

    postValidate({ input: text, offline: true })
      .then((data) => {
        if (seq !== decodeSeq || renderedSeq === seq) return;
        if (data.error) {
          showDecodeError(data.error);
          return;
        }
        render(seq, data, { awaitingNetworkChecks: true });
      })
      .catch((err) => {
        if (seq === decodeSeq && renderedSeq !== seq) showError("Request failed: " + err.message);
      });

    postValidate({ input: text, checkStatus: true })
      .then((data) => {
        if (seq !== decodeSeq) return;
        if (data.error) {
          showDecodeError(data.error);
          return;
        }
        lastData = data;
        lastValidation = data.validation || null;
        if (renderedSeq === seq) {
          replaceValidationBanner(data.validation && data.validation.checks, data.deviations, {});
          return;
        }
        render(seq, data, {});
      })
      .catch(() => {
        // The network checks stay unanswered, so the banner falls back to
        // what the offline pass reported about them.
        if (seq === decodeSeq && renderedSeq === seq) {
          replaceValidationBanner(lastValidation && lastValidation.checks, lastData && lastData.deviations, {});
        }
      });
  }

  function render(seq, data, opts) {
    lastData = data;
    lastValidation = data.validation || null;
    renderedSeq = seq;
    showResult(data, opts);
    showColorized();
  }

  function showDecodeError(message) {
    showError(message);
    formatBadge.className = "badge hidden";
    lastData = null;
    lastValidation = null;
    renderedSeq = -1;
  }

  // Swaps the banner in place so the rest of the output (and which sections the
  // reader collapsed) survives the online pass landing.
  function replaceValidationBanner(checks, deviations, opts) {
    if (!checks) return;
    const existing = outputEl.querySelector(".validity-banner");
    if (!existing) return;
    existing.replaceWith(renderValidationBanner(checks, deviations, opts));
  }

  // Re-validate with a public key or trust list for signature verification
  function verifySignature(keyText, trustListURL) {
    const text = input.value.trim();
    if (!text) return;

    const body = { input: text, checkStatus: true };
    if (keyText) body.key = keyText;
    if (trustListURL) body.trustListURL = trustListURL;

    const seq = ++decodeSeq;
    postValidate(body)
      .then((data) => {
        if (seq !== decodeSeq) return;
        if (data.error) {
          showToast("Verification error: " + data.error);
          return;
        }
        render(seq, data, {});
      })
      .catch((err) => {
        showToast("Verification failed: " + err.message);
      });
  }

  // Typing waits out a pause. A paste is the whole credential at once, so it
  // decodes as soon as the value has landed.
  const TYPING_DECODE_DELAY = 300;
  const PASTE_DECODE_DELAY = 10;

  // A decode already due sooner than this one stays. A paste raises both the
  // paste event and an input event, and that pair is one decode.
  function scheduleDecode(delay) {
    const dueAt = Date.now() + delay;
    if (decodeTimer !== null && decodeDueAt <= dueAt) return;
    clearTimeout(decodeTimer);
    decodeDueAt = dueAt;
    decodeTimer = setTimeout(() => {
      decodeTimer = null;
      decode();
    }, delay);
  }

  input.addEventListener("input", () => {
    // Update colorized view immediately so it stays in sync while typing
    if (colorized) updateRawView();
    scheduleDecode(TYPING_DECODE_DELAY);
  });
  input.addEventListener("paste", () => {
    scheduleDecode(PASTE_DECODE_DELAY);
  });

  function showError(msg) {
    outputEl.innerHTML = '<div class="error">' + escapeHtml(msg) + "</div>";
  }

  // Render result
  function showResult(data, opts) {
    updateBadge(data.format);
    outputEl.innerHTML = "";

    // Issuer/subject summary line
    const summary = extractSummary(data);
    if (summary) {
      outputEl.appendChild(renderSummaryLine(summary));
    }

    // Validation banner (always from server checks now)
    if (data.validation && data.validation.checks) {
      outputEl.appendChild(renderValidationBanner(data.validation.checks, data.deviations, opts));
    }

    const fmt = data.format;

    if (fmt === "dc+sd-jwt") {
      renderSDJWT(data);
    } else if (fmt === "jwt" || fmt === "jwt_vc_json") {
      renderJWT(data);
    } else if (fmt === "mso_mdoc") {
      renderMDOC(data);
    } else {
      outputEl.appendChild(renderJSON(data));
    }
  }

  // Issuer/subject summary
  function extractSummary(data) {
    const parts = [];
    if (data.format === "mso_mdoc") {
      if (data.docType) parts.push({ label: "DocType", value: data.docType });
      // Look for issuing_authority or issuing_country in mDOC claims
      if (data.claims) {
        for (const ns of Object.keys(data.claims)) {
          const c = data.claims[ns];
          if (c.issuing_authority) parts.push({ label: "Issuer", value: String(c.issuing_authority) });
          if (c.issuing_country) parts.push({ label: "Country", value: String(c.issuing_country) });
        }
      }
    } else if (data.payload) {
      if (data.payload.iss) parts.push({ label: "Issuer", value: data.payload.iss });
      if (data.payload.sub) parts.push({ label: "Subject", value: data.payload.sub });
      if (data.payload.vct) parts.push({ label: "Type", value: data.payload.vct });
    }
    return parts.length ? parts : null;
  }

  function renderSummaryLine(parts) {
    const el = document.createElement("div");
    el.className = "issuer-summary";
    parts.forEach((p) => {
      const chip = document.createElement("span");
      chip.className = "summary-chip";
      const label = document.createElement("span");
      label.className = "summary-chip-label";
      label.textContent = p.label;
      const value = document.createElement("span");
      value.className = "summary-chip-value";
      value.textContent = p.value;
      value.title = p.value;
      chip.appendChild(label);
      chip.appendChild(value);
      el.appendChild(chip);
    });
    return el;
  }

  function updateBadge(format) {
    if (format === "dc+sd-jwt") {
      formatBadge.textContent = "SD-JWT";
      formatBadge.className = "badge sd-jwt";
    } else if (format === "jwt" || format === "jwt_vc_json") {
      formatBadge.textContent = format === "jwt_vc_json" ? "JWT VC" : "JWT";
      formatBadge.className = "badge jwt";
    } else if (format === "mso_mdoc") {
      formatBadge.textContent = "mDOC";
      formatBadge.className = "badge mdoc";
    } else {
      formatBadge.className = "badge hidden";
    }
  }

  // The verification panel: a verdict, then the checks sorted into what is
  // valid, what could not be checked, and what is a clear violation (a failed
  // check, or a structural break the parser recorded as a deviation).
  // opts.awaitingNetworkChecks means the online pass is still running, so the
  // checks it owns are shown as in flight rather than as an outcome.
  function renderValidationBanner(checks, deviations, opts) {
    const banner = document.createElement("div");
    banner.className = "validity-banner";

    checks = checks || [];
    deviations = deviations || [];
    const awaiting = !!(opts && opts.awaitingNetworkChecks);
    const isPending = (c) => awaiting && c.needsNetwork === true;
    const pending = checks.filter(isPending);

    const valid = [];
    const cantCheck = [];
    const violations = [];
    checks.forEach((c) => {
      if (isPending(c)) return;
      const item = { name: c.name, detail: c.detail };
      if (c.status === "pass") valid.push(item);
      else if (c.status === "fail") violations.push(item);
      else cantCheck.push(item); // skipped or a warning that could not resolve
    });
    deviations.forEach((d) => violations.push({ name: "structure", detail: d }));

    const sig = checks.find((c) => c.name === "signature");
    const sigValid = sig && sig.status === "pass";

    let icon, label, cls, summary;
    if (pending.length > 0) {
      icon = "\u22ef"; label = "Checking"; cls = "checking";
      summary = pending.map((c) => c.name).join(", ") + " at the issuer";
    } else if (violations.length > 0) {
      icon = "\u2717"; label = "Invalid"; cls = "expired";
      summary = violations.length === 1 ? "1 violation" : violations.length + " violations";
    } else if (sigValid) {
      icon = "\u2713"; label = "Valid"; cls = "valid";
      summary = cantCheck.length > 0 ? cantCheck.length + " not checked" : "signature verified";
    } else {
      icon = "\u26a0"; label = "Unverified"; cls = "unverified";
      summary = "signature not verified";
    }
    banner.classList.add(cls);

    let html = '<div class="verification-head">';
    html += '<span class="verification-verdict">' + icon + " " + label + "</span>";
    if (summary) html += '<span class="validity-detail">' + escapeHtml(summary) + "</span>";
    html += "</div>";

    html += '<div class="verification-groups">';
    html += verificationGroup("Violations", "vg-violations", "\u2717", violations);
    html += verificationGroup("Cannot be checked", "vg-cant", "\u2014", cantCheck);
    html += verificationGroup("Valid", "vg-valid", "\u2713", valid);
    html += "</div>";

    const verifyLabel = sigValid ? "Re-verify signature" : "Verify signature";
    html += '<details class="verify-details"><summary>' + verifyLabel + " with a key or trust list</summary>";
    html += '<div class="verify-inline">';
    html += '<label class="verify-label">Public Key (PEM or JWK)</label>';
    html += '<textarea class="verify-input verify-inline-key" rows="3" placeholder="Paste PEM or JWK..." spellcheck="false"></textarea>';
    html += '<label class="verify-label">Trust List URL</label>';
    html += '<input class="verify-input verify-inline-tl" type="text" placeholder="https://...">';
    html += '<button class="btn verify-btn verify-inline-btn">' + verifyLabel + "</button>";
    html += "</div></details>";

    banner.innerHTML = html;

    const verifyInlineBtn = banner.querySelector(".verify-inline-btn");
    const keyInput = banner.querySelector(".verify-inline-key");
    const tlInput = banner.querySelector(".verify-inline-tl");
    verifyInlineBtn.addEventListener("click", () => {
      const keyText = keyInput.value.trim();
      const tlUrl = tlInput.value.trim();
      if (!keyText && !tlUrl) {
        showToast("Provide a public key or trust list URL");
        return;
      }
      verifyInlineBtn.disabled = true;
      verifyInlineBtn.textContent = "Verifying...";
      verifySignature(keyText, tlUrl);
    });

    return banner;
  }

  function verificationGroup(title, cls, icon, items) {
    if (items.length === 0) return "";
    let h = '<div class="verification-group ' + cls + '"><div class="vg-title">' + title + "</div>";
    items.forEach((it) => {
      h += '<div class="vg-item"><span class="vg-icon">' + icon + "</span>";
      h += '<span class="vg-name">' + escapeHtml(it.name) + "</span>";
      if (it.detail) h += '<span class="vg-detail">' + escapeHtml(it.detail) + "</span>";
      h += "</div>";
    });
    return h + "</div>";
  }

  function relativeTime(date) {
    const now = Date.now();
    let diff = date.getTime() - now;
    const future = diff > 0;
    diff = Math.abs(diff);

    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    const months = Math.floor(days / 30);

    let str;
    if (months >= 2) str = months + " months";
    else if (months === 1) str = "1 month";
    else if (days >= 2) str = days + " days";
    else if (days === 1) str = "1 day";
    else if (hours >= 2) str = hours + " hours";
    else if (hours === 1) str = "1 hour";
    else if (minutes >= 2) str = minutes + " minutes";
    else str = "1 minute";

    return future ? "in " + str : str + " ago";
  }

  function renderSDJWT(data) {
    appendSection("Header", renderJSONBlock(data.header), data.header, "header");
    appendSection("Payload (signed claims)", renderJSONBlock(data.payload, { timestampKeys: TIMESTAMP_FIELDS }), data.payload, "payload");

    if (data.disclosures && data.disclosures.length > 0) {
      const disc = document.createElement("div");
      data.disclosures.forEach((d, idx) => {
        const item = document.createElement("div");
        item.className = "disclosure-item";
        item.setAttribute("data-disc-index", idx);
        // Color-code the left border to match colorized input
        const colorIdx = idx % DISC_COLORS;
        item.style.borderLeftColor = "var(--disc-color-" + colorIdx + ", var(--accent))";
        const name = d.isArrayEntry ? "(array element)" : d.name;
        const valStr = typeof d.value === "object" ? JSON.stringify(d.value) : String(d.value);
        const truncatedDigest = d.digest ? d.digest.substring(0, 16) + "\u2026" : "";
        const nameEl = document.createElement("span");
        nameEl.className = "disclosure-name";
        nameEl.textContent = name;
        item.appendChild(nameEl);
        item.appendChild(document.createTextNode(": "));
        item.appendChild(renderInlineValue(valStr, "disclosure-value", name));

        const meta = document.createElement("div");
        meta.className = "disclosure-meta";
        meta.appendChild(document.createTextNode("salt: " + d.salt + " | digest: "));
        const digest = document.createElement("span");
        digest.className = "digest-truncated";
        digest.title = d.digest;
        digest.textContent = truncatedDigest;
        meta.appendChild(digest);
        // The digest is what ties a disclosure to the signed credential. One
        // the credential never refers to discloses nothing.
        if (d.referenced === true) {
          meta.appendChild(document.createTextNode(" \u00b7 matches _sd"));
        } else if (d.referenced === false) {
          const bad = document.createElement("span");
          bad.className = "disclosure-unreferenced";
          bad.textContent = " \u00b7 NOT REFERENCED BY THE CREDENTIAL";
          meta.appendChild(bad);
        }
        item.appendChild(meta);
        disc.appendChild(item);
      });
      disc.insertBefore(
        renderNote(
          "One entry per selectively disclosable claim. The credential signs a digest of each. " +
          "Recomputing it from the salt and value is what ties the claim to the signature, and " +
          "withholding a disclosure withholds the claim without breaking it."),
        disc.firstChild);
      appendSection("Disclosures (" + data.disclosures.length + ")", disc, data.disclosures, "disclosures");

      // Bidirectional hover: disclosure items <-> colorized input spans
      disc.querySelectorAll(".disclosure-item[data-disc-index]").forEach((item) => {
        const idx = item.getAttribute("data-disc-index");
        item.addEventListener("mouseenter", () => {
          item.classList.add("highlight");
          const span = rawView.querySelector('[data-section="disc-' + idx + '"]');
          if (span) {
            span.classList.add("highlight");
            span.scrollIntoView({ behavior: "smooth", block: "nearest" });
          }
        });
        item.addEventListener("mouseleave", () => {
          item.classList.remove("highlight");
          const span = rawView.querySelector('[data-section="disc-' + idx + '"]');
          if (span) span.classList.remove("highlight");
        });
      });
    }

    // Resolved Claims with disclosed vs standard separation
    if (data.resolvedClaims) {
      const disclosedNames = new Set();
      if (data.disclosures) {
        data.disclosures.forEach((d) => {
          if (d.name) disclosedNames.add(d.name);
        });
      }
      appendSection("Resolved Claims", renderResolvedClaims(data.resolvedClaims, disclosedNames), data.resolvedClaims);
    }

    if (data.keyBindingJWT) {
      const kb = document.createElement("div");
      kb.appendChild(createSubSection("Header", renderJSONBlock(data.keyBindingJWT.header)));
      kb.appendChild(createSubSection("Payload", renderJSONBlock(data.keyBindingJWT.payload, { timestampKeys: TIMESTAMP_FIELDS })));
      appendSection("Key Binding JWT", kb, data.keyBindingJWT, "kb-jwt");
    }

    // Deviations are shown in the verification panel. These are the benign
    // structural notes that do not make the credential invalid.
    if (data.warnings && data.warnings.length > 0) {
      const w = document.createElement("div");
      data.warnings.forEach((msg) => {
        const p = document.createElement("div");
        p.style.color = "var(--yellow)";
        p.textContent = "\u26A0 " + msg;
        w.appendChild(p);
      });
      appendSection("Notes", w);
    }
  }

  function renderResolvedClaims(claims, disclosedNames) {
    const el = document.createElement("div");
    el.className = "resolved-claims-list";

    // Separate disclosed vs standard claims
    const disclosed = [];
    const standard = [];
    const keys = Object.keys(claims).sort();
    keys.forEach((k) => {
      const val = claims[k];
      const valStr = typeof val === "object" && val !== null ? JSON.stringify(val) : String(val);
      if (disclosedNames.has(k)) {
        disclosed.push({ key: k, value: valStr });
      } else {
        standard.push({ key: k, value: valStr });
      }
    });

    if (disclosed.length > 0) {
      const label = document.createElement("div");
      label.className = "resolved-group-label disclosed";
      label.textContent = "Disclosed (" + disclosed.length + ")";
      el.appendChild(label);
      disclosed.forEach((c) => {
        el.appendChild(renderClaimCard(c.key, c.value, "disclosed"));
      });
    }

    if (standard.length > 0) {
      const label = document.createElement("div");
      label.className = "resolved-group-label";
      label.textContent = "Standard (" + standard.length + ")";
      el.appendChild(label);
      standard.forEach((c) => {
        el.appendChild(renderClaimCard(c.key, c.value, "standard"));
      });
    }

    return el;
  }

  function renderClaimCard(key, value, type) {
    const item = document.createElement("div");
    item.className = "claim-item" + (type === "disclosed" ? " claim-disclosed" : "");
    const name = document.createElement("span");
    name.className = "claim-name";
    name.textContent = key;
    item.appendChild(name);
    item.appendChild(document.createTextNode(": "));
    item.appendChild(renderInlineValue(value, "claim-value", key));
    return item;
  }

  function renderJWT(data) {
    appendSection("Header", renderJSONBlock(data.header), data.header, "header");
    appendSection("Payload", renderJSONBlock(data.payload, { timestampKeys: TIMESTAMP_FIELDS }), data.payload, "payload");
  }

  // What each part of an mdoc is for. The decoder is also where people come
  // to learn the format, and "issuerAuth" says nothing on its own.
  const MDOC_NOTES = {
    structure:
      "An mdoc is CBOR, not text. issuerSigned holds what the issuer signed (the elements and the COSE_Sign1 over them). deviceSigned holds what the holder signed when presenting.",
    issuerAuth:
      "A COSE_Sign1, the CBOR counterpart of a JWT: protected header, unprotected header, payload and signature. The payload is the Mobile Security Object.",
    mso:
      "What the issuer actually signed. It carries a digest per element rather than the values, which is what lets a holder disclose some elements and withhold the rest.",
    items:
      "One entry per disclosed element. The issuer signed a digest of each. Recomputing it from the value and its salt is what proves the value was not changed.",
    deviceKey:
      "The key the credential is bound to. The holder proves possession of it when presenting, which is the same role cnf plays in an SD-JWT.",
    deviceAuth:
      "The holder's own signature over this presentation, covering the session transcript of the request it answers. A bare credential has none.",
  };

  function renderNote(text) {
    const el = document.createElement("div");
    el.className = "format-note";
    el.textContent = text;
    return el;
  }

  function renderMDOC(data) {
    const info = document.createElement("div");
    info.appendChild(renderNote(MDOC_NOTES.structure));
    info.appendChild(renderKV("DocType", data.docType));
    if (data.isDeviceResponse) {
      info.appendChild(renderKV("Container", "DeviceResponse"));
      if (data.responseVersion) info.appendChild(renderKV("version", data.responseVersion));
      if (data.responseStatus !== undefined) info.appendChild(renderKV("status", data.responseStatus));
    } else {
      info.appendChild(renderKV("Container", "IssuerSigned"));
    }
    appendSection("Document Info", info, { docType: data.docType });

    // issuerSigned.nameSpaces, as mdoc selective disclosure actually works.
    if (data.issuerSignedItems) {
      Object.keys(data.issuerSignedItems).sort().forEach((ns) => {
        const items = data.issuerSignedItems[ns];
        const el = document.createElement("div");
        el.appendChild(renderNote(MDOC_NOTES.items));
        items.forEach((item) => {
          el.appendChild(renderIssuerSignedItem(item));
        });
        appendSection("issuerSigned.nameSpaces \u2192 " + ns + " (" + items.length + " elements)", el, items);
      });
    }

    // issuerSigned.issuerAuth, broken into its COSE_Sign1 parts.
    if (data.issuerAuth) {
      const el = document.createElement("div");
      el.appendChild(renderNote(MDOC_NOTES.issuerAuth));
      el.appendChild(renderKV("Structure", data.issuerAuth.structure));
      if (data.issuerAuth.protected) {
        el.appendChild(createSubSection("protected header (signed)", renderJSONBlock(data.issuerAuth.protected)));
      }
      if (data.issuerAuth.unprotected) {
        el.appendChild(createSubSection("unprotected header (not signed)", renderJSONBlock(data.issuerAuth.unprotected)));
      }
      const payload = document.createElement("div");
      payload.appendChild(renderKV("payload", data.issuerAuth.payload + " (" + data.issuerAuth.payloadBytes + " bytes)"));
      payload.appendChild(renderKV("signature", data.issuerAuth.signatureBytes + " bytes"));
      el.appendChild(payload);
      appendSection("issuerSigned.issuerAuth (COSE_Sign1)", el, data.issuerAuth);
    }

    if (data.mso) {
      const mso = data.mso;
      const el = document.createElement("div");
      el.appendChild(renderNote(MDOC_NOTES.mso));
      // In the order ISO 18013-5 declares them: version, digestAlgorithm,
      // valueDigests, deviceKeyInfo, docType, validityInfo.
      if (mso.version) el.appendChild(renderKV("version", mso.version));
      if (mso.digestAlgorithm) el.appendChild(renderKV("digestAlgorithm", mso.digestAlgorithm));
      if (mso.valueDigests) {
        el.appendChild(createSubSection("valueDigests (one per element)", renderJSONBlock(mso.valueDigests)));
      }
      el.appendChild(renderKV("deviceKeyInfo", "shown as its own section below"));
      if (mso.docType) el.appendChild(renderKV("docType", mso.docType));
      if (mso.validityInfo) {
        const vi = mso.validityInfo;
        const validity = document.createElement("div");
        if (vi.signed) validity.appendChild(renderKV("signed", vi.signed));
        if (vi.validFrom) validity.appendChild(renderKV("validFrom", vi.validFrom));
        if (vi.validUntil) validity.appendChild(renderKV("validUntil", vi.validUntil));
        el.appendChild(createSubSection("validityInfo", validity));
      }
      if (mso.status) {
        el.appendChild(createSubSection("status", renderJSONBlock(mso.status)));
      }
      appendSection("issuerAuth.payload \u2192 Mobile Security Object", el, mso);
    }

    if (data.deviceKey) {
      const el = document.createElement("div");
      el.appendChild(renderNote(MDOC_NOTES.deviceKey));
      if (!data.deviceKey.bound) {
        el.appendChild(renderKV("Bound to a holder key", "no"));
      } else if (data.deviceKey.error) {
        el.appendChild(renderKV("Bound to a holder key", "yes"));
        el.appendChild(renderKV("Key", "unreadable: " + data.deviceKey.error));
      } else {
        el.appendChild(renderKV("Type", data.deviceKey.type + " " + data.deviceKey.curve));
        el.appendChild(renderKV("Thumbprint", data.deviceKey.thumbprint));
      }
      if (data.deviceKey.coseKey) {
        el.appendChild(createSubSection("COSE_Key", renderJSONBlock(data.deviceKey.coseKey)));
      }
      appendSection("mso.deviceKeyInfo \u2192 device key", el, data.deviceKey);
    }

    const deviceAuth = document.createElement("div");
    deviceAuth.appendChild(renderNote(MDOC_NOTES.deviceAuth));
    if (data.deviceAuth) {
      if (data.deviceAuthType) deviceAuth.appendChild(renderKV("Type", data.deviceAuthType));
      deviceAuth.appendChild(createSubSection("COSE", renderJSONBlock(data.deviceAuth)));
    } else {
      deviceAuth.appendChild(renderKV("Present", "no (this is a credential, not a presentation)"));
    }
    appendSection("deviceSigned.deviceAuth", deviceAuth, data.deviceAuth || {});
  }

  // One disclosed element: the value, and the salt and digest that make
  // withholding the others possible.
  function renderIssuerSignedItem(item) {
    const wrap = document.createElement("div");
    wrap.className = "mdoc-item";

    const head = document.createElement("div");
    head.className = "claim-item";
    const name = document.createElement("span");
    name.className = "claim-name";
    name.textContent = item.elementIdentifier;
    head.appendChild(name);
    head.appendChild(document.createTextNode(": "));
    const val = item.elementValue;
    const valStr = typeof val === "object" && val !== null ? JSON.stringify(val, null, 2) : String(val);
    head.appendChild(renderInlineValue(valStr, "claim-value", item.elementIdentifier));
    wrap.appendChild(head);

    const meta = document.createElement("div");
    meta.className = "mdoc-item-meta";
    const parts = [
      "digestID " + item.digestID,
      "salt " + item.randomBytes + " bytes",
    ];
    if (item.digestMatches === true) {
      parts.push("digest matches the MSO");
    } else if (item.digestMatches === false) {
      parts.push("DIGEST DOES NOT MATCH");
      meta.classList.add("mdoc-item-bad");
    } else if (item.digestError) {
      parts.push(item.digestError);
    }
    meta.textContent = parts.join(" \u00b7 ");
    meta.title = item.random ? "salt: " + item.random + "\ndigest: " + (item.digest || "?") : "";
    wrap.appendChild(meta);
    return wrap;
  }

  // UI helpers
  function appendSection(title, contentEl, copyData, sectionId) {
    const section = document.createElement("div");
    section.className = "section";
    if (sectionId) section.setAttribute("data-section", sectionId);

    const header = document.createElement("div");
    header.className = "section-header";

    const arrow = document.createElement("span");
    arrow.className = "arrow";
    arrow.textContent = "\u25BC";

    const titleSpan = document.createElement("span");
    titleSpan.textContent = title;

    header.appendChild(arrow);
    header.appendChild(titleSpan);

    // Copy button
    if (copyData !== undefined) {
      const copyBtn = document.createElement("button");
      copyBtn.className = "copy-btn";
      copyBtn.textContent = "Copy";
      copyBtn.title = "Copy section as JSON";
      copyBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        const text = JSON.stringify(copyData, null, 2);
        navigator.clipboard.writeText(text).then(() => {
          copyBtn.textContent = "Copied!";
          copyBtn.classList.add("copied");
          setTimeout(() => {
            copyBtn.textContent = "Copy";
            copyBtn.classList.remove("copied");
          }, 1500);
        }).catch(() => {
          showToast("Failed to copy");
        });
      });
      header.appendChild(copyBtn);
    }

    const body = document.createElement("div");
    body.className = "section-body";
    body.appendChild(contentEl);

    header.addEventListener("click", (e) => {
      if (e.target.closest(".copy-btn")) return;
      const collapsed = body.classList.toggle("collapsed");
      arrow.classList.toggle("collapsed", collapsed);
    });

    // Bidirectional hover: output section → colorized input span(s)
    if (sectionId) {
      section.addEventListener("mouseenter", () => {
        section.classList.add("highlight");
        if (sectionId === "disclosures") {
          const spans = rawView.querySelectorAll('[data-section^="disc-"]');
          spans.forEach((s) => s.classList.add("highlight"));
          if (spans.length) spans[0].scrollIntoView({ behavior: "smooth", block: "nearest" });
        } else {
          const span = rawView.querySelector('[data-section="' + sectionId + '"]');
          if (span) {
            span.classList.add("highlight");
            span.scrollIntoView({ behavior: "smooth", block: "nearest" });
          }
        }
      });
      section.addEventListener("mouseleave", () => {
        section.classList.remove("highlight");
        if (sectionId === "disclosures") {
          rawView.querySelectorAll('[data-section^="disc-"]').forEach((s) => s.classList.remove("highlight"));
        } else {
          const span = rawView.querySelector('[data-section="' + sectionId + '"]');
          if (span) span.classList.remove("highlight");
        }
      });
    }

    section.appendChild(header);
    section.appendChild(body);
    outputEl.appendChild(section);
  }

  function createSubSection(title, contentEl) {
    const wrap = document.createElement("div");
    wrap.style.margin = "6px 0";
    const label = document.createElement("div");
    label.style.color = "var(--cyan)";
    label.style.fontWeight = "600";
    label.style.marginBottom = "4px";
    label.textContent = title;
    wrap.appendChild(label);
    wrap.appendChild(contentEl);
    return wrap;
  }

  function renderKV(key, value) {
    const line = document.createElement("div");
    line.className = "json-line";
    const keyEl = document.createElement("span");
    keyEl.className = "json-key";
    keyEl.textContent = key;
    line.appendChild(keyEl);
    line.appendChild(document.createTextNode(": "));
    line.appendChild(renderInlineValue(String(value), "json-string"));
    return line;
  }

  function renderJSONBlock(obj, opts) {
    const el = document.createElement("pre");
    el.className = "json-block";
    appendJSONValue(el, obj, 0, opts || {}, null);
    return el;
  }

  function appendJSONValue(parent, value, depth, opts, currentKey) {
    if (Array.isArray(value)) {
      parent.appendChild(document.createTextNode("["));
      if (value.length > 0) {
        parent.appendChild(document.createTextNode("\n"));
        value.forEach((entry, index) => {
          parent.appendChild(document.createTextNode("  ".repeat(depth + 1)));
          appendJSONValue(parent, entry, depth + 1, opts, currentKey);
          if (index < value.length - 1) {
            parent.appendChild(document.createTextNode(","));
          }
          parent.appendChild(document.createTextNode("\n"));
        });
        parent.appendChild(document.createTextNode("  ".repeat(depth)));
      }
      parent.appendChild(document.createTextNode("]"));
      return;
    }

    if (value && typeof value === "object") {
      const entries = Object.entries(value);
      parent.appendChild(document.createTextNode("{"));
      if (entries.length > 0) {
        parent.appendChild(document.createTextNode("\n"));
        entries.forEach(([key, entry], index) => {
          parent.appendChild(document.createTextNode("  ".repeat(depth + 1)));
          appendJSONToken(parent, "json-key", JSON.stringify(key));
          parent.appendChild(document.createTextNode(": "));
          appendJSONValue(parent, entry, depth + 1, opts, key);
          if (index < entries.length - 1) {
            parent.appendChild(document.createTextNode(","));
          }
          parent.appendChild(document.createTextNode("\n"));
        });
        parent.appendChild(document.createTextNode("  ".repeat(depth)));
      }
      parent.appendChild(document.createTextNode("}"));
      return;
    }

    if (typeof value === "string") {
      parent.appendChild(createEmbeddedValueElement(value, { quoted: true }));
      return;
    }

    if (typeof value === "number") {
      const title = timestampTitle(value, currentKey, opts);
      appendJSONToken(parent, title ? "json-number timestamp-hover" : "json-number", String(value), title);
      return;
    }

    if (typeof value === "boolean") {
      appendJSONToken(parent, "json-bool", String(value));
      return;
    }

    if (value === null) {
      appendJSONToken(parent, "json-null", "null");
      return;
    }

    appendJSONToken(parent, "json-null", JSON.stringify(value));
  }

  function appendJSONToken(parent, className, text, title) {
    const span = document.createElement("span");
    span.className = className;
    span.textContent = text;
    if (title) span.title = title;
    parent.appendChild(span);
  }

  function timestampTitle(value, currentKey, opts) {
    const tsKeys = opts && opts.timestampKeys;
    if (!tsKeys || !currentKey || !tsKeys.has(currentKey)) {
      return "";
    }
    if (!Number.isFinite(value) || value <= 1000000000 || value >= 4102444800) {
      return "";
    }

    const date = new Date(value * 1000);
    const iso = date.toISOString().replace(/\.\d+Z$/, "Z");
    return iso + " (" + relativeTime(date) + ")";
  }

  function renderInlineValue(value, className, key) {
    const wrap = document.createElement("span");
    wrap.className = className;
    const title = timestampTitle(Number(value), key, { timestampKeys: TIMESTAMP_FIELDS });
    if (title) {
      wrap.className = className + " timestamp-hover";
      wrap.title = title;
    }
    if (typeof value === "string") {
      wrap.appendChild(createEmbeddedValueElement(value, { quoted: false, plainStringClass: className }));
    } else {
      wrap.textContent = String(value);
    }
    return wrap;
  }

  // A claim value can be kilobytes (a portrait is the everyday case). Showing
  // all of it buries the rest of the section and lays out one line thousands of
  // pixels wide, so the head of it stands in until asked for the rest.
  const MAX_INLINE_VALUE_CHARS = 300;

  function createEmbeddedValueElement(value, opts) {
    const quoted = !!(opts && opts.quoted);
    const token = quoted ? JSON.stringify(value) : value;
    const el = createValueToken(value, token, quoted, opts);
    if (token.length <= MAX_INLINE_VALUE_CHARS) {
      return el;
    }
    return wrapLongValue(el, token, value);
  }

  function createValueToken(value, token, quoted, opts) {
    const info = detectEmbeddedCredential(value);
    if (!info) {
      const span = document.createElement("span");
      span.className = quoted ? "json-string" : (opts && opts.plainStringClass) || "";
      span.textContent = token;
      return span;
    }

    const button = document.createElement("button");
    button.type = "button";
    button.className = "embedded-token" + (quoted ? " json-string" : "");
    button.setAttribute("data-embedded-format", info.format);
    button.title = "Open embedded " + info.label;
    button.textContent = token;
    button.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      navigateToEmbeddedCredential(value);
    });
    return button;
  }

  function wrapLongValue(el, token, value) {
    const wrap = document.createElement("span");
    wrap.className = "long-value";

    const head = token.slice(0, MAX_INLINE_VALUE_CHARS) + "…";
    el.classList.add("long-value-token");
    el.textContent = head;
    wrap.appendChild(el);

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "long-value-toggle";
    const showAll = "Show all " + token.length + " characters";
    toggle.textContent = showAll;
    let expanded = false;
    toggle.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      expanded = !expanded;
      el.textContent = expanded ? token : head;
      toggle.textContent = expanded ? "Show less" : showAll;
    });
    wrap.appendChild(toggle);

    // An image claim is the one long value a reader can actually read.
    const image = imageDataURL(value);
    if (image) {
      const img = document.createElement("img");
      img.className = "value-image";
      img.src = image;
      img.alt = "";
      img.loading = "lazy";
      wrap.appendChild(img);
    }

    return wrap;
  }

  // Only base64 data URLs, which is the form a credential carries an image in.
  const IMAGE_DATA_URL_RE = /^data:image\/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=]+$/i;

  function imageDataURL(value) {
    if (typeof value !== "string") return null;
    const text = value.trim();
    return IMAGE_DATA_URL_RE.test(text) ? text : null;
  }

  function detectEmbeddedCredential(value) {
    if (typeof value !== "string") return null;
    const text = value.trim();
    if (!text) return null;

    if (looksLikeSDJWT(text)) {
      return { format: "sd-jwt", label: "SD-JWT" };
    }
    if (looksLikeJWT(text)) {
      return { format: "jwt", label: "JWT" };
    }
    if (looksLikeMDOC(text)) {
      return { format: "mdoc", label: "mDOC" };
    }

    return null;
  }

  function looksLikeSDJWT(text) {
    if (!text.includes("~")) return false;
    return looksLikeJWT(text.split("~")[0]);
  }

  function looksLikeJWT(text) {
    const parts = text.split(".");
    if (parts.length !== 3 || !parts[0] || !parts[1]) {
      return false;
    }

    const payload = decodeBase64URL(parts[1]);
    if (!payload) {
      return false;
    }

    try {
      const parsed = JSON.parse(new TextDecoder().decode(payload));
      return !!parsed && typeof parsed === "object";
    } catch (_) {
      return false;
    }
  }

  // Real mDOC structures are at least hundreds of bytes. The length floor
  // keeps short base64url blobs (sd_hash and other 32-byte digests, whose
  // random first byte often happens to look like a CBOR marker) from being
  // rendered as clickable embedded credentials.
  const MDOC_MIN_BYTES = 64;

  function looksLikeMDOC(text) {
    if (isHexString(text)) {
      const bytes = hexToBytes(text);
      return bytes.length >= MDOC_MIN_BYTES && isCBORStart(bytes[0]);
    }

    const decoded = decodeBase64URL(text);
    return !!decoded && decoded.length >= MDOC_MIN_BYTES && isCBORStart(decoded[0]);
  }

  function isHexString(text) {
    return text.length >= 2 && text.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(text);
  }

  function hexToBytes(text) {
    const bytes = new Uint8Array(text.length / 2);
    for (let i = 0; i < text.length; i += 2) {
      bytes[i / 2] = parseInt(text.slice(i, i + 2), 16);
    }
    return bytes;
  }

  function decodeBase64URL(text) {
    if (!text) return null;
    try {
      const normalized = text.replace(/-/g, "+").replace(/_/g, "/");
      const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
      const binary = atob(normalized + padding);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    } catch (_) {
      return null;
    }
  }

  function isCBORStart(b) {
    const major = b >> 5;
    return major === 4 || major === 5 || major === 6;
  }

  // JSON syntax highlighting: strings, keys, booleans, null, numbers
  var JSON_TOKEN_RE = /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g;

  function syntaxHighlight(json) {
    if (!json) return "";
    json = escapeHtml(json);
    return json.replace(JSON_TOKEN_RE, (match) => {
      let cls = "json-number";
      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? "json-key" : "json-string";
      } else if (/true|false/.test(match)) {
        cls = "json-bool";
      } else if (/null/.test(match)) {
        cls = "json-null";
      }
      return '<span class="' + cls + '">' + match + "</span>";
    });
  }

  function renderJSON(obj) {
    return renderJSONBlock(obj);
  }

  // Escapes for both element content and quoted attribute values. A
  // textContent round-trip leaves " and ' intact, which is not enough for a
  // value that lands inside an attribute.
  function escapeHtml(str) {
    return String(str === undefined || str === null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // Pre-fill: check ?credential= query param, then /api/prefill
  function prefill(credential) {
    applyCredential(credential);
  }

  // Update keyboard shortcut hints for platform
  const isMac = navigator.platform.toUpperCase().indexOf("MAC") >= 0;
  const mod = isMac ? "\u2318" : "Ctrl";
  const hintEl = document.querySelector(".shortcut-hint .kbd-hints");
  if (hintEl) {
    hintEl.innerHTML =
      "<kbd>" + mod + "+L</kbd> Focus input &nbsp;&middot;&nbsp; " +
      "<kbd>" + mod + "+Shift+C</kbd> Copy share link &nbsp;&middot;&nbsp; " +
      "Hover timestamps for human-readable dates";
  }

  const queryParams = new URLSearchParams(window.location.search);
  const queryCredential = queryParams.get("credential");
  const queryID = queryParams.get("id");

  window.addEventListener("popstate", (event) => {
    const credential = event.state && typeof event.state.credential === "string"
      ? event.state.credential
      : (new URLSearchParams(window.location.search).get("credential") || "");
    applyCredential(credential);
  });

  // ?id= names a credential held by the wallet this decoder is mounted on,
  // which keeps a link short. Anything else is carried in the link itself.
  function loadWalletCredential(id) {
    return fetch(basePath + "api/credentials/" + encodeURIComponent(id))
      .then((res) => res.json().then((data) => ({ ok: res.ok, data })))
      .then(({ ok, data }) => {
        if (!ok || !data.credential) {
          throw new Error(data.error || "the wallet returned no credential");
        }
        walletCredential = { id: id, credential: data.credential };
        history.replaceState({ credential: data.credential }, "", buildCredentialURL(data.credential));
        prefill(data.credential);
      })
      .catch((e) => {
        outputEl.innerHTML = '<div class="placeholder">Could not load credential ' +
          escapeHtml(id) + ": " + escapeHtml(e.message) + "</div>";
      });
  }

  if (queryID) {
    loadWalletCredential(queryID);
  } else if (queryCredential) {
    history.replaceState({ credential: queryCredential }, "", buildCredentialURL(queryCredential));
    prefill(queryCredential);
  } else {
    fetch(basePath + "api/prefill")
      .then((res) => res.json())
      .then((data) => {
        if (data.credential) {
          history.replaceState({ credential: data.credential }, "", window.location.pathname);
          prefill(data.credential);
        }
      })
      .catch(() => {});
  }

  // Get the CLI modal (same behavior as the wallet UI)
  const cliOverlay = document.getElementById("cli-overlay");
  document.getElementById("get-cli-link").addEventListener("click", (event) => {
    event.preventDefault();
    cliOverlay.classList.add("active");
  });
  document.getElementById("cli-close").addEventListener("click", () => {
    cliOverlay.classList.remove("active");
  });

  // Footer: version + imprint link (basePath-relative so the /decoder mount works)
  fetch(basePath + "api/meta")
    .then((res) => res.json())
    .then((meta) => {
      if (meta.version) {
        document.getElementById("footer-version").textContent = "eudi-dev " + meta.version;
      }
      if (meta.imprint) {
        const link = document.getElementById("imprint-link");
        link.href = basePath + "imprint";
        link.hidden = false;
      }
      if (meta.wallet) {
        const walletLink = document.getElementById("wallet-link");
        // "Demo wallet" only where it is one. A decoder mounted on somebody's
        // local wallet should not call it a demo.
        walletLink.textContent = meta.demo ? "Demo wallet" : "Wallet";
        walletLink.hidden = false;
      }
      if (meta.demo) {
        document.getElementById("demo-note").hidden = false;
      }
    })
    .catch(() => {});
})();
