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

  let debounceTimer = null;
  let lastData = null;
  let lastValidation = null;
  let colorized = false; // true when showing colorized view instead of textarea

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

  // Share — copy URL with ?credential= query param
  shareBtn.addEventListener("click", copyShareLink);

  function copyShareLink() {
    const text = input.value.trim();
    if (!text) return;
    const url = window.location.origin + window.location.pathname + "?credential=" + encodeURIComponent(text);
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
    hideColorized();
  }

  function buildCredentialURL(text) {
    if (!text) return window.location.pathname;
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

  // Colorized input view — overlaid behind transparent textarea
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

      // SD-JWT disclosures — each gets a unique color
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
            // KB-JWT — colorize its internal structure
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

  // Keyboard shortcuts
  document.addEventListener("keydown", (e) => {
    // Ctrl+L or Ctrl+K — focus input
    if ((e.ctrlKey || e.metaKey) && (e.key === "l" || e.key === "k")) {
      e.preventDefault();
      input.focus();
      input.select();
    }
    // Ctrl+Shift+C — copy share link (only when not in text selection)
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "C") {
      e.preventDefault();
      copyShareLink();
    }
  });

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

  // Decode — calls /api/validate to get both decode result and validation checks
  // (integrity, expiry, status run automatically; signature is skipped without key)
  function decode() {
    const text = input.value.trim();
    if (!text) {
      resetOutput();
      return;
    }

    fetch(basePath + "api/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: text, checkStatus: true }),
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.error) {
          showError(data.error);
          formatBadge.className = "badge hidden";
          lastData = null;
          lastValidation = null;
          return;
        }
        lastData = data;
        lastValidation = data.validation || null;
        showResult(data);
        showColorized();
      })
      .catch((err) => {
        showError("Request failed: " + err.message);
      });
  }

  // Re-validate with a public key or trust list for signature verification
  function verifySignature(keyText, trustListURL) {
    const text = input.value.trim();
    if (!text) return;

    const body = { input: text, checkStatus: true };
    if (keyText) body.key = keyText;
    if (trustListURL) body.trustListURL = trustListURL;

    fetch(basePath + "api/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.error) {
          showToast("Verification error: " + data.error);
          return;
        }
        lastData = data;
        lastValidation = data.validation || null;
        showResult(data);
        showColorized();
      })
      .catch((err) => {
        showToast("Verification failed: " + err.message);
      });
  }

  function scheduleDecode() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(decode, 300);
  }

  input.addEventListener("input", () => {
    // Update colorized view immediately so it stays in sync while typing
    if (colorized) updateRawView();
    scheduleDecode();
  });
  input.addEventListener("paste", () => {
    clearTimeout(debounceTimer);
    setTimeout(decode, 10);
  });

  function showError(msg) {
    outputEl.innerHTML = '<div class="error">' + escapeHtml(msg) + "</div>";
  }

  // Render result
  function showResult(data) {
    updateBadge(data.format);
    outputEl.innerHTML = "";

    // Issuer/subject summary line
    const summary = extractSummary(data);
    if (summary) {
      outputEl.appendChild(renderSummaryLine(summary));
    }

    // Validation banner (always from server checks now)
    if (data.validation && data.validation.checks) {
      outputEl.appendChild(renderValidationBanner(data.validation.checks));
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

  // Validation banner with hover checklist + clickable signature verify popover
  function renderValidationBanner(checks) {
    const banner = document.createElement("div");
    banner.className = "validity-banner";

    const hasFailure = checks.some((c) => c.status === "fail");
    const sigCheck = checks.find((c) => c.name === "signature");
    const sigSkipped = sigCheck && sigCheck.status === "skipped";
    const nonSkipped = checks.filter((c) => c.status !== "skipped");
    const allNonSkippedPass = nonSkipped.length > 0 && nonSkipped.every((c) => c.status === "pass");

    let icon, label, cls;
    if (hasFailure) {
      icon = "\u2717";
      label = "Invalid";
      cls = "expired"; // red
    } else if (sigSkipped) {
      icon = "\u26A0";
      label = "Unverified";
      cls = "unverified"; // yellow
    } else if (allNonSkippedPass) {
      icon = "\u2713";
      label = "Valid";
      cls = "valid"; // green
    } else {
      icon = "\u26A0";
      label = "Unverified";
      cls = "unverified";
    }

    banner.classList.add(cls);

    // Build summary detail from the most relevant check so the banner explains
    // what actually passed/failed instead of always defaulting to expiry.
    let detail = "";
    const firstFailed = checks.find((c) => c.status === "fail");
    const statusCheck = checks.find((c) => c.name === "status" && c.status !== "skipped");
    if (firstFailed) {
      detail = firstFailed.name + ": " + firstFailed.detail;
    } else if (statusCheck) {
      detail = "status: " + statusCheck.detail;
    } else if (sigCheck && sigCheck.status !== "skipped") {
      detail = "signature: " + sigCheck.detail;
    } else {
      const expiryCheck = checks.find((c) => c.name === "expiry" && c.status !== "skipped");
      if (expiryCheck) {
        detail = "expiry: " + expiryCheck.detail;
      } else {
        const firstRelevant = checks.find((c) => c.status !== "skipped" && c.detail);
        if (firstRelevant) {
          detail = firstRelevant.name + ": " + firstRelevant.detail;
        } else {
          const firstSkipped = checks.find((c) => c.detail);
          if (firstSkipped) {
            detail = firstSkipped.name + ": " + firstSkipped.detail;
          }
        }
      }
    }

    let html = '<span class="validity-banner-text">' + icon + " " + label;
    if (detail) {
      html += '<span class="validity-detail"> \u2014 ' + escapeHtml(detail) + "</span>";
    }
    html += "</span>";

    // Hover checklist
    html += '<div class="validity-checks">';
    checks.forEach((c) => {
      let cIcon, cCls;
      if (c.status === "pass") { cIcon = "\u2713"; cCls = "check-pass"; }
      else if (c.status === "fail") { cIcon = "\u2717"; cCls = "check-fail"; }
      else { cIcon = "\u2014"; cCls = "check-skipped"; }

      html += '<div class="validity-check-item ' + cCls + '">';
      html += '<span class="check-icon">' + cIcon + "</span>";
      html += '<span class="check-name">' + escapeHtml(c.name) + "</span>";
      html += '<span class="check-detail">' + escapeHtml(c.detail) + "</span>";
      html += "</div>";
    });

    // Always show the inline verify form so users can (re-)verify with different keys
    const verifyLabel = sigSkipped ? "Verify Signature" : "Re-verify Signature";
    html += '<div class="verify-inline-sep"></div>';
    html += '<div class="verify-inline">';
    html += '<label class="verify-label">Public Key (PEM or JWK)</label>';
    html += '<textarea class="verify-input verify-inline-key" rows="3" placeholder="Paste PEM or JWK..." spellcheck="false"></textarea>';
    html += '<label class="verify-label">Trust List URL</label>';
    html += '<input class="verify-input verify-inline-tl" type="text" placeholder="https://...">';
    html += '<button class="btn verify-btn verify-inline-btn">' + verifyLabel + '</button>';
    html += "</div>";

    html += "</div>";

    banner.innerHTML = html;

    // Wire up the inline verify button
    {
      const verifyInlineBtn = banner.querySelector(".verify-inline-btn");
      const keyInput = banner.querySelector(".verify-inline-key");
      const tlInput = banner.querySelector(".verify-inline-tl");

      // Prevent clicks on the form from closing the popover
      banner.querySelector(".validity-checks").addEventListener("click", (e) => {
        e.stopPropagation();
      });

      verifyInlineBtn.addEventListener("click", (e) => {
        e.stopPropagation();
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
    }

    // Click banner to toggle the popover open (for non-hover devices / to pin it)
    banner.addEventListener("click", () => {
      banner.classList.toggle("popover-pinned");
    });

    return banner;
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
        item.appendChild(renderInlineValue(valStr, "disclosure-value"));

        const meta = document.createElement("div");
        meta.className = "disclosure-meta";
        meta.appendChild(document.createTextNode("salt: " + d.salt + " | digest: "));
        const digest = document.createElement("span");
        digest.className = "digest-truncated";
        digest.title = d.digest;
        digest.textContent = truncatedDigest;
        meta.appendChild(digest);
        item.appendChild(meta);
        disc.appendChild(item);
      });
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

    if (data.warnings && data.warnings.length > 0) {
      const w = document.createElement("div");
      data.warnings.forEach((msg) => {
        const p = document.createElement("div");
        p.style.color = "var(--yellow)";
        p.textContent = "\u26A0 " + msg;
        w.appendChild(p);
      });
      appendSection("Warnings", w);
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
    item.appendChild(renderInlineValue(value, "claim-value"));
    return item;
  }

  function renderJWT(data) {
    appendSection("Header", renderJSONBlock(data.header), data.header, "header");
    appendSection("Payload", renderJSONBlock(data.payload, { timestampKeys: TIMESTAMP_FIELDS }), data.payload, "payload");
  }

  function renderMDOC(data) {
    const info = document.createElement("div");
    info.appendChild(renderKV("DocType", data.docType));
    appendSection("Document Info", info, { docType: data.docType });

    if (data.mso) {
      const mso = data.mso;
      const el = document.createElement("div");
      if (mso.version) el.appendChild(renderKV("Version", mso.version));
      if (mso.digestAlgorithm) el.appendChild(renderKV("Digest Algorithm", mso.digestAlgorithm));
      if (mso.validityInfo) {
        const vi = mso.validityInfo;
        if (vi.signed) el.appendChild(renderKV("Signed", vi.signed));
        if (vi.validFrom) el.appendChild(renderKV("Valid From", vi.validFrom));
        if (vi.validUntil) el.appendChild(renderKV("Valid Until", vi.validUntil));
      }
      if (mso.status) {
        el.appendChild(createSubSection("Status", renderJSONBlock(mso.status)));
      }
      appendSection("Mobile Security Object", el, mso);
    }

    if (data.claims) {
      Object.keys(data.claims).sort().forEach((ns) => {
        const claims = data.claims[ns];
        const keys = Object.keys(claims).sort();
        const el = document.createElement("div");
        keys.forEach((k) => {
          const val = claims[k];
          const valStr = typeof val === "object" && val !== null ? JSON.stringify(val, null, 2) : String(val);
          const item = document.createElement("div");
          item.className = "claim-item";
          const name = document.createElement("span");
          name.className = "claim-name";
          name.textContent = k;
          item.appendChild(name);
          item.appendChild(document.createTextNode(": "));
          item.appendChild(renderInlineValue(valStr, "claim-value"));
          el.appendChild(item);
        });
        appendSection(ns + " (" + keys.length + " claims)", el, claims);
      });
    }

    if (data.deviceAuth) {
      appendSection("Device Auth", renderJSONBlock(data.deviceAuth), data.deviceAuth);
    }
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
    if (value <= 1000000000 || value >= 4102444800) {
      return "";
    }

    const date = new Date(value * 1000);
    const iso = date.toISOString().replace(/\.\d+Z$/, "Z");
    return iso + " (" + relativeTime(date) + ")";
  }

  function renderInlineValue(value, className) {
    const wrap = document.createElement("span");
    wrap.className = className;
    if (typeof value === "string") {
      wrap.appendChild(createEmbeddedValueElement(value, { quoted: false, plainStringClass: className }));
    } else {
      wrap.textContent = String(value);
    }
    return wrap;
  }

  function createEmbeddedValueElement(value, opts) {
    const quoted = !!(opts && opts.quoted);
    const token = quoted ? JSON.stringify(value) : value;
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

  function looksLikeMDOC(text) {
    if (isHexString(text)) {
      const bytes = hexToBytes(text);
      return bytes.length > 0 && isCBORStart(bytes[0]);
    }

    const decoded = decodeBase64URL(text);
    return !!decoded && decoded.length > 0 && isCBORStart(decoded[0]);
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

  // JSON syntax highlighting regex — matches strings, keys, booleans, null, numbers
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

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  // Pre-fill: check ?credential= query param, then /api/prefill
  function prefill(credential) {
    applyCredential(credential);
  }

  // Update keyboard shortcut hints for platform
  const isMac = navigator.platform.toUpperCase().indexOf("MAC") >= 0;
  const mod = isMac ? "\u2318" : "Ctrl";
  const hintEl = document.querySelector(".shortcut-hint");
  if (hintEl) {
    hintEl.innerHTML =
      "<kbd>" + mod + "+L</kbd> Focus input &nbsp;&middot;&nbsp; " +
      "<kbd>" + mod + "+Shift+C</kbd> Copy share link &nbsp;&middot;&nbsp; " +
      "Hover timestamps for human-readable dates";
  }

  const queryCredential = new URLSearchParams(window.location.search).get("credential");

  window.addEventListener("popstate", (event) => {
    const credential = event.state && typeof event.state.credential === "string"
      ? event.state.credential
      : (new URLSearchParams(window.location.search).get("credential") || "");
    applyCredential(credential);
  });

  if (queryCredential) {
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
})();
