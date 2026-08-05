(function () {
  "use strict";

  const entriesEl = document.getElementById("entries");
  const emptyEl = document.getElementById("empty");
  const statusEl = document.getElementById("status");
  const clearBtn = document.getElementById("clear-btn");
  const themeToggle = document.getElementById("theme-toggle");
  const showAllCheckbox = document.getElementById("show-all");
  const harExportBtn = document.getElementById("har-export");
  const timelineToggle = document.getElementById("timeline-toggle");

  let entries = [];
  let showAll = false;
  let timelineView = localStorage.getItem("proxy-timeline") === "true";

  // Theme toggle
  const savedTheme = localStorage.getItem("proxy-theme") || "dark";
  if (savedTheme === "light") document.documentElement.setAttribute("data-theme", "light");

  themeToggle.addEventListener("click", function () {
    const isLight = document.documentElement.getAttribute("data-theme") === "light";
    if (isLight) {
      document.documentElement.removeAttribute("data-theme");
      localStorage.setItem("proxy-theme", "dark");
    } else {
      document.documentElement.setAttribute("data-theme", "light");
      localStorage.setItem("proxy-theme", "light");
    }
  });

  // Show all toggle
  showAllCheckbox.checked = localStorage.getItem("proxy-show-all") === "true";
  showAll = showAllCheckbox.checked;

  showAllCheckbox.addEventListener("change", function () {
    showAll = showAllCheckbox.checked;
    localStorage.setItem("proxy-show-all", showAll);
    renderEntries();
  });

  // Clear
  clearBtn.addEventListener("click", function () {
    entries = [];
    renderEntries();
  });

  // HAR export
  harExportBtn.addEventListener("click", function () {
    fetch("/api/har")
      .then(function (r) { return r.blob(); })
      .then(function (blob) {
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = "oid4vc-dev.har";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      })
      .catch(function (err) {
        console.error("Failed to export HAR:", err);
      });
  });

  // Timeline toggle
  updateTimelineButton();
  timelineToggle.addEventListener("click", function () {
    timelineView = !timelineView;
    localStorage.setItem("proxy-timeline", timelineView);
    updateTimelineButton();
    renderEntries();
  });

  function updateTimelineButton() {
    timelineToggle.textContent = timelineView ? "List" : "Timeline";
  }

  function isVisible(entry) {
    return showAll || entry.classLabel !== "Unknown";
  }

  function badgeClass(classLabel) {
    if (classLabel.startsWith("VP")) return "badge-vp";
    if (classLabel.startsWith("VCI")) return "badge-vci";
    if (classLabel.startsWith("OIDC")) return "badge-oidc";
    return "badge-unknown";
  }

  function statusClass(code) {
    if (code < 300) return "ok";
    if (code < 400) return "redirect";
    if (code < 500) return "client-error";
    return "server-error";
  }

  function formatTime(ts) {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-GB", { hour12: false });
  }

  // Escapes for both element content and quoted attribute values. A
  // textContent round-trip leaves " and ' intact, which is not enough for a
  // value that lands inside an attribute (proxied URLs do).
  function escapeHtml(s) {
    return String(s === undefined || s === null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function generateCurl(entry) {
    var parts = ["curl -X " + entry.method + " '" + entry.url + "'"];
    if (entry.requestHeaders) {
      for (var key in entry.requestHeaders) {
        if (key.toLowerCase().startsWith("x-proxy-")) continue;
        var vals = entry.requestHeaders[key];
        for (var i = 0; i < vals.length; i++) {
          parts.push("-H '" + key + ": " + vals[i] + "'");
        }
      }
    }
    if (entry.requestBody) {
      parts.push("--data-raw '" + entry.requestBody.replace(/'/g, "'\\''") + "'");
    }
    return parts.join(" \\\n  ");
  }

  function renderDecoded(decoded) {
    if (!decoded) return "";
    let html = '<div class="decoded-fields">';
    for (const [key, val] of Object.entries(decoded)) {
      html += '<span class="decoded-key">' + escapeHtml(key) + '</span>';
      if (typeof val === "object" && val !== null) {
        html += '<span class="decoded-value"><pre>' + escapeHtml(JSON.stringify(val, null, 2)) + '</pre></span>';
      } else {
        html += '<span class="decoded-value">' + escapeHtml(String(val)) + '</span>';
      }
    }
    html += "</div>";
    return html;
  }

  function renderHeaders(headers) {
    if (!headers) return "";
    let lines = [];
    for (const [key, vals] of Object.entries(headers)) {
      for (const v of vals) {
        lines.push(escapeHtml(key + ": " + v));
      }
    }
    return lines.join("\n");
  }

  function renderCredentialLinks(credentials, credentialLabels) {
    if (!credentials || credentials.length === 0) return "";
    var html = '<div class="detail-section"><h3>Credentials</h3><div class="credential-links">';
    for (var i = 0; i < credentials.length; i++) {
      var label;
      if (credentialLabels && credentialLabels[i]) {
        label = "View " + credentialLabels[i] + " in Decoder";
      } else if (credentials.length === 1) {
        label = "View in Decoder";
      } else {
        label = "View Credential " + (i + 1) + " in Decoder";
      }
      var href = "/decode/?credential=" + encodeURIComponent(credentials[i]);
      html += '<a class="btn credential-link" href="' + escapeHtml(href) + '" target="_blank">' + label + '</a>';
    }
    html += '</div></div>';
    return html;
  }

  function renderEntry(entry) {
    const el = document.createElement("div");
    el.className = "entry";
    el.dataset.id = entry.id;

    const urlPath = entry.url.length > 100 ? entry.url.substring(0, 100) + "..." : entry.url;

    el.innerHTML =
      '<div class="entry-header">' +
        '<span class="entry-time">' + formatTime(entry.timestamp) + '</span>' +
        '<span class="entry-method ' + entry.method + '">' + entry.method + '</span>' +
        '<span class="entry-url" title="' + escapeHtml(entry.url) + '">' + escapeHtml(urlPath) + '</span>' +
        '<span class="entry-status ' + statusClass(entry.statusCode) + '">' + entry.statusCode + '</span>' +
        '<span class="entry-duration">' + entry.durationMs + 'ms</span>' +
        '<span class="entry-badge ' + badgeClass(entry.classLabel) + '">' + escapeHtml(entry.classLabel) + '</span>' +
      '</div>' +
      '<div class="entry-details">' +
        '<div class="detail-actions"><button class="btn btn-copy-curl">Copy cURL</button></div>' +
        renderCredentialLinks(entry.credentials, entry.credentialLabels) +
        (entry.decoded ? '<div class="detail-section"><h3>Decoded</h3>' + renderDecoded(entry.decoded) + '</div>' : '') +
        '<div class="detail-section"><h3>Request Headers</h3><pre>' + renderHeaders(entry.requestHeaders) + '</pre></div>' +
        (entry.requestBody ? '<div class="detail-section"><h3>Request Body</h3><pre>' + escapeHtml(entry.requestBody) + '</pre></div>' : '') +
        '<div class="detail-section"><h3>Response Headers</h3><pre>' + renderHeaders(entry.responseHeaders) + '</pre></div>' +
        (entry.responseBody ? '<div class="detail-section"><h3>Response Body</h3><pre>' + escapeHtml(entry.responseBody) + '</pre></div>' : '') +
      '</div>';

    el.querySelector(".entry-header").addEventListener("click", function () {
      el.classList.toggle("expanded");
    });

    el.querySelector(".btn-copy-curl").addEventListener("click", function (e) {
      e.stopPropagation();
      var curl = generateCurl(entry);
      navigator.clipboard.writeText(curl).then(function () {
        var btn = e.target;
        btn.textContent = "Copied!";
        setTimeout(function () { btn.textContent = "Copy cURL"; }, 1500);
      });
    });

    return el;
  }

  function renderFlowTimeline(visible) {
    var flowGroups = {};
    var flowOrder = [];
    var standalone = [];

    for (var i = 0; i < visible.length; i++) {
      var entry = visible[i];
      if (entry.flowId) {
        if (!flowGroups[entry.flowId]) {
          flowGroups[entry.flowId] = [];
          flowOrder.push(entry.flowId);
        }
        flowGroups[entry.flowId].push(entry);
      } else {
        standalone.push(entry);
      }
    }

    var frag = document.createDocumentFragment();

    for (var f = 0; f < flowOrder.length; f++) {
      var flowId = flowOrder[f];
      var flowEntries = flowGroups[flowId];
      var group = document.createElement("div");
      group.className = "flow-group";

      // Determine flow type from first classified entry
      var flowType = "Flow";
      for (var j = 0; j < flowEntries.length; j++) {
        if (flowEntries[j].classLabel.startsWith("VP")) { flowType = "VP Flow"; break; }
        if (flowEntries[j].classLabel.startsWith("VCI")) { flowType = "VCI Flow"; break; }
      }

      var firstTime = formatTime(flowEntries[0].timestamp);
      var lastTime = formatTime(flowEntries[flowEntries.length - 1].timestamp);
      var timeRange = firstTime === lastTime ? firstTime : firstTime + " – " + lastTime;

      var header = document.createElement("div");
      header.className = "flow-header";
      header.innerHTML =
        '<span class="flow-type">' + escapeHtml(flowType) + '</span>' +
        '<span class="flow-time">' + escapeHtml(timeRange) + '</span>' +
        '<span class="flow-count">' + flowEntries.length + ' requests</span>' +
        '<span class="flow-toggle">▼</span>';

      var entriesContainer = document.createElement("div");
      entriesContainer.className = "flow-entries";
      for (var k = 0; k < flowEntries.length; k++) {
        entriesContainer.appendChild(renderEntry(flowEntries[k]));
      }

      header.addEventListener("click", function () {
        var g = this.parentElement;
        g.classList.toggle("collapsed");
        var toggle = this.querySelector(".flow-toggle");
        toggle.textContent = g.classList.contains("collapsed") ? "▶" : "▼";
      });

      group.appendChild(header);
      group.appendChild(entriesContainer);
      frag.appendChild(group);
    }

    for (var s = 0; s < standalone.length; s++) {
      frag.appendChild(renderEntry(standalone[s]));
    }

    return frag;
  }

  function renderEntries() {
    entriesEl.innerHTML = "";
    var visible = entries.filter(isVisible);
    if (visible.length === 0) {
      entriesEl.appendChild(emptyEl);
      emptyEl.style.display = "";
      return;
    }
    emptyEl.style.display = "none";

    if (timelineView) {
      entriesEl.appendChild(renderFlowTimeline(visible));
    } else {
      for (const entry of visible) {
        entriesEl.appendChild(renderEntry(entry));
      }
    }
    entriesEl.scrollTop = entriesEl.scrollHeight;
  }

  function addEntry(entry) {
    entries.push(entry);
    if (!isVisible(entry)) return;

    if (timelineView) {
      // Re-render to properly group
      renderEntries();
      return;
    }

    if (emptyEl.style.display !== "none") {
      emptyEl.style.display = "none";
      entriesEl.innerHTML = "";
    }
    entriesEl.appendChild(renderEntry(entry));
    entriesEl.scrollTop = entriesEl.scrollHeight;
  }

  // Load initial entries
  fetch("/api/entries")
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data && data.length > 0) {
        entries = data;
        renderEntries();
      }
    })
    .catch(function (err) {
      console.error("Failed to load entries:", err);
    });

  // SSE for live updates
  function connectSSE() {
    const es = new EventSource("/api/stream");

    es.onmessage = function (event) {
      try {
        const entry = JSON.parse(event.data);
        addEntry(entry);
      } catch (err) {
        console.error("Failed to parse SSE event:", err);
      }
    };

    es.onopen = function () {
      statusEl.textContent = "Connected";
      statusEl.className = "status";
    };

    es.onerror = function () {
      statusEl.textContent = "Disconnected";
      statusEl.className = "status disconnected";
      es.close();
      setTimeout(connectSSE, 3000);
    };
  }

  connectSSE();
})();
