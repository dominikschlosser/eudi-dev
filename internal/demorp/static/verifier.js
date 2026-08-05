// Polling is bounded on purpose: an abandoned tab used to poll a dead
// request every 1.5s forever, which dwarfed the real traffic in the
// access log. It backs off, pauses while the tab is hidden, and stops
// as soon as the request is no longer pending.
const POLL_MIN = 1500;
const POLL_MAX = 8000;
let pollTimer = null;
let pollDelay = POLL_MIN;
let pollID = null;

// Escapes for element content and quoted attribute values alike. A
// textContent round-trip leaves " and ' intact, which is not enough once
// a value lands inside an attribute.
function esc(s) {
  return String(s === undefined || s === null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderResult(doc) {
  const box = document.getElementById("result-box");
  box.style.display = "block";
  const status = document.getElementById("status");
  status.className = "status " + doc.status;
  status.textContent =
    doc.status === "verified" ? "✓ Presentation verified" :
    doc.status === "failed" ? "✗ Verification failed" + (doc.error ? ": " + doc.error : "") :
    doc.status === "expired" ? "Request expired, create a new one" :
    "Waiting for the wallet…";
  const checks = document.getElementById("checks");
  checks.innerHTML = (doc.checks || []).map((c) =>
    `<div class="${c.ok ? "ok" : "fail"}">${c.ok ? "✓" : "✗"} ${esc(c.name)}${c.error ? ": " + esc(c.error) : ""}</div>`
  ).join("");
  const claims = document.getElementById("claims");
  const label = document.getElementById("claims-label");
  if (doc.status === "verified" && doc.claims) {
    claims.innerHTML = Object.entries(doc.claims).map(([k, v]) =>
      `<tr><td>${esc(k)}</td><td>${esc(typeof v === "object" ? JSON.stringify(v) : v)}</td></tr>`
    ).join("");
    claims.hidden = false;
    label.hidden = false;
  } else {
    claims.hidden = true;
    label.hidden = true;
  }
}

function schedulePoll(id) {
  pollID = id;
  clearTimeout(pollTimer);
  pollTimer = setTimeout(() => poll(id), pollDelay);
  pollDelay = Math.min(Math.round(pollDelay * 1.4), POLL_MAX);
}

function stopPolling() {
  clearTimeout(pollTimer);
  pollID = null;
}

async function poll(id) {
  // Nobody is looking: keep the timer, skip the request.
  if (document.hidden) {
    schedulePoll(id);
    return;
  }
  try {
    const resp = await fetch("api/requests/" + id);
    if (resp.status === 404) {
      renderResult({ status: "expired" });
      stopPolling();
      return;
    }
    if (!resp.ok) {
      schedulePoll(id);
      return;
    }
    const doc = await resp.json();
    renderResult(doc);
    if (doc.status === "pending") {
      schedulePoll(id);
    } else {
      stopPolling();
    }
  } catch (e) {
    schedulePoll(id); // transient network error, try again later
  }
}

function startPolling(id) {
  pollDelay = POLL_MIN;
  pollID = id;
  poll(id);
}

// Coming back to a backgrounded tab should feel immediate again.
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && pollID) {
    pollDelay = POLL_MIN;
    clearTimeout(pollTimer);
    poll(pollID);
  }
});

// What each PID format choice asks of the wallet. The ticket only exists as
// an SD-JWT VC, so the choice applies to the PID alone.
const FORMAT_HINTS = {
  both: "The request asks for either format and the wallet answers with the one it holds.",
  "sd-jwt": "The request asks for the SD-JWT VC PID only. A wallet holding only the mdoc cannot answer it.",
  mdoc: "The request asks for the mdoc PID only. A wallet holding only the SD-JWT VC cannot answer it.",
};

let pidFormat = "both";

for (const option of document.querySelectorAll("#format-toggle .toggle-option")) {
  option.addEventListener("click", () => {
    pidFormat = option.dataset.format;
    for (const other of document.querySelectorAll("#format-toggle .toggle-option")) {
      const selected = other === option;
      other.classList.toggle("selected", selected);
      other.setAttribute("aria-checked", String(selected));
    }
    document.getElementById("format-hint").textContent = FORMAT_HINTS[pidFormat];
  });
}

for (const btn of document.querySelectorAll(".btn[data-type]")) {
  btn.addEventListener("click", async () => {
    stopPolling();
    const request = { type: btn.dataset.type };
    if (btn.dataset.type === "pid") request.format = pidFormat;
    const resp = await fetch("api/requests", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    });
    const doc = await resp.json();
    if (!resp.ok) {
      renderResult({ status: "failed", error: doc.error });
      return;
    }
    const link = document.getElementById("wallet-link");
    link.href = doc.wallet_url;
    link.textContent = doc.wallet_url;
    const scheme = document.getElementById("scheme-uri");
    scheme.textContent = doc.scheme_uri;
    scheme.href = doc.scheme_uri;
    document.getElementById("request-box").style.display = "block";
    renderResult({ status: "pending" });
    startPolling(doc.id);
  });
}

// Returning from the wallet redirect: show that request's result.
const resultID = new URLSearchParams(location.search).get("result");
if (resultID) startPolling(resultID);

// The imprint is the wallet's, and it is only served when the operator
// configured one, so the link appears only then.
fetch("../api/config")
  .then((resp) => resp.json())
  .then((config) => {
    if (config.imprint) document.getElementById("imprint-link").hidden = false;
  })
  .catch(() => {});
