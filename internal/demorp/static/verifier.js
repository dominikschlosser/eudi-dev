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
  checks.innerHTML = (doc.checks || []).map((c) => {
    // A check can pass with something to say: a profile rule the presentation
    // breaks without breaking the protocol.
    if (c.ok && c.warning) {
      return `<div class="warn">! ${esc(c.name)}: ${esc(c.warning)}</div>`;
    }
    return `<div class="${c.ok ? "ok" : "fail"}">${c.ok ? "✓" : "✗"} ${esc(c.name)}${c.error ? ": " + esc(c.error) : ""}</div>`;
  }).join("");
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
  renderPresentationLink(doc.presentation);
}

// The decoder opens whatever arrived, key binding JWT or device auth
// included, which is the part a claims table cannot show. It is offered
// whether the presentation verified or not: a failed one is the interesting
// case. The presentation is not a credential in any wallet, so the link has
// to carry it rather than name it by id.
function renderPresentationLink(presentation) {
  const box = document.getElementById("presentation-box");
  const label = document.getElementById("presentation-label");
  if (!presentation) {
    box.hidden = true;
    label.hidden = true;
    return;
  }
  const link = document.getElementById("presentation-link");
  link.href = "../decoder/?credential=" + encodeURIComponent(presentation);
  box.hidden = false;
  label.hidden = false;
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
// Which credential the request asks for.
let credential = "ticket";

for (const option of document.querySelectorAll("#credential-toggle .toggle-option")) {
  option.addEventListener("click", () => {
    credential = option.dataset.credential;
    for (const other of document.querySelectorAll("#credential-toggle .toggle-option")) {
      const selected = other === option;
      other.classList.toggle("selected", selected);
      other.setAttribute("aria-checked", String(selected));
    }
    // A PID request takes a format, the custom builder takes its own panel,
    // and the ticket takes neither.
    const showsFormat = credential === "pid" || credential === "pid-de";
    document.getElementById("format-row").hidden = !showsFormat;
    document.getElementById("format-hint").hidden = !showsFormat;
    document.getElementById("custom-panel").hidden = credential !== "custom";
  });
}

// What each client id scheme does to a custom request. The x509 prefixes carry
// the signing certificate in a signed request object, the others leave it
// unsigned (OpenID4VP 1.0 §5.9).
const SCHEME_HINTS = {
  x509_hash: "The request object is signed and delivered behind request_uri.",
  x509_san_dns: "The request object is signed. The client id names a DNS SAN of the signing certificate, which must also match the response host.",
  redirect_uri: "The request is unsigned plain parameters. The client id binds to the response endpoint.",
  "pre-registered": "The request is unsigned plain parameters under a bare client id the wallet has no key for, so the wallet reports the signature as unverified.",
};

let clientIDScheme = "x509_hash";
for (const option of document.querySelectorAll("#scheme-toggle .toggle-option")) {
  option.addEventListener("click", () => {
    clientIDScheme = option.dataset.scheme;
    for (const other of document.querySelectorAll("#scheme-toggle .toggle-option")) {
      const selected = other === option;
      other.classList.toggle("selected", selected);
      other.setAttribute("aria-checked", String(selected));
    }
    document.getElementById("scheme-hint").textContent = SCHEME_HINTS[clientIDScheme];
    // Only the pre-registered scheme takes a bare client id. The others derive
    // it from the certificate or the response endpoint.
    document.getElementById("client-id-row").hidden = clientIDScheme !== "pre-registered";
  });
}

// parsePath turns a dotted path with optional array brackets into a DCQL claims
// path (OpenID4VP 1.0 §7.1): a string selects a member, [*] every array
// element (encoded as null), [n] one element by index.
function parsePath(text) {
  const path = [];
  for (const segment of text.split(".")) {
    const name = segment.replace(/\[.*$/, "").trim();
    if (name) path.push(name);
    for (const bracket of segment.match(/\[[^\]]*\]/g) || []) {
      const inner = bracket.slice(1, -1).trim();
      if (inner === "*" || inner === "") path.push(null);
      else if (/^\d+$/.test(inner)) path.push(parseInt(inner, 10));
      else path.push(inner);
    }
  }
  return path;
}

function addClaimRow(container, value) {
  const row = document.createElement("div");
  row.className = "claim-row";
  const input = document.createElement("input");
  input.type = "text";
  input.className = "claim-input";
  input.placeholder = "given_name or nationalities[*]";
  input.value = value || "";
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "btn icon small";
  remove.textContent = "×";
  remove.setAttribute("aria-label", "Remove claim");
  remove.addEventListener("click", () => row.remove());
  row.append(input, remove);
  container.append(row);
}

function addCredential(seed) {
  const list = document.getElementById("credentials-list");
  const cred = document.createElement("div");
  cred.className = "cred";

  const head = document.createElement("div");
  head.className = "cred-head";
  const toggle = document.createElement("div");
  toggle.className = "toggle format-select";
  for (const fmt of ["dc+sd-jwt", "mso_mdoc"]) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "toggle-option" + (fmt === (seed?.format || "dc+sd-jwt") ? " selected" : "");
    b.dataset.format = fmt;
    b.textContent = fmt;
    b.addEventListener("click", () => {
      for (const other of toggle.children) other.classList.toggle("selected", other === b);
      typeInput.placeholder = b.dataset.format === "mso_mdoc" ? "doctype, e.g. eu.europa.ec.eudi.pid.1" : "vct, e.g. urn:eudi:pid:1";
    });
    toggle.append(b);
  }
  const typeInput = document.createElement("input");
  typeInput.type = "text";
  typeInput.className = "type-input";
  typeInput.placeholder = (seed?.format === "mso_mdoc") ? "doctype, e.g. eu.europa.ec.eudi.pid.1" : "vct, e.g. urn:eudi:pid:1";
  typeInput.value = seed?.type || "";
  const removeCred = document.createElement("button");
  removeCred.type = "button";
  removeCred.className = "btn icon small";
  removeCred.textContent = "×";
  removeCred.setAttribute("aria-label", "Remove credential");
  removeCred.addEventListener("click", () => cred.remove());
  head.append(toggle, typeInput, removeCred);

  const claimsLabel = document.createElement("div");
  claimsLabel.className = "claims-label";
  claimsLabel.textContent = "Claims";
  const claims = document.createElement("div");
  claims.className = "claims";
  for (const c of seed?.claims || [""]) addClaimRow(claims, c);
  const addClaim = document.createElement("button");
  addClaim.type = "button";
  addClaim.className = "btn small";
  addClaim.textContent = "+ Claim";
  addClaim.addEventListener("click", () => addClaimRow(claims, ""));

  cred.append(head, claimsLabel, claims, addClaim);
  list.append(cred);
}

document.getElementById("add-credential").addEventListener("click", () => addCredential());
// Seed a PID query whose nationalities path shows the empty-array behavior.
addCredential({ format: "dc+sd-jwt", type: "urn:eudi:pid:1", claims: ["given_name", "nationalities"] });

// customRequestBody reads the builder form into the request body the API takes.
function customRequestBody() {
  const credentials = [];
  for (const cred of document.querySelectorAll("#credentials-list .cred")) {
    const format = cred.querySelector(".format-select .selected").dataset.format;
    const type = cred.querySelector(".type-input").value.trim();
    const claims = [];
    for (const input of cred.querySelectorAll(".claim-input")) {
      const path = parsePath(input.value);
      if (path.length) claims.push(path);
    }
    const entry = { format, claims };
    if (format === "mso_mdoc") entry.doctype = type;
    else entry.vct = type;
    credentials.push(entry);
  }
  const body = { type: "custom", client_id_scheme: clientIDScheme, credentials };
  if (clientIDScheme === "pre-registered") {
    const clientID = document.getElementById("client-id-input").value.trim();
    if (clientID) body.client_id = clientID;
  }
  const signingKey = document.getElementById("signing-key").value.trim();
  if (signingKey) body.signing_key = signingKey;
  const verifierInfo = document.getElementById("verifier-info").value.trim();
  if (verifierInfo) body.verifier_info = JSON.parse(verifierInfo);
  return body;
}

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

document.getElementById("create-request").addEventListener("click", async () => {
  stopPolling();
  let request;
  if (credential === "custom") {
    try {
      request = customRequestBody();
    } catch (e) {
      renderResult({ status: "failed", error: "verifier_info is not valid JSON: " + e.message });
      return;
    }
  } else {
    request = { type: credential === "ticket" ? "ticket" : "pid" };
    if (credential !== "ticket") {
      request.format = pidFormat;
    }
    if (credential === "pid-de") {
      request.vct = "urn:eudi:pid:de:1";
    }
  }
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
