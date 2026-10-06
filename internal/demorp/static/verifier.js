// Stop polling completed requests and pause hidden tabs to limit traffic from abandoned
// pages.
const POLL_MIN = 1500;
const POLL_MAX = 8000;
let pollTimer = null;
let pollDelay = POLL_MIN;
let pollID = null;

// Escape quotes as well as markup because values also appear in attributes.
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
    // A protocol check can pass while reporting a profile warning.
    if (c.ok && c.warning) {
      return `<div class="warn">! ${esc(c.name)}: ${esc(c.warning)}</div>`;
    }
    return `<div class="${c.ok ? "ok" : "fail"}">${c.ok ? "✓" : "✗"} ${esc(c.name)}${c.error ? ": " + esc(c.error) : ""}</div>`;
  }).join("");
  const claims = document.getElementById("claims");
  const label = document.getElementById("claims-label");
  if (doc.status === "verified" && doc.claims) {
    claims.innerHTML = Object.entries(doc.claims).map(([k, v]) =>
      typeof v === "object" && v !== null
        ? `<tr><td>${esc(k)}</td><td><div class="claim-json">${esc(JSON.stringify(v, null, 2))}</div></td></tr>`
        : `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`
    ).join("");
    claims.hidden = false;
    label.hidden = false;
  } else {
    claims.hidden = true;
    label.hidden = true;
  }
  renderPresentationLink(doc.presentation);
}

// Include the complete presentation in the decoder link. It is not stored as a wallet
// credential.
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
    schedulePoll(id);
  }
}

function startPolling(id) {
  pollDelay = POLL_MIN;
  pollID = id;
  poll(id);
}

document.addEventListener("visibilitychange", () => {
  if (!document.hidden && pollID) {
    pollDelay = POLL_MIN;
    clearTimeout(pollTimer);
    poll(pollID);
  }
});

// Only PID requests offer a format choice. The demo ticket is SD-JWT only.
const FORMAT_HINTS = {
  both: "The request asks for either format and the wallet answers with the one it holds.",
  "sd-jwt": "The request asks for the SD-JWT VC PID only. A wallet holding only the mdoc cannot answer it.",
  mdoc: "The request asks for the mdoc PID only. A wallet holding only the SD-JWT VC cannot answer it.",
};

// Both shapes use DCQL credential_sets (OpenID4VP 1.0 §6.2).
const TICKET_HINTS = {
  combined: "One option asks for the SD-JWT PID and the ticket together, the others for a PID alone.",
  optional: "A required set asks for a PID. A second set asks for the ticket, and the wallet may skip it.",
};

let pidFormat = "both";
let credential = "ticket";
let ticketMode = "combined";

for (const option of document.querySelectorAll("#credential-toggle .toggle-option")) {
  option.addEventListener("click", () => {
    credential = option.dataset.credential;
    for (const other of document.querySelectorAll("#credential-toggle .toggle-option")) {
      const selected = other === option;
      other.classList.toggle("selected", selected);
      other.setAttribute("aria-checked", String(selected));
    }
    const showsFormat = credential === "pid" || credential === "pid-de" || credential === "pid-ticket";
    document.getElementById("format-row").hidden = !showsFormat;
    document.getElementById("format-hint").hidden = !showsFormat;
    document.getElementById("ticket-row").hidden = credential !== "pid-ticket";
    document.getElementById("ticket-hint").hidden = credential !== "pid-ticket";
    // A custom request sets multiple per credential.
    document.getElementById("multiple-row").hidden = credential === "custom";
    document.getElementById("custom-panel").hidden = credential !== "custom";
  });
}

// The X.509 prefixes require a signed request object (OpenID4VP 1.0 §5.9).
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
    document.getElementById("client-id-row").hidden = clientIDScheme !== "pre-registered";
  });
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
  // OpenID4VP 1.0 §6.1 multiple: the wallet may answer with several credentials.
  const multipleLabel = document.createElement("label");
  multipleLabel.className = "multiple-option";
  const multiple = document.createElement("input");
  multiple.type = "checkbox";
  multiple.className = "multiple-input";
  multiple.checked = !!seed?.multiple;
  multipleLabel.append(multiple, " multiple");
  head.append(toggle, typeInput, multipleLabel, removeCred);

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
addCredential({ format: "dc+sd-jwt", type: "urn:eudi:pid:1", claims: ["given_name", "nationalities"] });

function customRequestBody() {
  const credentials = [];
  for (const cred of document.querySelectorAll("#credentials-list .cred")) {
    const format = cred.querySelector(".format-select .selected").dataset.format;
    const type = cred.querySelector(".type-input").value.trim();
    const claims = [];
    for (const input of cred.querySelectorAll(".claim-input")) {
      const path = window.eudiParseClaimPath(input.value);
      if (path.length) claims.push(path);
    }
    const entry = { format, claims };
    if (cred.querySelector(".multiple-input").checked) entry.multiple = true;
    if (format === "mso_mdoc") entry.doctype = type;
    else entry.vct = type;
    credentials.push(entry);
  }
  const body = { type: "custom", client_id_scheme: clientIDScheme, credentials };
  if (clientIDScheme === "pre-registered") {
    const clientID = document.getElementById("client-id-input").value.trim();
    if (clientID) body.client_id = clientID;
  }
  return body;
}

document.getElementById("ticket-hint").textContent = TICKET_HINTS[ticketMode];
for (const option of document.querySelectorAll("#ticket-toggle .toggle-option")) {
  option.addEventListener("click", () => {
    ticketMode = option.dataset.ticket;
    for (const other of document.querySelectorAll("#ticket-toggle .toggle-option")) {
      const selected = other === option;
      other.classList.toggle("selected", selected);
      other.setAttribute("aria-checked", String(selected));
    }
    document.getElementById("ticket-hint").textContent = TICKET_HINTS[ticketMode];
  });
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

const IDENTITY_HINTS = {
  demo: "The request is signed with the demo verifier's access certificate and has no registration certificate.",
  registrar: "The first request registers this verifier with the wallet's registrar. The browser creates the key and sends it with each request to the demo verifier, which signs the request.",
  own: "The request is signed with your key and access certificate.",
  unsigned: "With this client identifier prefix the request is unsigned, so it can't show who the verifier is. Registrar certificates and own certificates need x509_hash or x509_san_dns.",
};
let identity = "demo";
let registration = null;

function selectIdentity(name) {
  identity = name;
  for (const other of document.querySelectorAll("#identity-toggle .toggle-option")) {
    const selected = other.dataset.identity === name;
    other.classList.toggle("selected", selected);
    other.setAttribute("aria-checked", String(selected));
  }
  document.getElementById("identity-hint").textContent = IDENTITY_HINTS[unsignedRequest() ? "unsigned" : identity];
  document.getElementById("identity-registrar-panel").hidden = identity !== "registrar";
  document.getElementById("identity-own-panel").hidden = identity !== "own";
}
for (const option of document.querySelectorAll("#identity-toggle .toggle-option")) {
  option.addEventListener("click", () => {
    if (!option.disabled) selectIdentity(option.dataset.identity);
  });
}
selectIdentity(identity);

// verifier_info needs a signed request (OpenID4VP 1.0 §5.1), so the custom
// redirect_uri and pre-registered schemes use the demo certificate only.
function unsignedRequest() {
  return credential === "custom" && (clientIDScheme === "redirect_uri" || clientIDScheme === "pre-registered");
}
function updateIdentityAvailability() {
  const unsigned = unsignedRequest();
  for (const name of ["registrar", "own"]) {
    const option = document.getElementById("identity-" + name);
    option.disabled = unsigned;
    option.title = unsigned ? "Needs a signed request (x509_hash or x509_san_dns)" : "";
  }
  selectIdentity(unsigned ? "demo" : identity);
}
for (const id of ["credential-toggle", "scheme-toggle"]) {
  document.getElementById(id).addEventListener("click", updateIdentityAvailability);
}

async function registrarCall(path, body) {
  const resp = await fetch("../api/registrar/" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify(body),
  });
  const doc = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(doc.error || "The registrar answered HTTP " + resp.status);
  return doc;
}

// Each row registers a credential type and its claims.
let registrationCredentialCount = 0;
function addRegistrationCredential(format, type, claims) {
  const n = ++registrationCredentialCount;
  const row = document.createElement("div");
  row.className = "reg-cred";
  row.id = "identity-credential-" + n;
  const select = document.createElement("select");
  select.id = row.id + "-format";
  select.setAttribute("aria-label", "Format");
  for (const [value, label] of [["dc+sd-jwt", "SD-JWT VC"], ["mso_mdoc", "mdoc"]]) {
    select.append(new Option(label, value, false, value === format));
  }
  const typeInput = document.createElement("input");
  typeInput.type = "text";
  typeInput.id = row.id + "-type";
  typeInput.className = "reg-type";
  typeInput.setAttribute("aria-label", "Credential type");
  typeInput.value = type;
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "btn small";
  remove.id = row.id + "-remove";
  remove.textContent = "Remove";
  remove.setAttribute("aria-label", "Remove this credential");
  remove.addEventListener("click", () => row.remove());
  const claimsInput = document.createElement("input");
  claimsInput.type = "text";
  claimsInput.id = row.id + "-claims";
  claimsInput.className = "reg-claims";
  claimsInput.setAttribute("aria-label", "Claims, comma separated");
  claimsInput.value = claims;
  const placeholders = () => {
    const mdoc = select.value === "mso_mdoc";
    typeInput.placeholder = mdoc ? "doctype, e.g. eu.europa.ec.eudi.pid.1" : "vct, e.g. urn:eudi:pid:1";
    claimsInput.placeholder = mdoc ? "claims, e.g. given_name, eu.europa.ec.eudi.pid.de.1:birth_name" : "claims, e.g. given_name, address.locality";
  };
  select.addEventListener("change", placeholders);
  placeholders();
  row.append(select, typeInput, remove, claimsInput);
  document.getElementById("identity-credentials").append(row);
  return row;
}
// The default rows have the same credentials and claims as the selected
// request. They follow the selection until someone edits them.
const TICKET_CLAIMS = "event, tier, seat, given_name, family_name";
function defaultRegistrationRows() {
  if (credential === "custom") {
    return [...document.querySelectorAll("#credentials-list .cred")].map((cred) => {
      const format = cred.querySelector(".format-select .selected").dataset.format;
      const claims = [...cred.querySelectorAll(".claim-input")].map((input) => input.value.trim()).filter(Boolean).map((claim) => {
        if (format !== "mso_mdoc") return claim;
        const path = window.eudiParseClaimPath(claim);
        return path.length > 1 ? path.slice(0, -1).join(".") + ":" + path[path.length - 1] : claim;
      });
      return [format, cred.querySelector(".type-input").value.trim(), claims.join(", ")];
    });
  }
  if (credential === "ticket") return [["dc+sd-jwt", "urn:eudi-test:demo-ticket:1", TICKET_CLAIMS]];
  const rows = [];
  const vct = credential === "pid-de" ? "urn:eudi:pid:de:1" : "urn:eudi:pid:1";
  if (pidFormat !== "mdoc") rows.push(["dc+sd-jwt", vct, "given_name, family_name"]);
  // Every mdoc PID has the base doctype, so a German PID request has no mdoc form.
  if (pidFormat !== "sd-jwt" && credential !== "pid-de") rows.push(["mso_mdoc", "eu.europa.ec.eudi.pid.1", "given_name, family_name"]);
  if (credential === "pid-ticket") rows.push(["dc+sd-jwt", "urn:eudi-test:demo-ticket:1", TICKET_CLAIMS]);
  return rows;
}

let registrationRowsEdited = false;
function syncRegistrationDefaults() {
  if (registrationRowsEdited) return;
  document.getElementById("identity-credentials").replaceChildren();
  registrationCredentialCount = 0;
  for (const [format, type, claims] of defaultRegistrationRows()) addRegistrationCredential(format, type, claims);
}
const registrationList = document.getElementById("identity-credentials");
registrationList.addEventListener("input", () => { registrationRowsEdited = true; });
registrationList.addEventListener("change", () => { registrationRowsEdited = true; });
registrationList.addEventListener("click", (event) => {
  if (event.target.closest("button")) registrationRowsEdited = true;
});
for (const id of ["credential-toggle", "format-toggle", "identity-toggle"]) {
  document.getElementById(id).addEventListener("click", syncRegistrationDefaults);
}
document.getElementById("custom-panel").addEventListener("input", syncRegistrationDefaults);
document.getElementById("custom-panel").addEventListener("click", syncRegistrationDefaults);
syncRegistrationDefaults();
document.getElementById("identity-add-credential").addEventListener("click", () => {
  registrationRowsEdited = true;
  addRegistrationCredential("dc+sd-jwt", "", "").querySelector(".reg-type").focus();
});

// For SD-JWT, a claim is a path with dots and brackets. For mdoc, it is the
// element name in the doctype's namespace, or namespace:element for another
// namespace.
function registrationCredentials() {
  const credentials = [];
  for (const row of document.querySelectorAll("#identity-credentials .reg-cred")) {
    const format = row.querySelector("select").value;
    const type = row.querySelector(".reg-type").value.trim();
    if (!type) continue;
    const claims = row.querySelector(".reg-claims").value.split(",").map((c) => c.trim()).filter(Boolean).map((claim) => {
      if (format !== "mso_mdoc") return { path: window.eudiParseClaimPath(claim) };
      const at = claim.lastIndexOf(":");
      return { path: at > 0 ? [claim.slice(0, at), claim.slice(at + 1)] : [type, claim] };
    });
    credentials.push({
      format,
      meta: format === "mso_mdoc" ? { doctype_value: type } : { vct_values: [type] },
      claims,
    });
  }
  return credentials;
}

// If a certificate fails, the registration is deleted again, so a retry starts
// clean.
async function register(name, purpose, credentials) {
  const { key, csr } = await window.eudiCreateKeyAndCSR();
  const rp = await registrarCall("wrp", {
    tradeName: name,
    services: [{ intendedUses: [{
      purpose: [{ lang: "en", content: purpose }],
      credentials,
    }] }],
  });
  const identifier = rp.identifier[0].identifier;
  try {
    // The DNS name lets the verifier use the x509_san_dns scheme too.
    const access = await registrarCall("access-certificates", { identifier, csr, dnsNames: [location.hostname] });
    const registrationCert = await registrarCall("registration-certificates", {
      identifier,
      intendedUseIdentifier: rp.services[0].intendedUses[0].intendedUseIdentifier,
    });
    return { identifier, signingKey: key + access.chain, verifierInfo: JSON.parse(registrationCert.verifierInfo) };
  } catch (e) {
    fetch("../api/registrar/wrp/" + encodeURIComponent(identifier), { method: "DELETE" }).catch(() => {});
    throw e;
  }
}

// Requests with the same name, purpose and rows reuse one registration, even
// after a reload in this tab. Parallel clicks share it too.
const REGISTRATION_KEY = "eudi-demo-verifier-registration";
function storedRegistration(key) {
  try {
    const stored = JSON.parse(sessionStorage.getItem(REGISTRATION_KEY) || "null");
    return stored && stored.key === key ? stored : null;
  } catch (e) {
    return null;
  }
}
let pendingRegistration = null;

async function identityFields() {
  if (identity === "own") {
    const fields = {};
    const signingKey = document.getElementById("signing-key").value.trim();
    if (!signingKey) throw new Error("Paste the signing key and access certificate chain.");
    fields.signing_key = signingKey;
    const verifierInfo = document.getElementById("verifier-info").value.trim();
    if (verifierInfo) {
      try {
        fields.verifier_info = JSON.parse(verifierInfo);
      } catch (e) {
        throw new Error("verifier_info is not valid JSON: " + e.message);
      }
    }
    return fields;
  }
  if (identity === "registrar") {
    const name = document.getElementById("identity-name").value.trim() || "Demo Verifier";
    const purpose = document.getElementById("identity-purpose").value.trim() || "Demo presentation";
    syncRegistrationDefaults();
    const credentials = registrationCredentials();
    if (credentials.length === 0) throw new Error("Add at least one credential.");
    const key = JSON.stringify([name, purpose, credentials]);
    if (!registration || registration.key !== key) registration = storedRegistration(key);
    // A demo reset or a delete in the wallet can remove the stored registration.
    if (registration) {
      const resp = await fetch("../api/registrar/wrp/" + encodeURIComponent(registration.identifier), { headers: { Accept: "application/json" } }).catch(() => null);
      if (!resp || !resp.ok) registration = null;
    }
    if (!registration) {
      if (!pendingRegistration || pendingRegistration.key !== key) {
        pendingRegistration = { key, promise: register(name, purpose, credentials) };
      }
      try {
        registration = Object.assign({ key }, await pendingRegistration.promise);
      } finally {
        pendingRegistration = null;
      }
      try { sessionStorage.setItem(REGISTRATION_KEY, JSON.stringify(registration)); } catch (e) { /* Storage may be unavailable. */ }
    }
    document.getElementById("identity-registered-id").textContent = registration.identifier;
    document.getElementById("identity-registered").hidden = false;
    return { signing_key: registration.signingKey, verifier_info: registration.verifierInfo };
  }
  return {};
}

document.getElementById("create-request").addEventListener("click", async () => {
  stopPolling();
  let request;
  if (credential === "custom") {
    request = customRequestBody();
  } else {
    request = { type: credential === "ticket" ? "ticket" : "pid" };
    if (credential !== "ticket") {
      request.format = pidFormat;
    }
    if (credential === "pid-de") {
      request.vct = "urn:eudi:pid:de:1";
    }
    if (credential === "pid-ticket") {
      request.ticket = ticketMode;
    }
    if (document.getElementById("request-multiple").checked) request.multiple = true;
  }
  try {
    Object.assign(request, await identityFields());
  } catch (e) {
    renderResult({ status: "failed", error: e.message });
    return;
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

const resultID = new URLSearchParams(location.search).get("result");
if (resultID) startPolling(resultID);

fetch("../api/config")
  .then((resp) => resp.json())
  .then((config) => {
    if (config.imprint) document.getElementById("imprint-link").hidden = false;
  })
  .catch(() => {});
