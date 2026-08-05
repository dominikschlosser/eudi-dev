async function createOffer(grant, status) {
  const errEl = document.getElementById("error");
  errEl.hidden = true;
  try {
    const params = new URLSearchParams();
    if (grant) params.set("grant", grant);
    if (status) params.set("status", status);
    const query = params.toString() ? "?" + params.toString() : "";
    const resp = await fetch("api/offers" + query, { method: "POST" });
    const doc = await resp.json();
    if (!resp.ok) throw new Error(doc.error || resp.status);
    const link = document.getElementById("wallet-link");
    link.href = doc.wallet_url;
    link.textContent = doc.wallet_url;
    const scheme = document.getElementById("scheme-uri");
    scheme.textContent = doc.scheme_uri;
    scheme.href = doc.scheme_uri;
    document.getElementById("offer-uri").textContent = doc.offer_uri;
    document.getElementById("result").style.display = "block";
  } catch (e) {
    errEl.textContent = "Creating the offer failed: " + e.message;
    errEl.hidden = false;
  }
}

// What each grant means for whoever is about to redeem the offer.
const GRANT_HINTS = {
  "": "The offer carries the code, so the wallet redeems it without any sign-in.",
  authorization_code:
    "You sign in here (alice / alice) while the wallet redeems the offer. " +
    "The wallet uses PAR, PKCE, DPoP and a wallet attestation on the way. " +
    "This issuer is its own authorization server.",
};

// What a status list reference buys: without one there is nothing to revoke,
// with one the wallet can revoke the ticket and the verifier will notice.
const STATUS_HINTS = {
  "": "The ticket carries no status reference, so nothing can revoke it.",
  true:
    "The ticket references this wallet's status list. Revoke it in the wallet " +
    "UI and the demo verifier rejects the next presentation.",
};

let grant = "";
let status = "";

// Each toggle owns its own options, so the selection is scoped to the group
// the clicked option belongs to.
function bindToggle(id, key, hintID, hints, onChange) {
  const group = document.getElementById(id);
  if (!group) return;
  for (const option of group.querySelectorAll(".toggle-option")) {
    option.addEventListener("click", () => {
      onChange(option.dataset[key] || "");
      for (const other of group.querySelectorAll(".toggle-option")) {
        const selected = other === option;
        other.classList.toggle("selected", selected);
        other.setAttribute("aria-checked", String(selected));
      }
      document.getElementById(hintID).textContent = hints[option.dataset[key] || ""];
      // The old offer belongs to the other setting, so it would be misleading.
      document.getElementById("result").style.display = "none";
    });
  }
}

bindToggle("grant-toggle", "grant", "grant-hint", GRANT_HINTS, (value) => {
  grant = value;
});
bindToggle("status-toggle", "status", "status-hint", STATUS_HINTS, (value) => {
  status = value;
});

document.getElementById("create-btn")
  .addEventListener("click", () => createOffer(grant, status));

// The imprint is the wallet's, and it is only served when the operator
// configured one, so the link appears only then. The status list toggle needs
// a wallet that has a status list URL at all, which the same document reports.
fetch("../api/config")
  .then((resp) => resp.json())
  .then((config) => {
    if (config.imprint) document.getElementById("imprint-link").hidden = false;
    if (config.status_list_url) {
      document.getElementById("status-row").hidden = false;
      document.getElementById("status-hint").hidden = false;
    }
  })
  .catch(() => {});
