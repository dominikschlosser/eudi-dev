async function createOffer(grant) {
  const errEl = document.getElementById("error");
  errEl.hidden = true;
  try {
    const query = grant ? "?grant=" + encodeURIComponent(grant) : "";
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

let grant = "";

document.querySelectorAll(".toggle-option").forEach((option) => {
  option.addEventListener("click", () => {
    grant = option.dataset.grant;
    document.querySelectorAll(".toggle-option").forEach((other) => {
      const selected = other === option;
      other.classList.toggle("selected", selected);
      other.setAttribute("aria-checked", String(selected));
    });
    document.getElementById("grant-hint").textContent = GRANT_HINTS[grant];
    // The old offer belongs to the other grant, so it would be misleading.
    document.getElementById("result").style.display = "none";
  });
});

document.getElementById("create-btn")
  .addEventListener("click", () => createOffer(grant));

// The imprint is the wallet's, and it is only served when the operator
// configured one, so the link appears only then.
fetch("../api/config")
  .then((resp) => resp.json())
  .then((config) => {
    if (config.imprint) document.getElementById("imprint-link").hidden = false;
  })
  .catch(() => {});
