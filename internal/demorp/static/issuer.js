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

document.getElementById("create-btn")
  .addEventListener("click", () => createOffer(""));
// The sign-in happens later, when the wallet reaches the authorization
// endpoint, not here.
document.getElementById("create-authcode-btn")
  .addEventListener("click", () => createOffer("authorization_code"));
