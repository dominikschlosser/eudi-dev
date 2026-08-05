// @ts-check
// Demo-mode consent visibility.
//
// Two rules pull in opposite directions and have broken each other twice:
//   1. A shared instance must not pop a consent dialog into every open tab.
//   2. A request that arrives without a browser redirect (a scheme dispatch,
//      which the OS handler submits through the API) must still be reachable,
//      or the flow hangs invisibly until it times out.
// These tests pin both, for presentations and for credential offers.
const { test, expect } = require("@playwright/test");
const { execSync, spawn } = require("child_process");
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PORT = 18930;
const BASE = `http://localhost:${PORT}`;

let walletProcess;

test.describe.configure({ mode: "serial" });
test.setTimeout(60_000);

test.beforeAll(async () => {
  test.setTimeout(120_000);
  execSync("go build -o /tmp/eudi-demo-e2e ..", { cwd: __dirname });

  const walletDir = fs.mkdtempSync(path.join(os.tmpdir(), "eudi-demo-e2e-"));
  walletProcess = spawn(
    "/tmp/eudi-demo-e2e",
    [
      "wallet",
      "serve",
      "--demo",
      // No periodic reset: it would clear state mid-test.
      "--demo-reset",
      "0",
      "--port",
      String(PORT),
      "--wallet-dir",
      walletDir,
      "--base-url",
      BASE,
    ],
    { stdio: "pipe" }
  );
  await waitForServer(`${BASE}/api/version`, 30_000);
});

test.afterAll(() => {
  if (walletProcess) walletProcess.kill("SIGTERM");
});

async function waitForServer(url, timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise((resolve, reject) => {
        const req = http.get(url, (res) => {
          res.resume();
          resolve(res);
        });
        req.on("error", reject);
        req.setTimeout(500, () => {
          req.destroy();
          reject(new Error("timeout"));
        });
      });
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  throw new Error(`Server at ${url} did not start within ${timeoutMs}ms`);
}

async function postJSON(pathname, body) {
  const res = await fetch(BASE + pathname, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

/** Creates a demo verifier request and returns its authorization parameters. */
async function createVerificationRequest() {
  const { body } = await postJSON("/verifier/api/requests", { type: "pid" });
  return { id: body.id, walletURL: body.wallet_url, schemeURI: body.scheme_uri };
}

/**
 * Submits a URI the way the OS URL handler does: through the API, but marked
 * interactive so it keeps the consent dialog.
 */
function submitAsSchemeHandler(pathname, uri) {
  // Deliberately not awaited: an interactive submission blocks until the
  // consent is resolved, which is what these tests are about.
  fetch(BASE + pathname, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ uri, interactive: true }),
  }).catch(() => {});
}

async function pendingCount() {
  const res = await fetch(`${BASE}/api/requests`);
  return (await res.json()).length;
}

async function waitForPending(expected) {
  for (let i = 0; i < 50; i++) {
    if ((await pendingCount()) === expected) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`expected ${expected} pending request(s)`);
}

async function clearPending() {
  const res = await fetch(`${BASE}/api/requests`);
  for (const req of await res.json()) {
    await fetch(`${BASE}/api/requests/${req.id}/deny`, { method: "POST" });
  }
  await waitForPending(0);
}

test.describe("Demo mode consent visibility", () => {
  test.afterEach(async () => {
    await clearPending();
  });

  test("a scheme-dispatched presentation shows the banner, not a dialog", async ({
    page,
  }) => {
    const req = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", req.schemeURI);
    await waitForPending(1);

    // The handler opens the UI without a request id, exactly like this.
    await page.goto(`${BASE}/?focus=overview`);

    await expect(page.locator("#pending-banner")).toBeVisible();
    await expect(page.locator("#pending-text")).toContainText("waiting for consent");
    // Rule 1: no dialog forced open in a tab that did not start the flow.
    await expect(page.locator("#consent-overlay")).not.toHaveClass(/active/);

    // Rule 2: the request is reachable.
    await page.locator("#pending-review").click();
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await expect(page.locator("#consent-approve")).toBeVisible();
  });

  test("the issuance consent dialog says what is being issued", async ({ page }) => {
    const { body: offer } = await postJSON("/issuer/api/offers", {});
    const offerDoc = await (await fetch(offer.offer_uri)).json();
    const uri = "openid-credential-offer://?credential_offer=" + encodeURIComponent(JSON.stringify(offerDoc));

    await page.goto(`${BASE}/?focus=overview&consent=await`);
    submitAsSchemeHandler("/api/offers", uri);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);

    const dialog = page.locator("#consent-dialog");
    // The issuer's own name, not just its origin.
    await expect(dialog).toContainText("EUDI Test Demo Issuer");
    await expect(page.locator("#offer-issuer-origin")).toContainText(BASE);
    // What is being issued: flow, format, display name, type and claims.
    await expect(page.locator("#offer-facts")).toContainText("pre-authorized code");
    await expect(dialog).toContainText("Demo Event Ticket");
    await expect(dialog).toContainText("urn:eudi-test:demo-ticket:1");
    for (const claim of ["event", "tier", "seat", "given_name", "family_name"]) {
      await expect(dialog.locator(".consent-claim-name", { hasText: claim })).toHaveCount(1);
    }

    await page.locator("#consent-deny").click();
    await expect(page.locator("#consent-overlay")).not.toHaveClass(/active/);
  });

  test("an offer delivered by reference is described too", async ({ page }) => {
    // The demo issuer hands out credential_offer_uri links, so this is the
    // path a visitor actually takes.
    const { body: offer } = await postJSON("/issuer/api/offers", {});
    await page.goto(`${BASE}/?focus=overview&consent=await`);
    submitAsSchemeHandler("/api/offers", offer.scheme_uri);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);

    const dialog = page.locator("#consent-dialog");
    await expect(dialog).toContainText("EUDI Test Demo Issuer");
    await expect(dialog).toContainText("Demo Event Ticket");
    await expect(dialog.locator(".consent-claim-name", { hasText: "seat" })).toHaveCount(1);
    await page.locator("#consent-deny").click();
  });

  test("a scheme-dispatched credential offer is reachable the same way", async ({
    page,
  }) => {
    const { body: offer } = await postJSON("/issuer/api/offers", {});
    submitAsSchemeHandler("/api/offers", offer.scheme_uri);
    await waitForPending(1);

    await page.goto(`${BASE}/?focus=overview`);
    await expect(page.locator("#pending-banner")).toBeVisible();
    await expect(page.locator("#consent-overlay")).not.toHaveClass(/active/);

    await page.locator("#pending-review").click();
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await expect(page.locator("#consent-dialog")).toContainText("Credential Offer");
  });

  test("the tab the scheme handler opened takes the consent directly", async ({
    page,
  }) => {
    // The handler opens the UI first and submits right after, so the request
    // can already exist by the time the page finishes loading.
    const req = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", req.schemeURI);
    await waitForPending(1);

    await page.goto(`${BASE}/?focus=overview&consent=await`);

    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await expect(page.locator("#consent-approve")).toBeVisible();
    await expect(page.locator("#pending-banner")).toBeHidden();
    // The marker is gone, so a reload or a shared link does not claim again.
    await expect(page).not.toHaveURL(/consent=/);
  });

  test("a request arriving after that tab opened is claimed too, but only one", async ({
    page,
  }) => {
    await page.goto(`${BASE}/?focus=overview&consent=await`);
    await expect(page.locator("#pending-banner")).toBeHidden();

    const first = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", first.schemeURI);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);

    await page.locator("#consent-deny").click();
    await expect(page.locator("#consent-overlay")).not.toHaveClass(/active/);

    // The claim was for that one dispatch. Anything after it is treated like
    // any other visitor's request again.
    const second = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", second.schemeURI);
    await expect(page.locator("#pending-banner")).toBeVisible();
    await expect(page.locator("#consent-overlay")).not.toHaveClass(/active/);
  });

  test("a browser-initiated request opens its own dialog", async ({ page }) => {
    const req = await createVerificationRequest();

    // A real navigation: the wallet redirects to /?request=<id>, and that tab
    // (and only that tab) shows the dialog.
    await page.goto(req.walletURL);
    await expect(page).toHaveURL(/\?request=/);
    await expect(page.locator("#consent-overlay")).toHaveClass(/active/);
    await expect(page.locator("#pending-banner")).toBeHidden();
  });

  test("another visitor's tab is not hijacked by a pending request", async ({
    browser,
  }) => {
    const starter = await browser.newPage();
    const bystander = await browser.newPage();
    await bystander.goto(BASE);

    const req = await createVerificationRequest();
    await starter.goto(req.walletURL);
    await expect(starter.locator("#consent-overlay")).toHaveClass(/active/);

    // The bystander was already open when the request arrived: it may learn
    // about it, but never through a dialog it did not ask for.
    await bystander.waitForTimeout(1500);
    await expect(bystander.locator("#consent-overlay")).not.toHaveClass(/active/);
    await expect(bystander.locator("#pending-banner")).toBeVisible();

    await starter.close();
    await bystander.close();
  });

  test("the banner disappears once nothing is pending", async ({ page }) => {
    const req = await createVerificationRequest();
    submitAsSchemeHandler("/api/presentations", req.schemeURI);
    await waitForPending(1);

    await page.goto(`${BASE}/?focus=overview`);
    await expect(page.locator("#pending-banner")).toBeVisible();

    await clearPending();
    await page.reload();
    await expect(page.locator("#pending-banner")).toBeHidden();
  });
});

test.describe("Protected baseline credentials", () => {
  test("the seeded PIDs are marked and offer no destructive actions", async ({
    page,
  }) => {
    await page.goto(BASE);
    const cards = page.locator(".credential-card[data-protected='true']");
    await expect(cards).toHaveCount(2, { timeout: 5000 });

    const first = cards.first();
    await expect(first.locator(".status-protected")).toHaveText("Protected");
    await expect(first.locator(".status-protected")).toHaveAttribute(
      "title",
      /cannot be deleted or revoked/
    );
    // No button that the server would only answer with 403.
    await expect(first.locator("[data-delete]")).toHaveCount(0);
    await expect(first.locator("[data-revoke]")).toHaveCount(0);
  });

  test("the API refuses to delete or revoke them", async () => {
    const res = await fetch(`${BASE}/api/credentials`);
    const creds = await res.json();
    const guarded = creds.find((c) => c.protected);
    expect(guarded, "expected a protected baseline credential").toBeTruthy();

    const del = await fetch(`${BASE}/api/credentials/${guarded.id}`, { method: "DELETE" });
    expect(del.status).toBe(403);

    const revoke = await fetch(`${BASE}/api/credentials/${guarded.id}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: 1 }),
    });
    expect(revoke.status).toBe(403);

    // Still there, still active.
    const after = await (await fetch(`${BASE}/api/credentials/${guarded.id}`)).json();
    expect(after.protected).toBe(true);
    expect(after.status.status).toBe(0);
  });

  test("issued credentials remain deletable and clearing keeps the baseline", async ({
    page,
  }) => {
    const issued = await postJSON("/api/issue", { format: "sdjwt", vct: "urn:example:e2e" });
    expect(issued.status).toBe(201);
    expect(issued.body.protected).toBeUndefined();

    await page.goto(BASE);
    const card = page.locator(`#credential-${issued.body.id}`);
    await expect(card).toBeVisible({ timeout: 5000 });
    await expect(card.locator("[data-delete]")).toHaveCount(1);

    const cleared = await fetch(`${BASE}/api/credentials`, { method: "DELETE" });
    expect((await cleared.json()).kept_protected).toBe(2);

    const remaining = await (await fetch(`${BASE}/api/credentials`)).json();
    expect(remaining).toHaveLength(2);
    expect(remaining.every((c) => c.protected)).toBe(true);
  });
});

test.describe("Credential paging", () => {
  test("pages through a long credential list", async ({ page }) => {
    // Start from the baseline, then add enough to need three pages.
    await fetch(`${BASE}/api/credentials`, { method: "DELETE" });
    for (let i = 0; i < 23; i++) {
      await postJSON("/api/issue", { format: "sdjwt", vct: `urn:example:page-${i}` });
    }

    await page.goto(BASE);
    const range = page.locator("#cred-range");
    await expect(page.locator(".credential-card")).toHaveCount(10, { timeout: 5000 });
    await expect(range).toHaveText("1–10 of 25");
    await expect(page.locator("#cred-prev")).toBeDisabled();

    await page.locator("#cred-next").click();
    await expect(range).toHaveText("11–20 of 25");
    await expect(page.locator(".credential-card")).toHaveCount(10);

    await page.locator("#cred-next").click();
    await expect(range).toHaveText("21–25 of 25");
    await expect(page.locator(".credential-card")).toHaveCount(5);
    await expect(page.locator("#cred-next")).toBeDisabled();

    await page.locator("#cred-prev").click();
    await expect(range).toHaveText("11–20 of 25");

    // Back to the baseline for the following tests.
    await fetch(`${BASE}/api/credentials`, { method: "DELETE" });
  });

  test("the pager stays hidden when everything fits on one page", async ({ page }) => {
    await fetch(`${BASE}/api/credentials`, { method: "DELETE" });
    await page.goto(BASE);
    await expect(page.locator(".credential-card")).toHaveCount(2, { timeout: 5000 });
    await expect(page.locator("#cred-pager")).toBeHidden();
  });
});

// The verifier page polls its request while it is pending. Two abandoned
// tabs once produced 38% of all traffic on the public demo, because the
// status endpoint never stopped saying "pending". Polling must end.
test.describe("Verifier polling", () => {
  /** Counts status polls the page makes from now on. */
  function countPolls(page) {
    const state = { n: 0 };
    page.on("request", (req) => {
      if (req.url().includes("/verifier/api/requests/")) state.n++;
    });
    return state;
  }

  test("an unknown or expired request stops the polling", async ({ page }) => {
    await page.goto(`${BASE}/verifier/?result=00000000000000000000000000000000`);
    await expect(page.locator("#status")).toHaveText(/expired/, { timeout: 10_000 });

    const polls = countPolls(page);
    await page.waitForTimeout(4000);
    expect(polls.n, "no further polls after the request is gone").toBe(0);
  });

  test("a hidden tab does not poll", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    await page.locator(".btn[data-type='pid']").click();
    await expect(page.locator("#status")).toHaveText(/Waiting/);

    // Nobody is looking at this tab any more. Chromium will not background a
    // page on command, so fake what the page reads.
    await page.evaluate(() => {
      Object.defineProperty(document, "hidden", { get: () => true });
      document.dispatchEvent(new Event("visibilitychange"));
    });

    const polls = countPolls(page);
    await page.waitForTimeout(8000);
    expect(polls.n, "a hidden tab must not keep polling").toBe(0);
  });

  test("a visible tab backs off instead of hammering", async ({ page }) => {
    await page.goto(`${BASE}/verifier/`);
    const polls = countPolls(page);
    await page.locator(".btn[data-type='pid']").click();
    await expect(page.locator("#status")).toHaveText(/Waiting/);

    // Ten seconds of the old fixed 1.5s interval was 6 polls and stayed
    // there forever. With backoff it settles well below that.
    await page.waitForTimeout(10_000);
    expect(polls.n, `polls in 10s: ${polls.n}`).toBeLessThanOrEqual(5);
    expect(polls.n, "but it must still be polling").toBeGreaterThan(0);
  });
});

// The demo is the EUDI profile, and the dialog is where a visitor finds out
// what that actually means for their verifier.
test.describe("Conformance", () => {
  test("the dialog reports what a demo instance enforces", async ({ page }) => {
    await page.goto(BASE);
    await page.locator("#conformance-link").click();
    await expect(page.locator("#conformance-overlay")).toHaveClass(/active/);

    await expect(page.locator("#conf-mode")).toHaveText("strict");
    await expect(page.locator("#conf-haip")).toHaveText("enforced");
    await expect(page.locator("#conf-haip-issuance")).toHaveText("enforced");
    await expect(page.locator("#conf-transcript")).toHaveText("oid4vp");

    // Only what is enforced is highlighted.
    await expect(page.locator("#conf-mode")).toHaveClass(/conf-on/);
    await expect(page.locator("#conf-haip-issuance")).toHaveClass(/conf-on/);
    await expect(page.locator("#conf-encrypted")).toHaveClass(/conf-off/);

    await expect(page.locator("#conf-explainer")).toContainText("signed request object");

    await page.locator("#conformance-close").click();
    await expect(page.locator("#conformance-overlay")).not.toHaveClass(/active/);
  });

  test("a request that ignores the profile is rejected", async ({ page }) => {
    const params = new URLSearchParams({
      client_id: "redirect_uri:" + BASE + "/nowhere",
      response_type: "vp_token",
      response_mode: "direct_post",
      response_uri: BASE + "/nowhere",
      nonce: "n-0S6_WzA2Mj",
      dcql_query: JSON.stringify({
        credentials: [{ id: "pid", format: "dc+sd-jwt", meta: { vct_values: ["urn:eudi:pid:1"] }, claims: [{ path: ["given_name"] }] }],
      }),
    });
    const res = await fetch(`${BASE}/authorize?${params}`);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("HAIP");
  });
});

test.describe("Demo mode hardening", () => {
  test("template writes and process control stay disabled", async () => {
    const blocked = [
      ["PUT", "/api/templates/e2e", { format: "sdjwt" }],
      ["DELETE", "/api/templates/e2e", null],
      ["POST", "/api/shutdown", null],
      ["POST", "/api/next-error", { error: "access_denied" }],
      ["PUT", "/api/config/preferred-format", { preferred_format: "dc+sd-jwt" }],
    ];
    for (const [method, pathname, body] of blocked) {
      const res = await fetch(BASE + pathname, {
        method,
        headers: body ? { "Content-Type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      expect(res.status, `${method} ${pathname}`).toBe(403);
    }
  });

  test("the UI hides what demo mode does not offer", async ({ page }) => {
    await page.goto(BASE);
    // Templates are read-only here, and the wallet is behind a TLS terminator.
    await expect(page.locator("#templates-btn")).toBeHidden();
    await expect(page.locator("#tls-cert-pem-link")).toBeHidden();
    // The shared-instance warning has to be there.
    await expect(page.locator("#demo-banner")).toBeVisible();
  });
});
