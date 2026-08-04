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
