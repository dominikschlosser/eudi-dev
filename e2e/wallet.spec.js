// @ts-check
const { test, expect } = require("@playwright/test");
const { execSync } = require("child_process");
const http = require("http");

const WALLET_PORT = 18924;
const WALLET_URL = `http://localhost:${WALLET_PORT}`;

// Build and start wallet server before tests
let walletProcess;

test.describe.configure({ mode: "serial" });
test.setTimeout(60_000);

test.beforeAll(async () => {
  // Cold Go builds in CI can exceed the default 30s hook timeout
  test.setTimeout(120_000);

  // Build the binary
  execSync("go build -o /tmp/oid4vc-dev-wallet-e2e ..", {
    cwd: __dirname,
  });

  // Start wallet with --pid and --auto-accept for some tests, interactive for others
  const { spawn } = require("child_process");
  walletProcess = spawn(
    "/tmp/oid4vc-dev-wallet-e2e",
    ["wallet", "serve", "--pid", "--port", String(WALLET_PORT)],
    { stdio: "pipe" }
  );

  // Wait for server to be ready
  await waitForServer(WALLET_URL, 30_000);
});

test.afterAll(async () => {
  if (walletProcess) {
    walletProcess.kill("SIGTERM");
  }
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

// Helper: make a JSON POST request
async function jsonPost(url, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const parsed = new URL(url);
    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data),
        },
      },
      (res) => {
        let body = "";
        res.on("data", (d) => (body += d));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: JSON.parse(body || "{}") })
        );
      }
    );
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

// Helper: make a GET request
async function jsonGet(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () =>
        resolve({ status: res.statusCode, body: JSON.parse(body || "{}") })
      );
      res.on("error", reject);
    });
  });
}

test.describe("Wallet Dashboard", () => {
  test("shows wallet title and credential count", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator("h1")).toHaveText("OID4VC Dev Wallet");
    await expect(page.locator("#cred-count")).toContainText("2 credentials");
  });

  test("shows PID credentials", async ({ page }) => {
    await page.goto(WALLET_URL);
    // Wait for credentials to load
    await expect(page.locator(".credential-card")).toHaveCount(2, {
      timeout: 5000,
    });

    // Check for SD-JWT credential
    const sdjwtCard = page.locator(".format-sdjwt").first();
    await expect(sdjwtCard).toBeVisible();

    // Check for mDoc credential
    const mdocCard = page.locator(".format-mdoc").first();
    await expect(mdocCard).toBeVisible();
  });

  test("displays claim tags on credential cards", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator(".credential-card")).toHaveCount(2, {
      timeout: 5000,
    });

    // Should show some claim tags
    const claimTags = page.locator(".claim-tag");
    const count = await claimTags.count();
    expect(count).toBeGreaterThan(0);
  });

  test("has theme toggle button", async ({ page }) => {
    await page.goto(WALLET_URL);
    const themeBtn = page.locator("#theme-toggle");
    await expect(themeBtn).toBeVisible();

    // Click to toggle theme
    await themeBtn.click();
    const theme = await page
      .locator("html")
      .getAttribute("data-theme");
    expect(theme).toBe("light");

    // Click again to toggle back
    await themeBtn.click();
  });

  test("has process input and button", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator("#offer-input")).toBeVisible();
    await expect(page.locator("#process-btn")).toBeVisible();
  });

  test("has import credential button", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator("#import-btn")).toBeVisible();
  });

  test("shows empty activity section", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator("#log-empty")).toBeVisible();
  });
});

test.describe("Credential Import via UI", () => {
  test("import modal opens and closes", async ({ page }) => {
    await page.goto(WALLET_URL);

    // Open import modal
    await page.locator("#import-btn").click();
    await expect(page.locator("#import-overlay")).toHaveClass(/active/);

    // Cancel closes it
    await page.locator("#import-cancel").click();
    await expect(page.locator("#import-overlay")).not.toHaveClass(/active/);
  });
});

test.describe("Credential Management API", () => {
  test("GET /api/credentials returns PID credentials", async () => {
    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    expect(res.status).toBe(200);
    expect(res.body.length).toBe(2);

    const formats = res.body.map((c) => c.format);
    expect(formats).toContain("dc+sd-jwt");
    expect(formats).toContain("mso_mdoc");
  });

  test("POST /api/credentials rejects invalid input", async () => {
    const res = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: "localhost",
          port: WALLET_PORT,
          path: "/api/credentials",
          method: "POST",
        },
        (res) => {
          let body = "";
          res.on("data", (d) => (body += d));
          res.on("end", () => resolve({ status: res.statusCode, body }));
        }
      );
      req.on("error", reject);
      req.write("not-a-credential");
      req.end();
    });

    expect(res.status).toBe(400);
  });
});

test.describe("Presentation Flow API", () => {
  test("POST /api/presentations with invalid URI returns error", async () => {
    const res = await jsonPost(`${WALLET_URL}/api/presentations`, {
      uri: "not-a-valid-uri",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });
});

test.describe("Static Files", () => {
  test("serves index.html at /", async ({ page }) => {
    const response = await page.goto(WALLET_URL);
    expect(response.status()).toBe(200);
  });

  test("serves style.css", async ({ page }) => {
    const response = await page.goto(`${WALLET_URL}/style.css`);
    expect(response.status()).toBe(200);
    const body = await response.text();
    expect(body).toContain("--bg");
  });

  test("serves app.js", async ({ page }) => {
    const response = await page.goto(`${WALLET_URL}/app.js`);
    expect(response.status()).toBe(200);
    const body = await response.text();
    expect(body).toContain("/api/credentials");
  });
});
