// @ts-check
const { test, expect } = require("@playwright/test");
const { execSync } = require("child_process");
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");

const WALLET_PORT = 18924;
const WALLET_URL = `http://localhost:${WALLET_PORT}`;

let walletProcess;

test.describe.configure({ mode: "serial" });
test.setTimeout(60_000);

test.beforeAll(async () => {
  // Cold Go builds can exceed the default hook timeout on CI.
  test.setTimeout(120_000);

  execSync("go build -o /tmp/oid4vc-dev-wallet-e2e ..", {
    cwd: __dirname,
  });

  // Use a fresh directory so stored serving URLs cannot change the test ports.
  const { spawn } = require("child_process");
  const walletDir = fs.mkdtempSync(path.join(os.tmpdir(), "oid4vc-dev-wallet-e2e-"));
  walletProcess = spawn(
    "/tmp/oid4vc-dev-wallet-e2e",
    [
      "wallet",
      "serve",
      "--pid",
      "--port",
      String(WALLET_PORT),
      "--wallet-dir",
      walletDir,
      "--base-url",
      "https://localhost:18926",
    ],
    { stdio: "pipe" }
  );

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
  test("shows wallet title", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator("h1")).toHaveText("EUDI Dev Wallet");
  });

  test("conformance panel changes the local wallet setting via the endpoint", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    const configMode = async () =>
      (await page.evaluate(async () => (await (await fetch("/api/config")).json()).validation_mode));

    const before = await configMode();
    const target = before === "strict" ? "debug" : "strict";

    await page.click("#conformance-link");
    await expect(page.locator("#conf-mode-select")).toBeEnabled();
    await page.selectOption("#conf-mode-select", target);
    await expect.poll(configMode).toBe(target);

    const cookie = await page.evaluate(() => document.cookie);
    expect(cookie).not.toContain("eudi_conformance");

    await page.click("#conf-reset");
    await expect.poll(configMode).toBe(before);
  });

  test("shows PID credentials", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator(".credential-card")).toHaveCount(2, {
      timeout: 5000,
    });

    const sdjwtCard = page.locator(".credential-card[data-format='sdjwt']").first();
    await expect(sdjwtCard).toBeVisible();

    const mdocCard = page.locator(".credential-card[data-format='mdoc']").first();
    await expect(mdocCard).toBeVisible();
  });

  test("shows the credential facts in the card meta line", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator(".credential-card")).toHaveCount(2, {
      timeout: 5000,
    });

    const meta = page.locator(".credential-card").first().locator(".cred-meta");
    await expect(meta).toContainText("iat");
    await expect(meta).toContainText("type");
  });

  test("has theme toggle button", async ({ page }) => {
    await page.goto(WALLET_URL);
    const themeBtn = page.locator("#theme-toggle");
    await expect(themeBtn).toBeVisible();

    await themeBtn.click();
    const theme = await page
      .locator("html")
      .getAttribute("data-theme");
    expect(theme).toBe("light");

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

test.describe("Wallet loading states", () => {
  test("loads credentials and activity independently without flashing empty messages", async ({ page }) => {
    let releaseCredentials;
    let releaseActivity;
    const credentialsReady = new Promise((resolve) => { releaseCredentials = resolve; });
    const activityReady = new Promise((resolve) => { releaseActivity = resolve; });
    await page.route("**/api/credentials?*", async (route) => {
      await credentialsReady;
      await route.continue();
    });
    await page.route("**/api/log", async (route) => {
      await activityReady;
      await route.fulfill({ json: [{ time: "2026-09-13T05:00:00Z", action: "issue", detail: "Credential issued", success: true }] });
    });

    try {
      await page.goto(WALLET_URL);
      await expect(page.getByRole("status", { name: "Loading credentials" })).toBeVisible();
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeVisible();
      await expect(page.locator("#cred-empty")).toBeHidden();
      await expect(page.locator("#log-empty")).toBeHidden();

      releaseCredentials();
      await expect(page.locator(".credential-card")).toHaveCount(2);
      await expect(page.getByRole("status", { name: "Loading credentials" })).toBeHidden();
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeVisible();
      await expect(page.locator("#cred-empty")).toBeHidden();

      releaseActivity();
      await expect(page.locator(".log-entry")).toContainText("Credential issued");
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeHidden();
      await expect(page.locator("#log-empty")).toBeHidden();
    } finally {
      releaseCredentials();
      releaseActivity();
    }
  });

  test("shows empty messages only after successful empty responses", async ({ page }) => {
    let release;
    const ready = new Promise((resolve) => { release = resolve; });
    await page.route("**/api/credentials?*", async (route) => {
      await ready;
      await route.fulfill({ json: [] });
    });
    await page.route("**/api/log", async (route) => {
      await ready;
      await route.fulfill({ contentType: "application/json", body: "null" });
    });
    try {
      await page.goto(WALLET_URL);
      await expect(page.getByRole("status", { name: "Loading credentials" })).toBeVisible();
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeVisible();
      await expect(page.locator("#cred-empty")).toBeHidden();
      await expect(page.locator("#log-empty")).toBeHidden();
      release();
      await expect(page.locator("#cred-empty")).toBeVisible();
      await expect(page.locator("#log-empty")).toBeVisible();
      await expect(page.getByRole("status", { name: "Loading credentials" })).toBeHidden();
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeHidden();
    } finally {
      release();
    }
  });

  test("keeps content visible while a state event refreshes both sections", async ({ page }) => {
    let sendEvent;
    let releaseRefresh;
    const eventReady = new Promise((resolve) => { sendEvent = resolve; });
    const refreshReady = new Promise((resolve) => { releaseRefresh = resolve; });
    let refreshing = false;
    await page.route("**/api/requests/stream", async (route) => {
      await eventReady;
      await route.fulfill({ contentType: "text/event-stream", body: "event: state\ndata: {}\n\n" });
    });
    await page.route("**/api/credentials?*", async (route) => {
      if (refreshing) await refreshReady;
      await route.continue();
    });
    await page.route("**/api/log", async (route) => {
      if (refreshing) await refreshReady;
      await route.fulfill({ json: [{ time: "2026-09-13T05:00:00Z", action: "issue", detail: refreshing ? "Updated activity" : "Original activity", success: true }] });
    });
    try {
      await page.goto(WALLET_URL);
      await expect(page.locator(".credential-card")).toHaveCount(2);
      await expect(page.locator(".log-entry")).toContainText("Original activity");
      refreshing = true;
      const requests = Promise.all([
        page.waitForRequest((request) => new URL(request.url()).pathname === "/api/credentials"),
        page.waitForRequest((request) => new URL(request.url()).pathname === "/api/log"),
      ]);
      sendEvent();
      await requests;
      await expect(page.locator(".credential-card")).toHaveCount(2);
      await expect(page.locator(".log-entry")).toContainText("Original activity");
      await expect(page.getByRole("status", { name: "Loading credentials" })).toBeHidden();
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeHidden();
      releaseRefresh();
      await expect(page.locator(".log-entry")).toContainText("Updated activity");
    } finally {
      sendEvent();
      releaseRefresh();
    }
  });

  for (const failure of ["http", "network", "json"]) {
    test(`recovers from ${failure} failures through Retry`, async ({ page }) => {
      const fail = async (route) => {
        if (failure === "network") await route.abort();
        else if (failure === "json") await route.fulfill({ contentType: "application/json", body: "{" });
        else await route.fulfill({ status: 503, json: { error: "Unavailable" } });
      };
      await page.route("**/api/credentials?*", fail);
      await page.route("**/api/log", fail);
      await page.goto(WALLET_URL);
      await expect(page.getByText("Could not load credentials.")).toBeVisible();
      await expect(page.getByText("Could not load activity.")).toBeVisible();
      await expect(page.getByRole("status", { name: "Loading credentials" })).toBeHidden();
      await expect(page.getByRole("status", { name: "Loading activity" })).toBeHidden();
      await expect(page.locator("#cred-empty")).toBeHidden();
      await expect(page.locator("#log-empty")).toBeHidden();

      let release;
      const ready = new Promise((resolve) => { release = resolve; });
      const retry = async (route) => { await ready; await route.continue(); };
      await page.route("**/api/credentials?*", retry);
      await page.route("**/api/log", retry);
      try {
        await page.locator("#credentials").getByRole("button", { name: "Retry" }).click();
        await page.locator("#log").getByRole("button", { name: "Retry" }).click();
        await expect(page.getByRole("status", { name: "Loading credentials" })).toBeVisible();
        await expect(page.getByRole("status", { name: "Loading activity" })).toBeVisible();
        await expect(page.getByText("Could not load credentials.")).toBeHidden();
        await expect(page.getByText("Could not load activity.")).toBeHidden();
        release();
        await expect(page.locator(".credential-card")).toHaveCount(2);
        await expect(page.locator("#log-empty")).toBeVisible();
        await expect(page.getByRole("status", { name: "Loading credentials" })).toBeHidden();
        await expect(page.getByRole("status", { name: "Loading activity" })).toBeHidden();
      } finally {
        release();
      }
    });
  }
});

test.describe("Credential Import via UI", () => {
  test("import modal opens and closes", async ({ page }) => {
    await page.goto(WALLET_URL);

    await page.locator("#import-btn").click();
    await expect(page.locator("#import-overlay")).toHaveClass(/active/);

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

test.describe("Credential Offer Endpoint", () => {
  test("GET /credential-offer without parameters returns error", async ({
    request,
  }) => {
    const res = await request.get(`${WALLET_URL}/credential-offer`);
    expect(res.status()).toBe(400);
  });

  test("GET /credential-offer with malformed offer returns error", async ({
    request,
  }) => {
    const res = await request.get(
      `${WALLET_URL}/credential-offer?credential_offer=${encodeURIComponent(
        "not-a-credential-offer"
      )}`
    );
    expect(res.status()).toBe(400);
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

test.describe("Credential Issuing via UI", () => {
  // Clear earlier errors and consent requests so overlays cannot intercept clicks.
  test.beforeEach(async () => {
    await new Promise((resolve) => {
      const req = http.request(
        `${WALLET_URL}/api/error`,
        { method: "DELETE" },
        (res) => res.on("data", () => {}).on("end", resolve)
      );
      req.on("error", resolve);
      req.end();
    });
    const pending = await jsonGet(`${WALLET_URL}/api/requests`);
    for (const r of Array.isArray(pending.body) ? pending.body : []) {
      await jsonPost(`${WALLET_URL}/api/requests/${r.id}/deny`, {});
    }
  });

  test("issue modal opens empty with the PID template as a choice", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);

    await page.locator("#issue-btn").click();
    await expect(page.locator("#issue-overlay")).toHaveClass(/active/);

    await expect(page.locator("#issue-vct")).toHaveValue("");
    await expect(page.locator("#issue-exp")).toHaveValue("");
    await expect(page.locator("#issue-claim-rows .claim-row")).toHaveCount(1);
    await expect(page.locator("#issue-claim-key-0")).toHaveValue("");

    await expect(page.locator("#issue-doctype")).toBeHidden();
    await expect(page.locator("#issue-claim-ns-0")).toBeHidden();

    await page.locator("#issue-template").selectOption("german-pid-sdjwt");
    await expect(page.locator("#issue-vct")).toHaveValue("urn:eudi:pid:de:1");
    await expect(page.locator("#issue-exp")).toHaveValue("720h");
    await expect(page.locator("#issue-claim-rows .claim-row")).toHaveCount(14);
    const keys = await page
      .locator("#issue-claim-rows .claim-row input[id^=issue-claim-key]")
      .evaluateAll((inputs) => inputs.map((i) => i.value));
    expect(keys.sort()).toEqual([
      "academic_title",
      "address",
      "age_equal_or_over",
      "aka_vcts",
      "birth_name",
      "birthdate",
      "family_name",
      "given_name",
      "issuing_authority",
      "issuing_country",
      "nationalities",
      "place_of_birth",
      "raw_eid_birth_date",
      "source_document_type",
    ]);

    await page.locator("#issue-cancel").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);
  });

  test("fields switch with the selected format and reset on change", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();
    await page.locator("#issue-vct").fill("urn:example:leftover");

    await page.locator("#issue-format").selectOption("mdoc");
    await expect(page.locator("#issue-vct")).toBeHidden();
    await expect(page.locator("#issue-doctype")).toBeVisible();
    await expect(page.locator("#issue-claim-ns-0")).toBeVisible();

    await page.locator("#issue-template").selectOption("german-pid-mdoc");
    await expect(page.locator("#issue-doctype")).toHaveValue(
      "eu.europa.ec.eudi.pid.1"
    );

    await page.locator("#issue-format").selectOption("sdjwt");
    await expect(page.locator("#issue-vct")).toBeVisible();
    await expect(page.locator("#issue-vct")).toHaveValue("");
    await expect(page.locator("#issue-doctype")).toBeHidden();
    await expect(page.locator("#issue-claim-rows .claim-row")).toHaveCount(1);
    await expect(page.locator("#issue-claim-key-0")).toHaveValue("");

    await page.locator("#issue-cancel").click();
  });

  test("issues an mDoc with a per-attribute namespace", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();
    await page.locator("#issue-format").selectOption("mdoc");
    await page.locator("#issue-doctype").fill("org.example.e2e.doctype");

    await page.locator("#issue-claim-key-0").fill("given_name");
    await page.locator("#issue-claim-value-0").fill("Erika");
    await page.locator("#issue-add-claim").click();
    const lastRow = page.locator("#issue-claim-rows .claim-row").last();
    await lastRow
      .locator('input[id^="issue-claim-ns-"]')
      .fill("org.example.custom");
    await lastRow.locator('input[id^="issue-claim-key-"]').fill("loyalty_tier");
    await lastRow.locator('input[id^="issue-claim-value-"]').fill("gold");

    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const summary = res.body.find(
      (c) => c.doctype === "org.example.e2e.doctype"
    );
    expect(summary).toBeDefined();
    const issued = (await jsonGet(`${WALLET_URL}/api/credentials/${summary.id}`))
      .body;
    expect(issued.claims["org.example.e2e.doctype:given_name"]).toBe("Erika");
    expect(issued.claims["org.example.custom:loyalty_tier"]).toBe("gold");

    await page.goto(WALLET_URL);
    await page.locator(`#delete-${issued.id}`).click();
    await expect(page.locator(`#credential-${issued.id}`)).toHaveCount(0);
  });

  test("issues an SD-JWT credential from the PID template with an added claim", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator(".credential-card")).toHaveCount(2, {
      timeout: 5000,
    });

    await page.locator("#issue-btn").click();
    await page.locator("#issue-template").selectOption("german-pid-sdjwt");
    await expect(page.locator("#issue-vct")).toHaveValue("urn:eudi:pid:de:1");
    await page.locator("#issue-vct").fill("urn:example:e2e-test");

    await page.locator("#issue-add-claim").click();
    const lastRow = page.locator("#issue-claim-rows .claim-row").last();
    await lastRow.locator('input[id^="issue-claim-key-"]').fill("e2e_marker");
    await lastRow.locator('input[id^="issue-claim-value-"]').fill("yes");

    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);
    await expect(page.locator(".credential-card")).toHaveCount(3);
    const newCard = page.locator(".credential-card", {
      hasText: "urn:example:e2e-test",
    });
    await expect(newCard).toBeVisible();
    await expect(newCard.locator(".credential-name").first()).toHaveText(
      "German PID"
    );

    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const summary = res.body.find((c) => c.vct === "urn:example:e2e-test");
    expect(summary).toBeDefined();
    const issued = (await jsonGet(`${WALLET_URL}/api/credentials/${summary.id}`))
      .body;
    expect(issued.claims.e2e_marker).toBe("yes");
    expect(issued.claims.given_name).toBeDefined();
  });

  test("JSON mode shows the builder claims as editable JSON", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();
    await page.locator("#issue-template").selectOption("german-pid-sdjwt");

    await page.locator("#issue-claims-mode-json").check();
    await expect(page.locator("#issue-claims")).toBeVisible();
    await expect(page.locator("#issue-claim-rows")).toBeHidden();
    await expect(page.locator("#issue-add-claim")).toBeHidden();
    const json = await page.locator("#issue-claims").inputValue();
    expect(JSON.parse(json).given_name).toBeDefined();

    await page
      .locator("#issue-claims")
      .fill('{"given_name": "Changed", "answer": 42}');
    await page.locator("#issue-claims-mode-builder").check();
    await expect(page.locator("#issue-claim-rows")).toBeVisible();
    await expect(page.locator("#issue-claims")).toBeHidden();
    await expect(page.locator("#issue-claim-rows .claim-row")).toHaveCount(2);
    await expect(page.locator("#issue-claim-key-0")).toHaveValue("given_name");
    await expect(page.locator("#issue-claim-value-0")).toHaveValue("Changed");
    await expect(page.locator("#issue-claim-value-1")).toHaveValue("42");

    await page.locator("#issue-claims-mode-json").check();
    await page.locator("#issue-claims").fill("{not json");
    // Use click() because the UI restores the radio value when JSON is invalid.
    await page.locator("#issue-claims-mode-builder").click();
    await expect(page.locator("#issue-error")).toContainText(
      "Claims must be valid JSON"
    );
    await expect(page.locator("#issue-claims")).toBeVisible();
    await expect(page.locator("#issue-claims-mode-json")).toBeChecked();

    await page.locator("#issue-cancel").click();
  });

  test("shows a validation error for invalid claims JSON", async ({ page }) => {
    await page.goto(WALLET_URL);

    await page.locator("#issue-btn").click();
    await page.locator("#issue-claims-mode-json").check();
    await page.locator("#issue-claims").fill("{not json");
    await page.locator("#issue-submit").click();

    await expect(page.locator("#issue-error")).toContainText(
      "Claims must be valid JSON"
    );
    await expect(page.locator("#issue-overlay")).toHaveClass(/active/);
    await page.locator("#issue-cancel").click();
  });

  test("shows a server error for an invalid exp duration", async ({ page }) => {
    await page.goto(WALLET_URL);

    await page.locator("#issue-btn").click();
    await page.locator("#issue-exp").fill("tomorrow");
    await page.locator("#issue-submit").click();

    await expect(page.locator("#issue-error")).toContainText("exp");
    await page.locator("#issue-cancel").click();
  });

  test("deletes the issued credential via its card button", async ({ page }) => {
    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const issued = res.body.find((c) => c.vct === "urn:example:e2e-test");
    expect(issued).toBeDefined();

    await page.goto(WALLET_URL);
    await expect(page.locator(`#credential-${issued.id}`)).toBeVisible();
    await page.locator(`#delete-${issued.id}`).click();
    await expect(page.locator(`#credential-${issued.id}`)).toHaveCount(0);
    await expect(page.locator(".credential-card")).toHaveCount(2);
  });

  test("an SD-JWT with a URI claim name renders and deletes", async ({
    page,
  }) => {
    const claimName = "https://example.org/claims/role";
    const issued = await jsonPost(`${WALLET_URL}/api/issue`, {
      format: "sdjwt",
      vct: "urn:example:colon-claim",
      claims: { [claimName]: "admin", given_name: "ERIKA" },
    });
    expect(issued.status).toBe(201);

    await page.goto(WALLET_URL);
    const card = page.locator(`#credential-${issued.body.id}`);
    await expect(card).toBeVisible();
    await expect(card.locator(".credential-name")).toContainText(
      "urn:example:colon-claim"
    );

    await page.locator(`#delete-${issued.body.id}`).click();
    await expect(card).toHaveCount(0);
  });

  test("manages templates and issues from one with a non-disclosable claim", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);

    await page.locator("#templates-btn").click();
    await expect(page.locator("#templates-overlay")).toHaveClass(/active/);
    await expect(
      page.locator(".template-row-name", { hasText: "german-pid-sdjwt" })
    ).toBeVisible();

    await page.locator("#template-name").fill("e2e-employee");
    await page.locator("#template-json").fill(
      JSON.stringify({
        format: "sdjwt",
        vct: "urn:example:e2e-employee",
        claims: { employee_id: "E-1", department: "IT" },
        always_disclosed: ["department"],
      })
    );
    await page.locator("#template-save").click();
    await expect(
      page.locator(".template-row-name", { hasText: "e2e-employee" })
    ).toBeVisible();
    await page.locator("#template-close").click();

    await page.locator("#issue-btn").click();
    await page.locator("#issue-template").selectOption("e2e-employee");
    await expect(page.locator("#issue-vct")).toHaveValue(
      "urn:example:e2e-employee"
    );
    await expect(page.locator("#issue-always-disclosed")).toHaveValue(
      "department"
    );
    // Read input properties through evaluate. The form sets properties rather than
    // attributes.
    const sdStates = await page.evaluate(() => {
      const states = {};
      document
        .querySelectorAll("#issue-claim-rows .claim-row")
        .forEach((row) => {
          const key = row.querySelector('input[id^="issue-claim-key-"]').value;
          const sd = row.querySelector('input[id^="issue-claim-sd-"]').checked;
          states[key] = sd;
        });
      return states;
    });
    expect(sdStates.department).toBe(false);
    expect(sdStates.employee_id).toBe(true);

    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const summary = res.body.find((c) => c.vct === "urn:example:e2e-employee");
    expect(summary).toBeDefined();
    const issued = (await jsonGet(`${WALLET_URL}/api/credentials/${summary.id}`))
      .body;
    expect(issued.claims.department).toBe("IT");
    expect(issued.claims.employee_id).toBe("E-1");
    const payload = JSON.parse(
      Buffer.from(issued.raw.split(".")[1], "base64url").toString()
    );
    expect(payload.department).toBe("IT");
    expect(payload.employee_id).toBeUndefined();

    await page.goto(WALLET_URL);
    await page.locator(`#delete-${issued.id}`).click();
    await expect(page.locator(`#credential-${issued.id}`)).toHaveCount(0);

    await page.locator("#templates-btn").click();
    const templateRow = page
      .locator(".template-row")
      .filter({ hasText: "e2e-employee" });
    await templateRow.locator("button", { hasText: "Delete" }).click();
    await expect(
      page.locator(".template-row-name", { hasText: "e2e-employee" })
    ).toHaveCount(0);
    await page.locator("#template-close").click();
  });

  test("saves the issue dialog contents as a template", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();

    await page.locator("#issue-vct").fill("urn:example:e2e-saved");
    await page.locator("#issue-claim-key-0").fill("member_id");
    await page.locator("#issue-claim-value-0").fill("M-1");
    await page.locator("#issue-save-template").fill("e2e-saved-template");

    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    const tplRes = await jsonGet(
      `${WALLET_URL}/api/templates/e2e-saved-template`
    );
    expect(tplRes.body.vct).toBe("urn:example:e2e-saved");
    expect(tplRes.body.claims.member_id).toBe("M-1");

    // Clean up through the API because pagination may hide the credential delete button.
    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const issued = res.body.find((c) => c.vct === "urn:example:e2e-saved");
    expect(issued).toBeDefined();
    await fetch(`${WALLET_URL}/api/credentials/${issued.id}`, {
      method: "DELETE",
    });
    await fetch(`${WALLET_URL}/api/templates/e2e-saved-template`, {
      method: "DELETE",
    });
  });

  test("sets display values on the issued credential", async ({ page }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();
    await page.locator("#issue-vct").fill("urn:example:e2e-display");
    await page.locator("#issue-display-name").fill("E2E Badge");
    await page.locator("#issue-bg-color").fill("#0f766e");
    await page.locator("#issue-text-color").fill("#ffffff");
    await expect(page.locator("#issue-bg-color-picker")).toHaveValue("#0f766e");

    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const issued = res.body.find((c) => c.vct === "urn:example:e2e-display");
    expect(issued).toBeDefined();
    expect(issued.display.name).toBe("E2E Badge");
    expect(issued.display.background_color).toBe("#0f766e");
    expect(issued.display.text_color).toBe("#ffffff");

    await fetch(`${WALLET_URL}/api/credentials/${issued.id}`, {
      method: "DELETE",
    });
  });

  test("reveals the description behind an About control, only when there is one", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();
    await page.locator("#issue-vct").fill("urn:example:e2e-desc");
    await page.locator("#issue-display-name").fill("Described Badge");
    await page
      .locator("#issue-display-description")
      .fill("A sample description shown behind About.");
    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    await page.locator("#issue-btn").click();
    await page.locator("#issue-vct").fill("urn:example:e2e-nodesc");
    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    const described = page.locator(
      '.credential-card[data-vct="urn:example:e2e-desc"]',
    );
    const plain = page.locator(
      '.credential-card[data-vct="urn:example:e2e-nodesc"]',
    );
    await expect(described.locator(".about-btn")).toHaveCount(1);
    await expect(plain.locator(".about-btn")).toHaveCount(0);

    await expect(described).not.toHaveClass(/desc-open/);
    await described.locator(".about-btn").click();
    await expect(described).toHaveClass(/desc-open/);
    await expect(described.locator(".cred-desc-body")).toContainText(
      "A sample description",
    );
    await described.locator(".about-btn").click();
    await expect(described).not.toHaveClass(/desc-open/);

    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    for (const vct of ["urn:example:e2e-desc", "urn:example:e2e-nodesc"]) {
      const c = res.body.find((x) => x.vct === vct);
      if (c) await fetch(`${WALLET_URL}/api/credentials/${c.id}`, { method: "DELETE" });
    }
  });

  test("shows status badges and revokes and re-activates a credential", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator(".credential-card")).toHaveCount(2);

    const card = page.locator('.credential-card[data-format="sdjwt"]').first();
    const id = await card.getAttribute("data-credential-id");
    await expect(card).toHaveAttribute("data-status", "active");
    await expect(page.locator(`#status-${id}`)).toHaveText("Active");
    await expect(page.locator(`#revoke-${id}`)).toHaveText("Revoke");

    await page.locator(`#revoke-${id}`).click();
    await expect(page.locator(`#status-${id}`)).toHaveText("Revoked");
    await expect(page.locator(`#credential-${id}`)).toHaveAttribute(
      "data-status",
      "revoked"
    );
    await expect(page.locator(`#revoke-${id}`)).toHaveText("Activate");

    const status = await jsonGet(
      `${WALLET_URL}/api/credentials/${id}/status`
    );
    expect(status.body.status).toBe(1);
    expect(status.body.managed).toBe(true);

    await page.locator(`#revoke-${id}`).click();
    await expect(page.locator(`#status-${id}`)).toHaveText("Active");
    const restored = await jsonGet(
      `${WALLET_URL}/api/credentials/${id}/status`
    );
    expect(restored.body.status).toBe(0);
  });

  test("issues a credential without a status list via the dialog", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    await page.locator("#issue-btn").click();

    await page.locator("#issue-vct").fill("urn:example:e2e-nostatus");
    await page.locator("#issue-claim-key-0").fill("given_name");
    await page.locator("#issue-claim-value-0").fill("Erika");
    await page.locator("#issue-status-list").selectOption("none");

    await page.locator("#issue-submit").click();
    await expect(page.locator("#issue-overlay")).not.toHaveClass(/active/);

    const card = page.locator(
      '.credential-card[data-vct="urn:example:e2e-nostatus"]'
    );
    await expect(card).toHaveAttribute("data-status", "none");
    const id = await card.getAttribute("data-credential-id");
    await expect(page.locator(`#revoke-${id}`)).toHaveCount(0);

    await page.locator(`#delete-${id}`).click();
    await expect(page.locator(`#credential-${id}`)).toHaveCount(0);
  });

  test("trust and certificate links live in the header dialog", async ({
    page,
    request,
  }) => {
    await page.goto(WALLET_URL);

    await expect(page.locator("#ca-cert-pem-link")).toBeHidden();
    await page.locator("#trust-link").click();
    await expect(page.locator("#trust-overlay")).toHaveClass(/active/);

    for (const id of ["ca-cert-pem-link", "ca-cert-jwks-link", "signing-jwks-link"]) {
      await expect(page.locator(`#${id}`)).toBeVisible();
    }
    const categories = page.locator("#trust-list-links .trust-items dt");
    await expect(categories).toHaveText(["Credential providers", "Wallet providers"]);
    const walletGroup = page.locator("#trust-list-links .trust-items dd").nth(1);
    await expect(walletGroup.locator(".trust-links a")).toHaveText(["wallet-provider"]);
    const names = page.locator("#trust-list-links .trust-list-name");
    expect(await names.count()).toBeGreaterThan(0);
    for (const name of await names.allTextContents()) {
      expect(name.trim()).not.toBe("");
    }
    for (const id of ["tls-cert-pem-link", "tls-cert-jwks-link"]) {
      await expect(page.locator(`#${id}`)).toBeHidden();
    }

    const signing = await request.get(`${WALLET_URL}/.well-known/jwt-vc-issuer`);
    expect(signing.status()).toBe(200);
    expect(await signing.text()).toContain('"keys"');

    for (const href of [
      "/api/certificates/ca",
      "/api/certificates/ca?format=jwks",
      "/api/certificates/tls",
      "/api/certificates/tls?format=jwks",
    ]) {
      const res = await request.get(`${WALLET_URL}${href}`);
      expect(res.status()).toBe(200);
      const body = await res.text();
      if (href.includes("jwks")) {
        expect(body).toContain('"keys"');
      } else {
        expect(body).toContain("BEGIN CERTIFICATE");
      }
    }

    await page.locator("#trust-close").click();
    await expect(page.locator("#trust-overlay")).not.toHaveClass(/active/);
  });
});

test.describe("Stored XSS", () => {
  // A status URI must remain one attribute value when another visitor renders it.
  test("a credential cannot inject an attribute into another visitor's page", async ({
    page,
    request,
  }) => {
    const b64 = (obj) =>
      Buffer.from(JSON.stringify(obj)).toString("base64url");
    const credential =
      b64({ alg: "ES256", typ: "dc+sd-jwt" }) +
      "." +
      b64({
        vct: "urn:xss-probe:1",
        iss: WALLET_URL,
        // The trailing // comments out text appended by the template.
        status: {
          status_list: {
            idx: 1,
            uri: 'http://x/" onmouseover="window.__XSS_FIRED=1;//',
          },
        },
      }) +
      "." +
      Buffer.alloc(64).toString("base64url");

    const imported = await request.post(`${WALLET_URL}/api/credentials`, {
      headers: { "Content-Type": "text/plain" },
      data: credential,
    });
    expect(imported.status()).toBe(201);

    await page.goto(WALLET_URL);
    await page.waitForSelector(".credential-card");

    const badge = page.locator(".status-badge.status-external").first();
    await expect(badge).toBeVisible();
    const attrs = await badge.evaluate((el) =>
      [...el.attributes].map((a) => a.name),
    );
    expect(attrs).not.toContain("onmouseover");

    const box = await badge.boundingBox();
    if (box) await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.waitForTimeout(200);
    expect(await page.evaluate(() => window.__XSS_FIRED)).toBeUndefined();
  });

  test("the wallet sends browser hardening headers", async ({ request }) => {
    const res = await request.get(`${WALLET_URL}/`);
    const csp = res.headers()["content-security-policy"] || "";
    // CSP blocks injected handlers through script-src without 'unsafe-inline'.
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain("script-src 'self' 'unsafe-inline'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(res.headers()["x-content-type-options"]).toBe("nosniff");
  });
});

test.describe("Mobile layout", () => {
  test("footer stays reachable on a small viewport", async ({ page }) => {
    // Mobile browser controls affect 100vh, so the footer must remain in the scrollable
    // area.
    await page.setViewportSize({ width: 390, height: 480 });
    await page.goto(WALLET_URL);
    await page.waitForSelector(".credential-card");

    const reachable = await page.evaluate(() => {
      window.scrollTo(0, document.documentElement.scrollHeight);
      const r = document.querySelector("footer").getBoundingClientRect();
      return r.top < window.innerHeight && r.bottom > 0;
    });
    expect(reachable).toBe(true);
  });
});

test.describe("Transaction code in the consent dialog", () => {
  // An unreachable issuer lets the test inspect transaction code input without completing
  // issuance.
  const offerWithTxCode = (txCode) => {
    const offer = {
      credential_issuer: "https://issuer.invalid",
      credential_configuration_ids: ["test-config"],
      grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": "test-code",
          tx_code: txCode,
        },
      },
    };
    return (
      "openid-credential-offer://?credential_offer=" +
      encodeURIComponent(JSON.stringify(offer))
    );
  };

  test.beforeEach(async () => {
    const pending = await jsonGet(`${WALLET_URL}/api/requests`);
    for (const r of Array.isArray(pending.body) ? pending.body : []) {
      await jsonPost(`${WALLET_URL}/api/requests/${r.id}/deny`, {});
    }
  });

  test("dialog asks for the code and blocks an empty approval", async ({
    page,
  }) => {
    // Do not await this POST. It waits for the consent decision made below.
    jsonPost(`${WALLET_URL}/api/offers`, {
      uri: offerWithTxCode({
        input_mode: "numeric",
        length: 6,
        description: "The code from your letter",
      }),
      interactive: true,
    }).catch(() => {});

    let pending = [];
    for (let i = 0; i < 50 && pending.length === 0; i++) {
      pending = await (await fetch(`${WALLET_URL}/api/requests`)).json();
      if (pending.length === 0) await new Promise((r) => setTimeout(r, 100));
    }
    await page.goto(`${WALLET_URL}/?focus=overview&request=${pending[0].id}`);
    const input = page.locator("#offer-tx-code-input");
    await expect(input).toBeVisible();

    await expect(input).toHaveAttribute("inputmode", "numeric");
    await expect(input).toHaveAttribute("maxlength", "6");
    await expect(page.locator("#offer-tx-code-description")).toHaveText(
      "The code from your letter"
    );

    await page.locator("#consent-approve").click();
    await expect(input).toHaveClass(/input-error/);
    await expect(page.locator("#consent-approve")).toBeEnabled();
    await expect(input).toBeVisible();
  });

  test("no input appears for an offer that needs no code", async ({ page }) => {
    jsonPost(`${WALLET_URL}/api/offers`, {
      uri: "openid-credential-offer://?credential_offer=" +
        encodeURIComponent(
          JSON.stringify({
            credential_issuer: "https://issuer.invalid",
            credential_configuration_ids: ["test-config"],
            grants: {
              "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "test-code",
              },
            },
          })
        ),
      interactive: true,
    }).catch(() => {});

    let pending = [];
    for (let i = 0; i < 50 && pending.length === 0; i++) {
      pending = await (await fetch(`${WALLET_URL}/api/requests`)).json();
      if (pending.length === 0) await new Promise((r) => setTimeout(r, 100));
    }
    await page.goto(`${WALLET_URL}/?focus=overview&request=${pending[0].id}`);
    await expect(page.locator("#consent-approve")).toBeVisible();
    await expect(page.locator("#offer-tx-code-input")).toHaveCount(0);
  });
});

test.describe("Deferred issuance in the UI", () => {
  test("nothing is shown when no issuance is outstanding", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator("#deferred-section")).toBeHidden();
  });

  test("the deferred API reports an empty list", async () => {
    const res = await jsonGet(`${WALLET_URL}/api/deferred`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  test("collecting an unknown deferred id is a 404", async () => {
    const res = await jsonPost(
      `${WALLET_URL}/api/deferred/no-such-id/collect`,
      {}
    );
    expect(res.status).toBe(404);
    expect(res.body.error).toContain("no deferred issuance");
  });
});

test.describe("Auto-accept toggle", () => {
  test("names the mode and flips it at runtime", async ({ page }) => {
    // Earlier tests can leave consent pending, which opens an overlay on local wallet
    // pages.
    const pending = await (await fetch(`${WALLET_URL}/api/requests`)).json();
    for (const req of pending) {
      await fetch(`${WALLET_URL}/api/requests/${req.id}/deny`, { method: "POST" });
    }
    await page.goto(WALLET_URL);
    const toggle = page.locator("#auto-accept-toggle");
    await expect(toggle).toHaveAttribute("aria-pressed", "false");

    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-pressed", "true");
    let config = await (await fetch(`${WALLET_URL}/api/config`)).json();
    expect(config.auto_accept).toBe(true);

    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-pressed", "false");
    config = await (await fetch(`${WALLET_URL}/api/config`)).json();
    expect(config.auto_accept).toBe(false);
  });
});

test.describe("A credential bound to a key the wallet does not hold", () => {
  // Presentations require the holder key (RFC 9901 §4.3 and ISO 18013-5 §9.1.3).
  // Credentials bound to another wallet remain readable but cannot be presented.
  test("is marked on its card and in its summary", async ({ page }) => {
    const crypto = require("crypto");
    const b64 = (obj) =>
      Buffer.from(JSON.stringify(obj)).toString("base64url");
    const coordinate = () => crypto.randomBytes(32).toString("base64url");
    const foreign =
      b64({ alg: "ES256", typ: "dc+sd-jwt" }) +
      "." +
      b64({
        iss: "https://foreign-issuer.example",
        vct: "urn:test:foreign-key:1",
        cnf: { jwk: { kty: "EC", crv: "P-256", x: coordinate(), y: coordinate() } },
      }) +
      "." +
      crypto.randomBytes(64).toString("base64url") +
      "~";

    const res = await fetch(`${WALLET_URL}/api/credentials`, {
      method: "POST",
      body: foreign,
    });
    expect(res.status).toBe(201);
    const imported = await res.json();
    expect(imported.key_binding_not_held).toBe(true);

    await page.goto(WALLET_URL);
    const card = page.locator(
      `.credential-card[data-credential-id='${imported.id}']`
    );
    await expect(card.locator(".status-unheld-key")).toHaveText("Bound to another key", {
      timeout: 5000,
    });
    await expect(card.locator(".status-unheld-key")).toHaveAttribute(
      "title",
      /does not hold/
    );

    const own = page.locator(".credential-card[data-format='mdoc']").first();
    await expect(own.locator(".status-unheld-key")).toHaveCount(0);

    await fetch(`${WALLET_URL}/api/credentials/${imported.id}`, {
      method: "DELETE",
    });
  });
});
