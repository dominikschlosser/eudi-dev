// @ts-check
const { test, expect } = require("@playwright/test");
const { execSync } = require("child_process");
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");

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

  // Start wallet with --pid and --auto-accept for some tests, interactive for others.
  // A fresh --wallet-dir keeps the test isolated from any local wallet state
  // (a persisted issuer URL would make the server bind that issuer port too).
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
      // Explicit issuer URL: the default (port+1 = 18925) collides with
      // docker.spec.js's host port mapping.
      "--base-url",
      "https://localhost:18926",
    ],
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
  test("shows wallet title", async ({ page }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator("h1")).toHaveText("EUDI Dev Wallet");
  });

  test("conformance panel changes the local wallet setting via the endpoint", async ({
    page,
  }) => {
    // On a local (non-demo) wallet the panel flips the wallet's own setting
    // (PUT /api/config/conformance), not a cookie.
    await page.goto(WALLET_URL);
    const configMode = async () =>
      (await page.evaluate(async () => (await (await fetch("/api/config")).json()).validation_mode));

    const before = await configMode();
    const target = before === "strict" ? "debug" : "strict";

    await page.click("#conformance-link");
    // A local wallet's controls are editable (unlike the read-only demo).
    await expect(page.locator("#conf-mode-select")).toBeEnabled();
    await page.selectOption("#conf-mode-select", target);
    await expect.poll(configMode).toBe(target);

    // The change is the server's own setting, no per-visitor cookie involved.
    const cookie = await page.evaluate(() => document.cookie);
    expect(cookie).not.toContain("eudi_conformance");

    // Reset restores the value the wallet started with.
    await page.click("#conf-reset");
    await expect.poll(configMode).toBe(before);
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
  // Earlier API tests intentionally trigger wallet errors (invalid
  // presentation URI, malformed offer). The wallet UI surfaces the last
  // error and any pending consent request as an overlay on page load, which
  // would intercept clicks on the issue button. Clear both before each test.
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

    // Opens empty: no pre-filled values, one empty claim row
    await expect(page.locator("#issue-vct")).toHaveValue("");
    await expect(page.locator("#issue-exp")).toHaveValue("");
    await expect(page.locator("#issue-claim-rows .claim-row")).toHaveCount(1);
    await expect(page.locator("#issue-claim-key-0")).toHaveValue("");

    // mDoc-only fields are hidden for SD-JWT
    await expect(page.locator("#issue-doctype")).toBeHidden();
    await expect(page.locator("#issue-claim-ns-0")).toBeHidden();

    // Selecting the pre-defined PID template fills everything on demand
    await page.locator("#issue-template").selectOption("german-pid-sdjwt");
    await expect(page.locator("#issue-vct")).toHaveValue("urn:eudi:pid:de:1");
    await expect(page.locator("#issue-exp")).toHaveValue("720h");
    // One row per top-level claim of the German PID, aka_vcts included: it
    // is what says the credential is also a urn:eudi:pid:1.
    await expect(page.locator("#issue-claim-rows .claim-row")).toHaveCount(15);
    const keys = await page
      .locator("#issue-claim-rows .claim-row input[id^=issue-claim-key]")
      .evaluateAll((inputs) => inputs.map((i) => i.value));
    expect(keys.sort()).toEqual([
      "address",
      "age_equal_or_over",
      "aka_vcts",
      "also_known_as",
      "birth_name",
      "birthdate",
      "date_of_expiry",
      "family_name",
      "given_name",
      "issuing_authority",
      "issuing_country",
      "nationalities",
      "place_of_birth",
      "source_document_type",
      "title",
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
    // mDoc claim rows get a per-attribute namespace input
    await expect(page.locator("#issue-claim-ns-0")).toBeVisible();

    await page.locator("#issue-template").selectOption("german-pid-mdoc");
    await expect(page.locator("#issue-doctype")).toHaveValue(
      "eu.europa.ec.eudi.pid.1"
    );

    // Switching the format resets all other fields
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
    const issued = res.body.find(
      (c) => c.doctype === "org.example.e2e.doctype"
    );
    expect(issued).toBeDefined();
    expect(issued.claims["org.example.e2e.doctype:given_name"]).toBe("Erika");
    expect(issued.claims["org.example.custom:loyalty_tier"]).toBe("gold");

    // Clean up so later count assertions stay stable
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
    await expect(
      page.locator(".credential-type", { hasText: "urn:example:e2e-test" })
    ).toBeVisible();

    // The issued credential contains the pre-filled PID claims plus the added one
    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const issued = res.body.find((c) => c.vct === "urn:example:e2e-test");
    expect(issued).toBeDefined();
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

    // JSON edits are reflected in the builder when switching back
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

    // Invalid JSON blocks the switch and keeps JSON mode active
    await page.locator("#issue-claims-mode-json").check();
    await page.locator("#issue-claims").fill("{not json");
    // click() instead of check(): the UI reverts the radio on invalid JSON
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

  // Namespaces are an mdoc idea, and the card groups mdoc elements by them.
  // An SD-JWT claim name may contain a colon of its own (a URI claim name is
  // ordinary), and splitting that into a namespace would show half a name.
  test("an SD-JWT claim name containing a colon stays whole on the card", async ({
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
    await expect(card.locator(".claim-namespace")).toHaveCount(0);
    await expect(card.locator(".claim-tag", { hasText: claimName })).toHaveCount(1);

    await page.locator(`#delete-${issued.body.id}`).click();
    await expect(card).toHaveCount(0);
  });

  test("manages templates and issues from one with a non-disclosable claim", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);

    // Create a template through the manager (paste JSON = import)
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

    // Issue from the template
    await page.locator("#issue-btn").click();
    await page.locator("#issue-template").selectOption("e2e-employee");
    await expect(page.locator("#issue-vct")).toHaveValue(
      "urn:example:e2e-employee"
    );
    await expect(page.locator("#issue-always-disclosed")).toHaveValue(
      "department"
    );
    // The SD checkbox of the always-disclosed claim is unchecked (input
    // values are set as JS properties, so query them via evaluate)
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
    const issued = res.body.find((c) => c.vct === "urn:example:e2e-employee");
    expect(issued).toBeDefined();
    expect(issued.claims.department).toBe("IT");
    expect(issued.claims.employee_id).toBe("E-1");
    // department is embedded plainly: it appears in the raw JWT payload
    const payload = JSON.parse(
      Buffer.from(issued.raw.split(".")[1], "base64url").toString()
    );
    expect(payload.department).toBe("IT");
    expect(payload.employee_id).toBeUndefined();

    // Clean up credential and template
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

    // Clean up: the issued credential and the saved template
    const res = await jsonGet(`${WALLET_URL}/api/credentials`);
    const issued = res.body.find((c) => c.vct === "urn:example:e2e-saved");
    expect(issued).toBeDefined();
    await page.goto(WALLET_URL);
    await page.locator(`#delete-${issued.id}`).click();
    await expect(page.locator(`#credential-${issued.id}`)).toHaveCount(0);
    await fetch(`${WALLET_URL}/api/templates/e2e-saved-template`, {
      method: "DELETE",
    });
  });

  test("shows status badges and revokes and re-activates a credential", async ({
    page,
  }) => {
    await page.goto(WALLET_URL);
    await expect(page.locator(".credential-card")).toHaveCount(2);

    // The wallet manages its own status list (--base-url), so PID cards show
    // a live status badge and a revoke action.
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

    // The status API agrees
    const status = await jsonGet(
      `${WALLET_URL}/api/credentials/${id}/status`
    );
    expect(status.body.status).toBe(1);
    expect(status.body.managed).toBe(true);

    // Re-activate to leave the wallet in a clean state
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

    // Clean up
    await page.locator(`#delete-${id}`).click();
    await expect(page.locator(`#credential-${id}`)).toHaveCount(0);
  });

  test("trust and certificate links live in the header dialog", async ({
    page,
    request,
  }) => {
    await page.goto(WALLET_URL);

    // They used to sit under the action bar; now they are one click away so
    // the main view stays focused on running flows.
    await expect(page.locator("#ca-cert-pem-link")).toBeHidden();
    await page.locator("#trust-link").click();
    await expect(page.locator("#trust-overlay")).toHaveClass(/active/);

    for (const id of ["ca-cert-pem-link", "ca-cert-jwks-link", "signing-jwks-link"]) {
      await expect(page.locator(`#${id}`)).toBeVisible();
    }
    // A bare trust-list id ("pid") does not say what the list covers, so the
    // provider profile is named next to it, and the lists are grouped by what
    // they anchor. Verifiers want the credential anchor, issuers the wallet
    // attestation one, and neither should have to read past the other.
    const categories = page.locator("#trust-list-links .trust-items dt");
    await expect(categories).toHaveText(["Credential providers", "Wallet providers"]);
    const walletGroup = page.locator("#trust-list-links .trust-items dd").nth(1);
    await expect(walletGroup.locator(".trust-links a")).toHaveText(["wallet-provider"]);
    // Every entry names its profile, not just its id.
    const names = page.locator("#trust-list-links .trust-list-name");
    expect(await names.count()).toBeGreaterThan(0);
    for (const name of await names.allTextContents()) {
      expect(name.trim()).not.toBe("");
    }
    // This server runs with an https --base-url, so the built-in HTTPS
    // listener is disabled and the self-signed TLS leaf stays hidden.
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
  // A wallet is shared state: one visitor imports a credential, every other
  // visitor's browser renders it. The escaping helper used to round-trip
  // through textContent, which leaves " and ' alone, so a status list URI
  // could close the title="" attribute and add an event handler that ran in
  // everyone else's browser.
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
        // The trailing // comments out whatever the template appends.
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
    // The payload has to stay one attribute value, not become two.
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
    // script-src without 'unsafe-inline' is what stops an injected handler
    // from running even when escaping fails somewhere.
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain("script-src 'self' 'unsafe-inline'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(res.headers()["x-content-type-options"]).toBe("nosniff");
  });
});

test.describe("Mobile layout", () => {
  test("footer stays reachable on a small viewport", async ({ page }) => {
    // Regression: the wallet had no responsive rules, so body height 100vh
    // with overflow hidden put the footer (imprint link) below the visible
    // area on phones, where the URL bar counts into 100vh.
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
  // An offer whose pre-authorized grant carries tx_code cannot be redeemed
  // without the code, which the issuer delivers out of band. The dialog has to
  // ask for it. The issuer here does not exist, so the offer is described from
  // what it carries and the flow fails after approval, which is fine: what is
  // under test is the input, not the issuance.
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
    // Park an offer on a consent request. The POST hangs until the decision,
    // so it is deliberately not awaited.
    jsonPost(`${WALLET_URL}/api/offers`, {
      uri: offerWithTxCode({
        input_mode: "numeric",
        length: 6,
        description: "The code from your letter",
      }),
      interactive: true,
    }).catch(() => {});

    await page.goto(WALLET_URL);
    const input = page.locator("#offer-tx-code-input");
    await expect(input).toBeVisible();

    // The input is shaped by the offer's own tx_code members.
    await expect(input).toHaveAttribute("inputmode", "numeric");
    await expect(input).toHaveAttribute("maxlength", "6");
    await expect(page.locator("#offer-tx-code-description")).toHaveText(
      "The code from your letter"
    );

    // Approving with nothing typed stays in the dialog and marks the field.
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

    await page.goto(WALLET_URL);
    await expect(page.locator("#consent-approve")).toBeVisible();
    await expect(page.locator("#offer-tx-code-input")).toHaveCount(0);
  });
});

test.describe("Deferred issuance in the UI", () => {
  // A credential the issuer deferred is collected in the background, so the
  // section reports rather than asks. The two buttons are for going faster
  // than the issuer's interval, and for giving up on it.
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
    // Earlier tests can leave a pending consent behind, and a local wallet
    // opens its dialog for it on page load, which would sit over the header.
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

    // Back to interactive, so the rest of the suite keeps its consent flows.
    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-pressed", "false");
    config = await (await fetch(`${WALLET_URL}/api/config`)).json();
    expect(config.auto_accept).toBe(false);
  });
});
