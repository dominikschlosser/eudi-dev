// @ts-check
const { test, expect } = require("@playwright/test");

// Helper: build a minimal JWT token (header.payload.signature)
function makeJWT(header, payload) {
  const h = Buffer.from(JSON.stringify(header)).toString("base64url");
  const p = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return h + "." + p + ".fakesig";
}

// Helper: build a minimal SD-JWT with disclosures and correct _sd digests
const crypto = require("crypto");

function makeSDJWT(payload, disclosures) {
  const header = { alg: "ES256", typ: "dc+sd-jwt" };

  // Compute digests for disclosures and set _sd
  if (disclosures && disclosures.length > 0) {
    const digests = disclosures.map((d) => {
      const raw = Buffer.from(JSON.stringify(d)).toString("base64url");
      return crypto.createHash("sha256").update(raw).digest("base64url");
    });
    payload._sd = digests;
  }

  const h = Buffer.from(JSON.stringify(header)).toString("base64url");
  const p = Buffer.from(JSON.stringify(payload)).toString("base64url");
  let result = h + "." + p + ".fakesig";

  for (const d of disclosures || []) {
    result += "~" + Buffer.from(JSON.stringify(d)).toString("base64url");
  }
  result += "~";
  return result;
}

const TEST_JWT = makeJWT(
  { alg: "none", typ: "JWT" },
  { sub: "user123", iss: "https://example.com", exp: 4102444799 }
);

const EXPIRED_JWT = makeJWT(
  { alg: "none", typ: "JWT" },
  { sub: "user123", iss: "https://example.com", exp: 1000000000 }
);

const TEST_SDJWT = makeSDJWT(
  { iss: "https://issuer.example", _sd_alg: "sha-256", exp: 4102444800 },
  [
    ["salt1", "given_name", "Erika"],
    ["salt2", "family_name", "Mustermann"],
  ]
);

const EMBEDDED_REGISTRATION_JWT = makeJWT(
  { alg: "none", typ: "JWT" },
  { sub: "registration-cert", iss: "https://trust.example", cnf: { kid: "reg-key-1" } }
);

const OUTER_JWT_WITH_EMBEDDED = makeJWT(
  { alg: "none", typ: "JWT" },
  {
    client_id: "https://verifier.example",
    response_type: "vp_token",
    verifier_info: {
      registration: {
        jwt: EMBEDDED_REGISTRATION_JWT,
      },
    },
  }
);

test.describe("Page load", () => {
  test("shows OID4VC Dev title and empty state", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("h1")).toHaveText("EUDI Dev Decoder");
    await expect(page.locator(".placeholder")).toHaveText(
      "Paste a credential to see decoded output"
    );
    await expect(page.locator("#format-badge")).toHaveClass(/hidden/);
  });

  test("prefill via query param", async ({ page }) => {
    await page.goto("/?credential=" + encodeURIComponent(TEST_JWT));
    await expect(page.locator("#format-badge")).toHaveText("JWT");
    await expect(page.locator(".validity-banner")).toBeVisible();
  });
});

test.describe("JWT decoding", () => {
  test("decodes and shows format badge, banner, and sections", async ({
    page,
  }) => {
    await page.goto("/");
    await page.locator("#input").fill(TEST_JWT);
    // Wait for debounced decode
    await expect(page.locator("#format-badge")).toHaveText("JWT", {
      timeout: 3000,
    });
    await expect(page.locator("#format-badge")).toHaveClass(/jwt/);

    // Validity banner should show Unverified (no key provided)
    const banner = page.locator(".validity-banner");
    await expect(banner).toBeVisible();
    await expect(banner).toContainText("Unverified");
    await expect(banner).toHaveClass(/unverified/);

    // Header and Payload sections should be visible in output pane
    await expect(page.locator('#output .section[data-section="header"]')).toBeVisible();
    await expect(page.locator('#output .section[data-section="payload"]')).toBeVisible();

    // Issuer summary should be present
    await expect(page.locator(".issuer-summary")).toContainText(
      "https://example.com"
    );
  });

  test("expired JWT shows Invalid banner", async ({ page }) => {
    await page.goto("/");
    await page.locator("#input").fill(EXPIRED_JWT);
    const banner = page.locator(".validity-banner");
    await expect(banner).toContainText("Invalid", { timeout: 3000 });
    await expect(banner).toHaveClass(/expired/);
  });

  test("clicking an embedded JWT navigates to it and browser back restores the parent", async ({
    page,
  }) => {
    await page.goto("/");
    await page.locator("#input").fill(OUTER_JWT_WITH_EMBEDDED);
    await expect(page.locator("#format-badge")).toHaveText("JWT", {
      timeout: 3000,
    });

    const embedded = page.locator('.embedded-token[data-embedded-format="jwt"]').first();
    await expect(embedded).toBeVisible();

    await embedded.click();
    await expect(page.locator("#input")).toHaveValue(EMBEDDED_REGISTRATION_JWT);
    await expect(page.locator('#output .section[data-section="payload"]')).toContainText(
      "registration-cert"
    );

    await page.goBack();
    await expect(page.locator("#input")).toHaveValue(OUTER_JWT_WITH_EMBEDDED);
    await expect(page.locator('#output .section[data-section="payload"]')).toContainText(
      "verifier_info"
    );
  });
});

test.describe("SD-JWT decoding", () => {
  test("shows SD-JWT badge, disclosures, and resolved claims", async ({
    page,
  }) => {
    await page.goto("/");
    await page.locator("#input").fill(TEST_SDJWT);
    await expect(page.locator("#format-badge")).toHaveText("SD-JWT", {
      timeout: 3000,
    });

    // Disclosures section
    const discSection = page.locator(".disclosure-item");
    await expect(discSection).toHaveCount(2);

    // Resolved claims
    await expect(page.locator(".resolved-claims-list")).toBeVisible();
    await expect(page.locator(".claim-disclosed")).toHaveCount(2);
  });
});

test.describe("Colorized input view", () => {
  test("shows colorized overlay when credential is decoded", async ({
    page,
  }) => {
    await page.goto("/");
    await page.locator("#input").fill(TEST_JWT);
    await expect(page.locator("#format-badge")).toHaveText("JWT", {
      timeout: 3000,
    });

    // Raw view should be visible (colorized overlay)
    await expect(page.locator("#raw-view")).toBeVisible();

    // Textarea should have colorized class
    await expect(page.locator("#input")).toHaveClass(/colorized/);

    // Raw view should contain colored spans
    await expect(page.locator("#raw-view .jwt-header")).toBeVisible();
    await expect(page.locator("#raw-view .jwt-payload")).toBeVisible();
    await expect(page.locator("#raw-view .jwt-signature")).toBeVisible();
  });

  test("textarea remains editable while colorized", async ({ page }) => {
    await page.goto("/");
    const textarea = page.locator("#input");
    await textarea.fill(TEST_JWT);
    await expect(page.locator("#format-badge")).toHaveText("JWT", {
      timeout: 3000,
    });

    // Type additional text — should still work
    await textarea.focus();
    await textarea.press("End");
    await textarea.type("extra", { delay: 50 });

    // Value should be updated
    const value = await textarea.inputValue();
    expect(value).toContain("extra");
  });

  test("editing at cursor position inserts text correctly and colorization stays", async ({
    page,
  }) => {
    await page.goto("/");
    const textarea = page.locator("#input");
    const rawView = page.locator("#raw-view");

    // Fill a simple JWT and wait for colorization
    await textarea.fill(TEST_JWT);
    await expect(rawView).toBeVisible({ timeout: 3000 });
    await expect(textarea).toHaveClass(/colorized/);

    const originalValue = await textarea.inputValue();

    // Place cursor at a known position using setSelectionRange
    await textarea.focus();
    await textarea.evaluate((el) => {
      el.setSelectionRange(5, 5);
    });

    // Insert text at cursor position (should go at index 5)
    await page.keyboard.type("XYZ", { delay: 30 });

    const newValue = await textarea.inputValue();

    // Text should be inserted at position 5
    expect(newValue.substring(0, 5)).toBe(originalValue.substring(0, 5));
    expect(newValue.substring(5, 8)).toBe("XYZ");
    expect(newValue.substring(8)).toBe(originalValue.substring(5));

    // Colorization should still be active
    await expect(textarea).toHaveClass(/colorized/);
    await expect(rawView).toBeVisible();

    // Raw view content should reflect the updated text
    const rawText = await rawView.textContent();
    expect(rawText).toContain("XYZ");
  });

  test("colorized view updates in sync after multiple edits", async ({
    page,
  }) => {
    await page.goto("/");
    const textarea = page.locator("#input");
    const rawView = page.locator("#raw-view");

    await textarea.fill(TEST_JWT);
    await expect(rawView).toBeVisible({ timeout: 3000 });

    // Delete some characters from the end using Backspace
    await textarea.focus();
    await textarea.press("End");
    await textarea.press("Backspace");
    await textarea.press("Backspace");
    await textarea.press("Backspace");

    const afterDelete = await textarea.inputValue();
    expect(afterDelete.length).toBe(TEST_JWT.length - 3);

    // Colorized class should still be active (rawView updates on input)
    await expect(textarea).toHaveClass(/colorized/);
    await expect(rawView).toBeVisible();

    // Raw view text should match textarea value
    const rawText = await rawView.textContent();
    expect(rawText).toBe(afterDelete.trim());
  });

  test("colorized view clears when input is cleared", async ({ page }) => {
    await page.goto("/");
    await page.locator("#input").fill(TEST_JWT);
    await expect(page.locator("#raw-view")).toBeVisible({ timeout: 3000 });

    // Click Clear button
    await page.locator("#clear-btn").click();

    // Raw view should be hidden
    await expect(page.locator("#raw-view")).toBeHidden();
    await expect(page.locator("#input")).not.toHaveClass(/colorized/);

    // Placeholder should be back
    await expect(page.locator(".placeholder")).toBeVisible();
  });
});

test.describe("Verification panel", () => {
  test("panel shows all checks", async ({ page }) => {
    await page.goto("/");
    await page.locator("#input").fill(TEST_JWT);
    await expect(page.locator(".validity-banner")).toBeVisible({
      timeout: 3000,
    });

    // Checks are always visible, grouped into valid / cannot-be-checked / violations.
    const checks = page.locator(".vg-item");
    await expect(checks).toHaveCount(4);

    const names = await page.locator(".vg-name").allTextContents();
    expect(names).toContain("expiry");
    expect(names).toContain("integrity");
    expect(names).toContain("signature");
    expect(names).toContain("status");
  });

  test("verify form opens with key input and button", async ({ page }) => {
    await page.goto("/");
    await page.locator("#input").fill(TEST_JWT);
    await expect(page.locator(".validity-banner")).toBeVisible({
      timeout: 3000,
    });

    // Collapsed until the summary is clicked.
    await expect(page.locator(".verify-inline-key")).toBeHidden();
    await page.locator(".verify-details summary").click();

    await expect(page.locator(".verify-inline-key")).toBeVisible();
    await expect(page.locator(".verify-inline-tl")).toBeVisible();
    await expect(page.locator(".verify-inline-btn")).toBeVisible();
    await expect(page.locator(".verify-inline-btn")).toContainText(
      "Verify signature"
    );
  });

  test("JWT shows integrity and status as Not applicable", async ({
    page,
  }) => {
    await page.goto("/");
    await page.locator("#input").fill(TEST_JWT);
    await expect(page.locator(".validity-banner")).toBeVisible({
      timeout: 3000,
    });

    const items = page.locator(".vg-item");
    const count = await items.count();
    const details = {};
    for (let i = 0; i < count; i++) {
      const name = await items.nth(i).locator(".vg-name").textContent();
      const detail = await items.nth(i).locator(".vg-detail").textContent();
      details[name] = detail;
    }

    expect(details["integrity"]).toBe("Not applicable for plain JWT");
    expect(details["status"]).toBe("Not applicable for plain JWT");
    expect(details["signature"]).toBe("No key provided");
  });

  test("SD-JWT shows integrity under Valid", async ({ page }) => {
    await page.goto("/");
    await page.locator("#input").fill(TEST_SDJWT);
    await expect(page.locator(".validity-banner")).toBeVisible({
      timeout: 3000,
    });

    await expect(page.locator(".vg-valid")).toContainText("integrity");
  });
});

test.describe("Cross-highlighting (right → left)", () => {
  test("hovering output section highlights input span", async ({ page }) => {
    await page.goto("/");
    await page.locator("#input").fill(TEST_JWT);
    await expect(page.locator('#output .section[data-section="header"]')).toBeVisible({
      timeout: 3000,
    });

    // Hover over the Header section in the output pane
    await page.locator('#output .section[data-section="header"]').hover();

    // The corresponding span in the raw view should get the highlight class
    await expect(
      page.locator('#raw-view [data-section="header"]')
    ).toHaveClass(/highlight/);
  });

  test("leaving output section removes highlight", async ({ page }) => {
    await page.goto("/");
    await page.locator("#input").fill(TEST_JWT);
    await expect(page.locator('#output .section[data-section="header"]')).toBeVisible({
      timeout: 3000,
    });

    // Hover, then move away
    await page.locator('#output .section[data-section="header"]').hover();
    await expect(
      page.locator('#raw-view [data-section="header"]')
    ).toHaveClass(/highlight/);

    // Move to a different area
    await page.locator("h1").hover();
    await expect(
      page.locator('#raw-view [data-section="header"]')
    ).not.toHaveClass(/highlight/);
  });
});

test.describe("Section collapsing", () => {
  test("clicking section header collapses/expands body", async ({ page }) => {
    await page.goto("/");
    await page.locator("#input").fill(TEST_JWT);
    await expect(page.locator('#output .section[data-section="header"]')).toBeVisible({
      timeout: 3000,
    });

    const headerSection = page.locator('#output .section[data-section="header"]');
    const body = headerSection.locator(".section-body");
    const sectionHeader = headerSection.locator(".section-header");

    // Body should initially be visible (not collapsed)
    await expect(body).not.toHaveClass(/collapsed/);

    // Click to collapse
    await sectionHeader.click();
    await expect(body).toHaveClass(/collapsed/);

    // Click again to expand
    await sectionHeader.click();
    await expect(body).not.toHaveClass(/collapsed/);
  });
});

test.describe("Theme toggle", () => {
  test("toggles between light and dark theme", async ({ page }) => {
    await page.goto("/");
    const html = page.locator("html");
    const btn = page.locator("#theme-btn");

    // Default is dark: no data-theme attribute set
    await expect(html).not.toHaveAttribute("data-theme", "light");

    // Click toggle -> light theme
    await btn.click();
    await expect(html).toHaveAttribute("data-theme", "light");

    // Click again -> back to dark (attribute cleared)
    await btn.click();
    await expect(html).not.toHaveAttribute("data-theme", "light");
  });
});

test.describe("Clear button", () => {
  test("clears input, output, badge, and colorized view", async ({
    page,
  }) => {
    await page.goto("/");
    await page.locator("#input").fill(TEST_JWT);
    await expect(page.locator("#format-badge")).toHaveText("JWT", {
      timeout: 3000,
    });

    await page.locator("#clear-btn").click();

    await expect(page.locator("#input")).toHaveValue("");
    await expect(page.locator("#format-badge")).toHaveClass(/hidden/);
    await expect(page.locator(".placeholder")).toBeVisible();
    await expect(page.locator("#raw-view")).toBeHidden();
  });
});

test.describe("Mobile / responsive layout", () => {
  test("input pane stacks above output pane on narrow viewport", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto("/");
    await page.locator("#input").fill(TEST_JWT);
    await expect(page.locator("#format-badge")).toHaveText("JWT", {
      timeout: 3000,
    });

    // Input pane should be above output pane (stacked vertically)
    const inputBox = await page.locator(".input-pane").boundingBox();
    const outputBox = await page.locator(".output-pane").boundingBox();
    expect(inputBox.y).toBeLessThan(outputBox.y);

    // Input pane should have visible height for the textarea content
    expect(inputBox.height).toBeGreaterThan(100);

    // Textarea should be visible and editable inside the input pane
    await expect(page.locator("#input")).toBeVisible();
    await expect(page.locator("#raw-view")).toBeVisible();

    // Output pane should show decoded content
    await expect(page.locator(".validity-banner")).toBeVisible();
    await expect(page.locator('#output .section[data-section="header"]')).toBeVisible();
  });

  test("page scrolls to reveal full output on mobile", async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 568 });
    await page.goto("/");
    await page.locator("#input").fill(TEST_JWT);
    await expect(page.locator(".validity-banner")).toBeVisible({
      timeout: 3000,
    });

    // Payload section may be below the fold — scroll to it
    const payload = page.locator('#output .section[data-section="payload"]');
    await payload.scrollIntoViewIfNeeded();
    await expect(payload).toBeVisible();
  });
});

test.describe("Timestamp hover", () => {
  test("exp field has timestamp-hover with title attribute", async ({
    page,
  }) => {
    await page.goto("/");
    await page.locator("#input").fill(TEST_JWT);
    await expect(page.locator('#output .section[data-section="payload"]')).toBeVisible({
      timeout: 3000,
    });

    // The exp value should have a timestamp-hover class with a title
    const tsHover = page.locator('#output .timestamp-hover').first();
    await expect(tsHover).toBeAttached({ timeout: 3000 });
    const title = await tsHover.getAttribute("title");
    expect(title).toContain("2099"); // exp: 4102444799 ≈ 2099-12-31
  });

  test("timestamps in claim lists carry the tooltip too", async ({ page }) => {
    // Own fixture: TEST_SDJWT's exp sits exactly on the upper sanity bound
    // (4102444800), which the tooltip deliberately skips.
    const sdjwt = makeSDJWT(
      { iss: "https://issuer.example", _sd_alg: "sha-256", exp: 4102444799 },
      [["salt1", "given_name", "Erika"]]
    );
    await page.goto("/");
    await page.locator("#input").fill(sdjwt);
    await expect(page.locator("#output .claim-value").first()).toBeAttached({
      timeout: 3000,
    });

    // Regression: claim and disclosure lists rendered through a helper that
    // never received the claim name, so only the raw payload block had
    // tooltips while the lists users actually read had none.
    const claimTs = page.locator("#output .claim-value.timestamp-hover").first();
    await expect(claimTs).toBeAttached({ timeout: 3000 });
    expect(await claimTs.getAttribute("title")).toContain("2099");
  });
});

// A 48x64 JPEG, the size range a portrait claim actually carries.
const PORTRAIT_DATA_URL =
  "data:image/jpeg;base64," +
  "/9j/2wCEAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYn" +
  "KSopGR8tMC0oMCUoKSgBBwcHCggKEwoKEygaFhooKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo" +
  "KCgoKCgoKCgoKCgoKCgoKCgoKCgoKP/AABEIAEAAMAMBIgACEQEDEQH/xAGiAAABBQEBAQEBAQAA" +
  "AAAAAAAAAQIDBAUGBwgJCgsQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGh" +
  "CCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hp" +
  "anN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV" +
  "1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+gEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoLEQAC" +
  "AQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXx" +
  "FxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqS" +
  "k5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo6ery8/T1" +
  "9vf4+fr/2gAMAwEAAhEDEQA/APma3g9q0reDpxT7eD2rSt4OnFNHRg64y3g6cVp28HTin28HTitK" +
  "3g6cVaPq8HXGW8HTitO3g9qdbwe1advB04q0fV4OuecW8HTitK3g6cU+3g6cVp28HTiskfh+DrjL" +
  "eDpxWlbwdOKfbwdOK0reD2qkfV4OuNt4PatK3g6cU+3g6cVpW8HTirR9Xg655zbwdOK0reDpxT7e" +
  "DpxWlbwdOKyR+H4OuMt4OnFadvB7U63g6cVp28HtVo+rwdcZbwdOK0reDpxT7eDpxWnbwdOKpH1e" +
  "DrnnFvB04rSt4OnFPt4OnFadvB04rJH4fg64y3g9q0reDpxT7eD2rSt4OnFWj6vB1xtvB04rSt4O" +
  "nFPt4OnFaVvB04q0fV4Ouf/Z";

test.describe("Long claim values", () => {
  test("a portrait shows as a thumbnail with the value behind a toggle", async ({
    page,
  }) => {
    const sdjwt = makeSDJWT(
      { iss: "https://issuer.example", _sd_alg: "sha-256", exp: 4102444799 },
      [["salt1", "portrait", PORTRAIT_DATA_URL]]
    );
    await page.goto("/");
    await page.locator("#input").fill(sdjwt);

    const value = page.locator("#output .disclosure-value .long-value-token").first();
    await expect(value).toBeAttached({ timeout: 3000 });

    // The line carries the head of the value, not all of it.
    const shown = await value.textContent();
    expect(shown.length).toBeLessThan(PORTRAIT_DATA_URL.length);
    expect(shown.endsWith("…")).toBe(true);

    // An image claim is readable, so it is shown as one.
    const thumbnail = page.locator("#output .value-image").first();
    await expect(thumbnail).toBeVisible();
    expect(await thumbnail.evaluate((img) => img.naturalWidth)).toBe(48);

    // Without wrapping, one value this long lays out a line wider than the
    // screen and the whole output pane scrolls sideways.
    const overflow = await page.evaluate(() => {
      const out = document.getElementById("output");
      return out.scrollWidth - out.clientWidth;
    });
    expect(overflow).toBeLessThanOrEqual(1);

    const toggle = page.locator("#output .disclosure-value .long-value-toggle").first();
    await expect(toggle).toContainText("Show all " + PORTRAIT_DATA_URL.length + " characters");
    await toggle.click();
    expect(await value.textContent()).toBe(PORTRAIT_DATA_URL);
    await expect(toggle).toContainText("Show less");
  });
});

test.describe("Decoding does not wait on the issuer", () => {
  test("output renders while the checks that need the network are still running", async ({
    page,
  }) => {
    // A status reference is what gives the online pass something to fetch.
    // Port 1 answers by refusing, so the check resolves without a wait.
    const sdjwt = makeSDJWT(
      {
        iss: "https://issuer.example",
        _sd_alg: "sha-256",
        exp: 4102444799,
        status: { status_list: { uri: "http://127.0.0.1:1/status-list/1", idx: 0 } },
      },
      [["salt1", "given_name", "Erika"]]
    );

    // Stand in for an issuer that takes its time answering.
    let releaseOnlinePass;
    const onlinePassHeld = new Promise((resolve) => {
      releaseOnlinePass = resolve;
    });
    let offlinePasses = 0;
    let onlinePasses = 0;
    await page.route("**/api/validate", async (route) => {
      const body = JSON.parse(route.request().postData());
      if (body.offline) {
        offlinePasses++;
        await route.continue();
        return;
      }
      onlinePasses++;
      await onlinePassHeld;
      await route.continue();
    });

    await page.goto("/");
    await page.locator("#input").fill(sdjwt);

    // The credential is on screen with the online pass still in flight.
    await expect(page.locator('#output .section[data-section="payload"]')).toBeVisible({
      timeout: 3000,
    });
    const banner = page.locator("#output .validity-banner");
    await expect(banner).toHaveClass(/checking/);
    await expect(banner).toContainText("Checking");

    releaseOnlinePass();
    await expect(banner).not.toHaveClass(/checking/, { timeout: 10000 });
    await expect(banner).toContainText("status");

    // One edit is one pass of each kind, and the issuer is asked once.
    expect(offlinePasses).toBe(1);
    expect(onlinePasses).toBe(1);
  });

  test("pasting decodes once instead of twice", async ({ page, context }) => {
    const sdjwt = makeSDJWT(
      { iss: "https://issuer.example", _sd_alg: "sha-256", exp: 4102444799 },
      [["salt1", "given_name", "Erika"]]
    );

    let onlinePasses = 0;
    await page.route("**/api/validate", async (route) => {
      if (!JSON.parse(route.request().postData()).offline) onlinePasses++;
      await route.continue();
    });

    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await page.goto("/");
    await page.evaluate((text) => navigator.clipboard.writeText(text), sdjwt);
    await page.locator("#input").click();
    await page.keyboard.press("ControlOrMeta+V");

    await expect(page.locator("#format-badge")).toHaveText("SD-JWT", { timeout: 3000 });
    // A paste raises a paste event and an input event. Both used to schedule
    // their own decode, so every paste asked the issuer twice.
    await page.waitForTimeout(1500);
    expect(onlinePasses).toBe(1);
  });
});
