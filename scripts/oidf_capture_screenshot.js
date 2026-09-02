// Captures the wallet UI as a PNG for the OIDF suite's screenshot uploads.
// The negative wallet modules end in REVIEW and expect an image of the error
// the wallet showed the user, so the harness photographs the real UI, which
// renders the rejection it just produced.
//
// Usage: node oidf_capture_screenshot.js <wallet-ui-url> <output-png>
const path = require("path");
const { chromium } = require(path.join(__dirname, "..", "e2e", "node_modules", "@playwright/test"));

(async () => {
  const [url, out] = process.argv.slice(2);
  if (!url || !out) {
    console.error("usage: oidf_capture_screenshot.js <wallet-ui-url> <output-png>");
    process.exit(2);
  }
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    await page.goto(url, { waitUntil: "networkidle", timeout: 15000 }).catch(() => {});
    // The error banner arrives over the event stream shortly after load.
    await page.waitForTimeout(1500);
    await page.screenshot({ path: out });
  } finally {
    await browser.close();
  }
})().catch((err) => {
  console.error(String(err));
  process.exit(1);
});
