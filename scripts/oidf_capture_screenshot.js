// Capture the wallet error UI for negative OIDF modules that finish in REVIEW and require
// screenshot evidence.
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
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
    await page.locator("#error-dismiss").waitFor({ state: "visible", timeout: 15000 });
    await page.screenshot({ path: out });
  } finally {
    await browser.close();
  }
})().catch((err) => {
  console.error(String(err));
  process.exit(1);
});
