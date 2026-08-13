// @ts-check
const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: ".",
  testMatch: "*.spec.js",
  timeout: 30_000,
  // The suite runs against a single shared wallet server, so a slow CI runner
  // can occasionally lose a timing race between tests. Retry in CI so a
  // transient flake does not fail the run; keep local runs strict.
  retries: process.env.CI ? 2 : 0,
  use: {
    baseURL: "http://localhost:18923",
    headless: true,
  },
  webServer: {
    command: "go build -o /tmp/oid4vc-dev-e2e .. && /tmp/oid4vc-dev-e2e serve --port 18923",
    url: "http://localhost:18923",
    reuseExistingServer: true,
    // CI runners frequently hit a cold Go build here, so allow enough time
    // for the binary to compile and the HTTP server to become healthy.
    timeout: 60_000,
  },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
  ],
});
