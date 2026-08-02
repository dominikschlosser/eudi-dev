// @ts-check
const { test, expect } = require("@playwright/test");
const { execSync } = require("child_process");
const http = require("http");

const DOCKER_IMAGE = "oid4vc-dev-e2e";
const CONTAINER_NAME = "oid4vc-dev-e2e-test";
// Must not collide with ports bound by the other (parallel) spec files:
// 18923 (webServer), 18924 (wallet.spec), 18925 (wallet.spec HTTPS port+1),
// 18926 (wallet.spec issuer base URL).
const HOST_PORT = 18935;
const WALLET_URL = `http://localhost:${HOST_PORT}`;

test.describe.configure({ mode: "serial" });
// Docker build + container startup can exceed the default 30s timeout
test.setTimeout(120_000);

test.beforeAll(async ({ }, testInfo) => {
  testInfo.setTimeout(120_000);
  // Build Docker image (can take a while in CI with cold cache)
  execSync(`docker build -t ${DOCKER_IMAGE} ..`, {
    cwd: __dirname,
    stdio: "pipe",
    timeout: 120_000,
  });

  // Remove any leftover container
  try {
    execSync(`docker rm -f ${CONTAINER_NAME}`, { stdio: "pipe" });
  } catch {}

  // Start container with default CMD (wallet serve --auto-accept --pid --port 8085)
  execSync(
    `docker run -d --name ${CONTAINER_NAME} -p ${HOST_PORT}:8085 ${DOCKER_IMAGE}`,
    { stdio: "pipe" }
  );

  // Wait for server to be ready
  await waitForServer(WALLET_URL, 30_000);
});

test.afterAll(async () => {
  try {
    execSync(`docker rm -f ${CONTAINER_NAME}`, { stdio: "pipe" });
  } catch {}
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
      await new Promise((r) => setTimeout(r, 300));
    }
  }
  throw new Error(`Server at ${url} did not start within ${timeoutMs}ms`);
}

function httpGet(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => resolve({ status: res.statusCode, body }));
      res.on("error", reject);
    });
  });
}

test.describe("Docker Image", () => {
  test("wallet serves UI at /", async ({ page }) => {
    const response = await page.goto(WALLET_URL);
    expect(response.status()).toBe(200);
    await expect(page.locator("h1")).toHaveText("EUDI Dev Wallet");
  });

  test("wallet has PID credentials pre-loaded", async () => {
    const res = await httpGet(`${WALLET_URL}/api/credentials`);
    expect(res.status).toBe(200);
    const creds = JSON.parse(res.body);
    expect(creds.length).toBe(2);

    const formats = creds.map((c) => c.format);
    expect(formats).toContain("dc+sd-jwt");
    expect(formats).toContain("mso_mdoc");
  });

  test("trust list endpoint is available", async () => {
    const res = await httpGet(`${WALLET_URL}/api/trustlist`);
    expect(res.status).toBe(200);
    // Trust list is a JWT (three dot-separated parts)
    expect(res.body.split(".").length).toBe(3);
  });

  test("version is set", () => {
    const output = execSync(
      `docker run --rm ${DOCKER_IMAGE} version`
    ).toString().trim();
    expect(output).toContain("dev");
  });

  test("decode works via stdin", () => {
    // Create a minimal JWT to decode
    const header = Buffer.from('{"alg":"none","typ":"JWT"}').toString("base64url");
    const payload = Buffer.from('{"sub":"test","iss":"example"}').toString("base64url");
    const jwt = `${header}.${payload}.`;

    const output = execSync(
      `echo '${jwt}' | docker run -i --rm ${DOCKER_IMAGE} decode --json`,
      { encoding: "utf-8" }
    );
    const parsed = JSON.parse(output);
    expect(parsed.payload.sub).toBe("test");
  });
});
