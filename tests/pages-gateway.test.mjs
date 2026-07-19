import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";

import { onRequest as openApp } from "../functions/app.js";
import { onRequest as routeStatic } from "../functions/[[path]].js";
import { onRequest as protectedRoute } from "../functions/protected/[[path]].js";
import { createSessionCookie, telegramUserId, verifySessionCookie } from "../functions/_shared/session.js";

const TEST_SECRET = "test-secret-with-enough-entropy-for-hmac";
const VALID_INIT_DATA = "user=%7B%22id%22%3A8482703228%2C%22first_name%22%3A%22Admin%22%7D&auth_date=1&hash=signed";

function request(method = "POST", body = { initData: VALID_INIT_DATA, fingerprint: {} }) {
  return new Request("https://paradiseminiapp.pages.dev/app", {
    method,
    headers: method === "POST" ? { "Content-Type": "application/json" } : {},
    body: method === "POST" ? JSON.stringify(body) : undefined,
  });
}

test("public bootstrap does not contain the catalogue payload", async () => {
  const publicHtml = await fs.readFile(new URL("../index.html", import.meta.url), "utf8");
  const protectedHtml = await fs.readFile(new URL("../protected/index.html", import.meta.url), "utf8");
  assert.ok(publicHtml.length < 20_000);
  assert.ok(protectedHtml.length > 100_000);
  assert.equal(publicHtml.includes("adminProductList"), false);
  assert.equal(publicHtml.includes("catalogOverrides"), false);
});

test("public and protected inline scripts parse", async () => {
  for (const path of ["../index.html", "../protected/index.html"]) {
    const html = await fs.readFile(new URL(path, import.meta.url), "utf8");
    const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)];
    assert.ok(scripts.length > 0);
    for (const script of scripts) assert.doesNotThrow(() => new Function(script[1]));
  }
});

test("protected static route is never served directly", async () => {
  const response = protectedRoute();
  assert.equal(response.status, 404);
  assert.match(response.headers.get("Cache-Control"), /no-store/);
});

test("gateway never serves app assets when access is denied", async () => {
  let assetReads = 0;
  const response = await openApp({
    request: request(),
    env: {
      BAN_SECRET: TEST_SECRET,
      PARADISE_USERS: { fetch: async () => new Response(JSON.stringify({ blocked: true }), { status: 403 }) },
      ASSETS: { fetch: async () => { assetReads += 1; return new Response("secret"); } },
    },
  });
  assert.equal(response.status, 403);
  assert.equal(assetReads, 0);
});

test("gateway serves protected HTML only after access succeeds", async () => {
  let assetReads = 0;
  const response = await openApp({
    request: request(),
    env: {
      BAN_SECRET: TEST_SECRET,
      PARADISE_USERS: { fetch: async () => new Response(JSON.stringify({ access: true }), { status: 200 }) },
      ASSETS: {
        fetch: async (url) => {
          assetReads += 1;
          assert.equal(new URL(url).pathname, "/protected/");
          return new Response("<html>catalogue</html>", { status: 200 });
        },
      },
    },
  });
  assert.equal(response.status, 200);
  assert.equal(assetReads, 1);
  assert.match(await response.text(), /catalogue/);
  assert.match(response.headers.get("Cache-Control"), /no-store/);
  assert.match(response.headers.get("Set-Cookie"), /__Host-paradise_session=/);
});

test("session cookies are signed, expire, and preserve the Telegram ID", async () => {
  assert.equal(telegramUserId(VALID_INIT_DATA), "8482703228");
  const now = Date.now();
  const cookie = await createSessionCookie(TEST_SECRET, "8482703228", now);
  assert.equal((await verifySessionCookie(TEST_SECRET, cookie, now))?.userId, "8482703228");
  assert.equal(await verifySessionCookie(`${TEST_SECRET}-wrong`, cookie, now), null);
  assert.equal(await verifySessionCookie(TEST_SECRET, cookie, now + 301_000), null);
});

test("Pages routing hides source and data files from unauthenticated requests", async () => {
  let assetReads = 0;
  const env = { BAN_SECRET: TEST_SECRET, ASSETS: { fetch: async () => { assetReads += 1; return new Response("asset"); } } };
  const source = await routeStatic({ request: new Request("https://example.test/workers/paradise-users.js"), env });
  const users = await routeStatic({ request: new Request("https://example.test/users.json"), env });
  const banners = await routeStatic({ request: new Request("https://example.test/banners.json"), env });
  assert.equal(source.status, 404);
  assert.equal(users.status, 404);
  assert.equal(banners.status, 404);
  assert.equal(assetReads, 0);
});

test("only a valid short session can read catalogue JSON assets", async () => {
  let assetReads = 0;
  const cookie = await createSessionCookie(TEST_SECRET, "8482703228");
  const env = { BAN_SECRET: TEST_SECRET, ASSETS: { fetch: async () => { assetReads += 1; return new Response("[]"); } } };
  const response = await routeStatic({
    request: new Request("https://example.test/banners.json", { headers: { Cookie: cookie } }),
    env,
  });
  assert.equal(response.status, 200);
  assert.equal(assetReads, 1);
});
