import assert from "node:assert/strict";
import test from "node:test";

import adminWorker, { __test } from "../workers/paradise-admin.js";

const deviceA = "a".repeat(64);
const deviceB = "b".repeat(64);
const DASHBOARD_BOT_TOKEN = "123456789:test-dashboard-token";

function user(id, ip, deviceKey) {
  return {
    id,
    first_name: `User ${id}`,
    username: `user${id}`,
    ips: [{ ip, visits: 1 }],
    visits: [],
    fingerprint: {},
    device_keys: deviceKey ? [deviceKey] : [],
  };
}

test("ban preview finds accounts linked by exact IP and device key", async () => {
  const users = {
    "1": user(1, "1.1.1.1", deviceA),
    "2": user(2, "1.1.1.1", deviceB),
    "3": user(3, "3.3.3.3", deviceA),
    "4": user(4, "4.4.4.4", deviceB),
  };
  const preview = await __test.buildBanPreview("test-secret", users, {
    target_id: "1",
    scopes: { ip: true, device: true },
  });
  assert.deepEqual(preview.user_ids, ["1", "2", "3"]);
  assert.equal(preview.ip_hashes.length, 1);
  assert.deepEqual(preview.device_hashes, [deviceA]);
  assert.ok(!JSON.stringify(preview).includes("1.1.1.1"));
});

test("manual related IDs are included even when automatic scopes are disabled", async () => {
  const users = {
    "1": user(1, "1.1.1.1", deviceA),
    "4": user(4, "4.4.4.4", deviceB),
  };
  const preview = await __test.buildBanPreview("test-secret", users, {
    target_id: "1",
    extra_ids: ["4"],
    scopes: { ip: false, device: false },
  });
  assert.deepEqual(preview.user_ids, ["1", "4"]);
  assert.equal(preview.ip_hashes.length, 0);
  assert.equal(preview.device_hashes.length, 0);
});

test("blacklist normalisation never keeps invalid hashes or duplicate IDs", () => {
  const data = __test.normaliseBlacklist({
    entries: [{
      id: "ban 1",
      root_user_id: "1",
      user_ids: ["1", "1", "bad"],
      ip_hashes: ["c".repeat(64), "not-a-hash"],
      device_hashes: [],
    }],
  });
  assert.equal(data.entries[0].id, "ban-1");
  assert.deepEqual(data.entries[0].user_ids, ["1"]);
  assert.deepEqual(data.entries[0].ip_hashes, ["c".repeat(64)]);
});

async function signedInitData(userId, botToken = DASHBOARD_BOT_TOKEN, authDate = Math.floor(Date.now() / 1000)) {
  const values = new URLSearchParams({
    user: JSON.stringify({ id: userId, first_name: "Admin" }),
    auth_date: String(authDate),
    query_id: "dashboard-test-query",
  });
  const checkString = [...values.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");
  const encoder = new TextEncoder();
  const sign = async (keyBytes, data) => {
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(data)));
  };
  const secret = await sign(encoder.encode("WebAppData"), botToken);
  values.set("hash", Buffer.from(await sign(secret, checkString)).toString("hex"));
  return values.toString();
}

async function adminSessionRequest(userId, botToken = DASHBOARD_BOT_TOKEN) {
  const initData = await signedInitData(userId, botToken);
  return new Request("https://paradise-admin.example/session", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: "https://testikusik.vercel.app" },
    body: JSON.stringify({ initData }),
  });
}

function adminEnv() {
  return {
    BOT_TOKEN: DASHBOARD_BOT_TOKEN,
    GITHUB_TOKEN: "test-token",
    ADMIN_IDS: "7511735897",
    BAN_SECRET: "test-ban-secret",
  };
}

test("dashboard bot signature opens an admin session", async () => {
  const response = await adminWorker.fetch(await adminSessionRequest(7511735897), adminEnv());
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.user.id, 7511735897);
  assert.ok(body.session);
});

test("validated non-admin IDs still cannot open the dashboard", async () => {
  const response = await adminWorker.fetch(await adminSessionRequest(8482703228), adminEnv());
  const body = await response.json();
  assert.equal(response.status, 403);
  assert.match(body.error, /8482703228/);
});

test("invalid Telegram sessions never receive an admin session", async () => {
  const response = await adminWorker.fetch(await adminSessionRequest(7511735897, `${DASHBOARD_BOT_TOKEN}-wrong`), adminEnv());
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error, "Telegram session is invalid");
});

test("dashboard accepts a valid Swiftgram session older than 24 hours", async () => {
  const now = Math.floor(Date.now() / 1000);
  const initData = await signedInitData(7511735897, DASHBOARD_BOT_TOKEN, now - (26 * 60 * 60));
  assert.equal((await __test.verifyTelegramInitData(initData, DASHBOARD_BOT_TOKEN, now))?.id, 7511735897);
});
