import assert from "node:assert/strict";
import test from "node:test";

import { __test } from "../workers/paradise-users.js";

test("GitHub Base64 round-trip preserves UTF-8 names", () => {
  const original = JSON.stringify({
    first_name: "АК",
    japanese: "私はクソピエロだ",
    emoji: "Изя💋",
  });
  assert.equal(__test.base64ToText(__test.textToBase64(original)), original);
});

test("cleanText preserves Unicode and bounds hostile input", () => {
  assert.equal(__test.cleanText("  АК💋  ", 70), "АК💋");
  assert.equal([...__test.cleanText("я".repeat(5000), 70)].length, 70);
});

test("database cleanup never drops valid user IDs", () => {
  const source = {
    "1": { id: 1, first_name: "A" },
    "2": { id: 2, first_name: "Б" },
  };
  const cleaned = __test.cleanDatabase(source);
  assert.deepEqual(Object.keys(cleaned), ["1", "2"]);
});

test("merge keeps existing history and adds exactly one visit", () => {
  const previous = {
    id: 7,
    first_name: "Old",
    username: "old_user",
    registered: "2026-07-01T00:00:00.000Z",
    last_seen: "2026-07-01T00:00:00.000Z",
    visit_count: 4,
    visits: [{ timestamp: "2026-07-01T00:00:00.000Z", ip: "1.1.1.1" }],
    ips: [{ ip: "1.1.1.1", first_seen: "2026-07-01T00:00:00.000Z", last_seen: "2026-07-01T00:00:00.000Z", visits: 4 }],
  };
  const now = "2026-07-18T06:00:00.000Z";
  const visit = { timestamp: now, ip: "1.1.1.1", device: "iPhone", os: "iOS", browser: "Safari" };
  const merged = __test.mergeUser(
    previous,
    { id: 7, first_name: "Новое имя", username: "new_user" },
    visit,
    {},
    ["a".repeat(64)],
    { device: "iPhone", browser: "Safari", os: "iOS" },
    { country: "LV", city: "Riga" },
    now,
  );

  assert.equal(merged.first_name, "Новое имя");
  assert.equal(merged.username, "new_user");
  assert.equal(merged.registered, "2026-07-01T00:00:00.000Z");
  assert.equal(merged.visit_count, 5);
  assert.equal(merged.visits.length, 2);
  assert.equal(merged.ips.length, 1);
  assert.equal(merged.ips[0].visits, 5);
  assert.deepEqual(merged.device_keys, ["a".repeat(64)]);
});

test("UA parser keeps notification labels stable", () => {
  const android = __test.parseUA("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36");
  assert.equal(android.device, "Android Phone");
  assert.equal(android.os, "Android");
  assert.equal(android.browser, "Chrome");
});

test("device keys link Telegram accounts without storing the installation ID", async () => {
  const fingerprint = {
    install_id: "browser-installation-123456",
    screen: "1179x2556@3",
    timezone: "Europe/Riga",
    colorDepth: 24,
    touch: 5,
    platform: "iPhone",
    cores: 6,
    languages: ["ru", "en"],
  };
  const first = await __test.deviceKeysForFingerprint("test-secret", fingerprint, { device: "iPhone", os: "iOS" });
  const second = await __test.deviceKeysForFingerprint("test-secret", fingerprint, { device: "iPhone", os: "iOS" });
  assert.deepEqual(first, second);
  assert.equal(first.length, 2);
  assert.ok(first.every((value) => /^[a-f0-9]{64}$/.test(value)));
  assert.ok(!JSON.stringify(first).includes(fingerprint.install_id));
});

test("blacklist matches account, network, and device hashes", () => {
  const blacklist = __test.normaliseBlacklist({
    entries: [{
      id: "ban-1",
      root_user_id: "100",
      user_ids: ["100", "101"],
      ip_hashes: ["b".repeat(64)],
      device_hashes: ["c".repeat(64)],
      active: true,
    }],
  });
  assert.equal(__test.findBlacklistMatch(blacklist, "101", "", [])?.matched_by, "account");
  assert.equal(__test.findBlacklistMatch(blacklist, "200", "b".repeat(64), [])?.matched_by, "network");
  assert.equal(__test.findBlacklistMatch(blacklist, "300", "", ["c".repeat(64)])?.matched_by, "device");
  assert.equal(__test.findBlacklistMatch(blacklist, "400", "", []), null);
});
