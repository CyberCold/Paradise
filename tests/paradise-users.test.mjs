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
});

test("UA parser keeps notification labels stable", () => {
  const android = __test.parseUA("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36");
  assert.equal(android.device, "Android Phone");
  assert.equal(android.os, "Android");
  assert.equal(android.browser, "Chrome");
});
