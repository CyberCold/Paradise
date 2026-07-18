import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { __test } from "../workers/paradise-users.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const usersPath = path.join(root, "users.json");
const webappPath = path.join(root, "webapp_users.json");

function git(...args) {
  return execFileSync("git", ["-c", `safe.directory=${root}`, ...args], {
    cwd: root,
    maxBuffer: 128 * 1024 * 1024,
  });
}

function decodeMojibake(value) {
  let current = String(value ?? "");
  for (let round = 0; round < 16 && current; round += 1) {
    if (![...current].every((char) => char.codePointAt(0) <= 255)) break;
    const next = Buffer.from(current, "latin1").toString("utf8");
    if (next === current || next.includes("\uFFFD")) break;
    current = next;
  }
  return current;
}

function repairIdentity(record = {}) {
  return {
    ...record,
    first_name: decodeMojibake(record.first_name),
    last_name: decodeMojibake(record.last_name),
    username: decodeMojibake(record.username),
  };
}

function earlierIso(left, right) {
  const values = [left, right].filter((value) => value && !Number.isNaN(Date.parse(value)));
  return values.sort((a, b) => Date.parse(a) - Date.parse(b))[0] || "";
}

function laterIso(left, right) {
  const values = [left, right].filter((value) => value && !Number.isNaN(Date.parse(value)));
  return values.sort((a, b) => Date.parse(b) - Date.parse(a))[0] || "";
}

function cleanWebRecord(uid, record) {
  return __test.cleanDatabase({ [uid]: repairIdentity(record) })[uid];
}

const originalUsers = JSON.parse(await readFile(usersPath, "utf8"));
const originalWebapp = JSON.parse(await readFile(webappPath, "utf8"));
const restoredWebapp = {};

for (const [uid, record] of Object.entries(originalWebapp)) {
  restoredWebapp[uid] = cleanWebRecord(uid, record);
}

const webappCommits = git("log", "--format=%H", "origin/main", "--", "webapp_users.json")
  .toString("utf8")
  .trim()
  .split(/\r?\n/)
  .filter(Boolean);

for (const commit of webappCommits) {
  let historical;
  try {
    historical = JSON.parse(git("show", `${commit}:webapp_users.json`).toString("utf8"));
  } catch {
    continue;
  }
  if (!historical || typeof historical !== "object" || Array.isArray(historical)) continue;
  for (const [uid, record] of Object.entries(historical)) {
    if (!restoredWebapp[uid]) restoredWebapp[uid] = cleanWebRecord(uid, record);
  }
}

for (const [uid, record] of Object.entries(originalUsers)) {
  const sources = new Set([record?.source, ...(Array.isArray(record?.sources) ? record.sources : [])].filter(Boolean));
  if (sources.has("webapp") && !restoredWebapp[uid]) restoredWebapp[uid] = cleanWebRecord(uid, record);
}

const repairedUsers = {};
let repairedIdentityCount = 0;
for (const [uid, record] of Object.entries(originalUsers)) {
  const repaired = repairIdentity(record);
  if (
    repaired.first_name !== String(record?.first_name ?? "")
    || repaired.last_name !== String(record?.last_name ?? "")
    || repaired.username !== String(record?.username ?? "")
  ) repairedIdentityCount += 1;
  repairedUsers[uid] = repaired;
}

let enrichedCount = 0;
let addedToUsersCount = 0;
for (const [uid, webappRecord] of Object.entries(restoredWebapp)) {
  const current = repairedUsers[uid];
  if (!current) {
    repairedUsers[uid] = { ...webappRecord, sources: ["webapp"] };
    addedToUsersCount += 1;
    continue;
  }

  const sources = [...new Set([current.source, ...(Array.isArray(current.sources) ? current.sources : []), "webapp"].filter(Boolean))];
  repairedUsers[uid] = {
    ...current,
    ...webappRecord,
    id: current.id ?? webappRecord.id,
    first_name: webappRecord.first_name || current.first_name || "",
    last_name: webappRecord.last_name || current.last_name || "",
    username: webappRecord.username || current.username || "",
    source: current.source || "webapp",
    sources,
    registered: earlierIso(current.registered, webappRecord.registered),
    last_seen: laterIso(current.last_seen, webappRecord.last_seen),
  };
  enrichedCount += 1;
}

await writeFile(webappPath, `${JSON.stringify(restoredWebapp, null, 2)}\n`, "utf8");
await writeFile(usersPath, `${JSON.stringify(repairedUsers, null, 2)}\n`, "utf8");

console.log(JSON.stringify({
  usersBefore: Object.keys(originalUsers).length,
  usersAfter: Object.keys(repairedUsers).length,
  webappBefore: Object.keys(originalWebapp).length,
  webappAfter: Object.keys(restoredWebapp).length,
  repairedIdentityCount,
  enrichedCount,
  addedToUsersCount,
}, null, 2));
