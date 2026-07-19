const REPO = "CyberCold/Paradise";
const BRANCH = "main";
const FILE = "webapp_users.json";
const BLACKLIST_FILE = "blacklist.json";
const ADMIN_ID = "7511735897";
const ALLOWED_ORIGIN = "https://paradiseminiapp.pages.dev";
const GITHUB_API = `https://api.github.com/repos/${REPO}/contents/${FILE}`;
const BLACKLIST_API = `https://api.github.com/repos/${REPO}/contents/${BLACKLIST_FILE}`;
const MAX_RETRIES = 5;
const MAX_VISITS = 30;
const MAX_IPS = 20;
const MAX_DEVICE_KEYS = 8;
const BLACKLIST_CACHE_MS = 10_000;
const TELEGRAM_INIT_DATA_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
const TELEGRAM_INIT_DATA_CLOCK_SKEW_SECONDS = 5 * 60;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
let blacklistCache = null;
let blacklistCacheAt = 0;

function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  if (origin !== ALLOWED_ORIGIN) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    Vary: "Origin",
  };
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });
}

function cleanText(value, maxLength = 160) {
  return [...String(value ?? "")
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, "")
    .trim()]
    .slice(0, maxLength)
    .join("");
}

function cleanArray(value, maxItems = 10, itemLength = 80) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, maxItems).map((item) => cleanText(item, itemLength)).filter(Boolean);
}

function cleanNumber(value, fallback = null) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function cleanBoolean(value) {
  return value === true;
}

function cleanIso(value, fallback = "") {
  const text = cleanText(value, 40);
  return text && !Number.isNaN(Date.parse(text)) ? text : fallback;
}

function cleanUrl(value, maxLength = 400) {
  const text = cleanText(value, maxLength);
  if (!text) return null;
  try {
    const url = new URL(text);
    return /^https?:$/.test(url.protocol) ? url.href : null;
  } catch {
    return null;
  }
}

function base64ToText(value) {
  const binary = atob(String(value || "").replace(/\s/g, ""));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return decoder.decode(bytes);
}

function textToBase64(value) {
  const bytes = encoder.encode(value);
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

async function hmac(keyBytes, valueBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, valueBytes));
}

function bytesToHex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function identifierHash(secret, kind, value) {
  const cleanValue = cleanText(value, 1200);
  if (!secret || !cleanValue) return "";
  return bytesToHex(await hmac(encoder.encode(secret), encoder.encode(`paradise-ban:${kind}:${cleanValue}`)));
}

function constantTimeEqual(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

async function verifyTelegramInitData(initData, botToken, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!initData || initData.length > 8192) return null;
  const values = new URLSearchParams(initData);
  const suppliedHash = values.get("hash") || "";
  const authDate = Number(values.get("auth_date"));
  const userText = values.get("user") || "";
  values.delete("hash");

  if (!/^[a-f0-9]{64}$/i.test(suppliedHash) || !authDate || !userText) return null;
  if (authDate > nowSeconds + TELEGRAM_INIT_DATA_CLOCK_SKEW_SECONDS) return null;
  if (nowSeconds - authDate > TELEGRAM_INIT_DATA_MAX_AGE_SECONDS) return null;

  const checkString = [...values.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");
  const webAppKey = await hmac(encoder.encode("WebAppData"), encoder.encode(botToken));
  const expected = await hmac(webAppKey, encoder.encode(checkString));
  const supplied = Uint8Array.from(suppliedHash.match(/.{2}/g) || [], (pair) => Number.parseInt(pair, 16));
  if (!constantTimeEqual(expected, supplied)) return null;

  try {
    const user = JSON.parse(userText);
    return Number.isSafeInteger(Number(user?.id)) ? user : null;
  } catch {
    return null;
  }
}

function telegramUserFromInitData(initData) {
  try {
    const user = JSON.parse(new URLSearchParams(String(initData || "")).get("user") || "null");
    const id = String(user?.id || "");
    if (!/^\d{5,20}$/.test(id)) return null;
    return { ...user, id: Number(id) };
  } catch {
    return null;
  }
}

function parseUA(userAgent) {
  const ua = String(userAgent || "");
  const result = { device: "Unknown", browser: "unknown", browserVersion: null, os: "Unknown", osVersion: null };

  if (/iPhone/i.test(ua)) {
    result.device = "iPhone";
    result.os = "iOS";
    result.osVersion = ua.match(/OS ([\d_]+)/i)?.[1]?.replace(/_/g, ".") || null;
  } else if (/iPad/i.test(ua)) {
    result.device = "iPad";
    result.os = "iOS";
    result.osVersion = ua.match(/OS ([\d_]+)/i)?.[1]?.replace(/_/g, ".") || null;
  } else if (/Android/i.test(ua)) {
    result.device = /Mobile/i.test(ua) ? "Android Phone" : "Android Tablet";
    result.os = "Android";
    result.osVersion = ua.match(/Android\s+([\d.]+)/i)?.[1] || null;
  } else if (/Windows/i.test(ua)) {
    result.device = "Desktop";
    result.os = "Windows";
  } else if (/Macintosh|Mac OS X/i.test(ua)) {
    result.device = "Desktop";
    result.os = "macOS";
    result.osVersion = ua.match(/Mac OS X\s+([\d_]+)/i)?.[1]?.replace(/_/g, ".") || null;
  } else if (/Linux/i.test(ua)) {
    result.device = "Desktop";
    result.os = "Linux";
  }

  const browsers = [
    [/EdgA?\/([\d.]+)/i, "Edge"],
    [/OPR\/([\d.]+)/i, "Opera"],
    [/CriOS\/([\d.]+)/i, "Chrome"],
    [/Chrome\/([\d.]+)/i, "Chrome"],
    [/FxiOS\/([\d.]+)/i, "Firefox"],
    [/Firefox\/([\d.]+)/i, "Firefox"],
    [/Version\/([\d.]+).*Safari/i, "Safari"],
  ];
  for (const [pattern, name] of browsers) {
    const match = ua.match(pattern);
    if (match) {
      result.browser = name;
      result.browserVersion = match[1] || null;
      break;
    }
  }
  return result;
}

function cleanFingerprint(value = {}) {
  return {
    screen: cleanText(value.screen, 40) || null,
    timezone: cleanText(value.timezone, 80) || null,
    color_depth: cleanNumber(value.color_depth ?? value.colorDepth),
    touch: cleanNumber(value.touch),
    platform: cleanText(value.platform, 80) || null,
    memory: cleanNumber(value.memory),
    cores: cleanNumber(value.cores),
    connection: cleanText(value.connection, 80) || null,
    webgl_vendor: cleanText(value.webgl_vendor ?? value.webglVendor, 120) || null,
    webgl_renderer: cleanText(value.webgl_renderer ?? value.webglRenderer, 180) || null,
    languages: cleanArray(value.languages, 12, 30),
    ua_platform: cleanText(value.ua_platform ?? value.uaPlatform, 80) || null,
    ua_platform_version: cleanText(value.ua_platform_version ?? value.uaPlatformVersion, 80) || null,
    ua_architecture: cleanText(value.ua_architecture ?? value.uaArchitecture, 40) || null,
    ua_bitness: cleanText(value.ua_bitness ?? value.uaBitness, 20) || null,
    ua_model: cleanText(value.ua_model ?? value.uaModel, 120) || null,
    ua_mobile: value.ua_mobile === true || value.uaMobile === true,
    device: cleanText(value.device, 40) || null,
    browser: cleanText(value.browser, 40) || null,
    os: cleanText(value.os, 40) || null,
    updated_at: cleanIso(value.updated_at),
  };
}

function hardwareSignature(value = {}, uaParsed = {}) {
  const fingerprint = cleanFingerprint(value);
  const parts = {
    screen: fingerprint.screen,
    timezone: fingerprint.timezone,
    color_depth: fingerprint.color_depth,
    touch: fingerprint.touch,
    platform: fingerprint.platform,
    memory: fingerprint.memory,
    cores: fingerprint.cores,
    webgl_vendor: fingerprint.webgl_vendor,
    webgl_renderer: fingerprint.webgl_renderer,
    languages: fingerprint.languages.length ? fingerprint.languages : null,
    ua_platform: fingerprint.ua_platform,
    ua_platform_version: fingerprint.ua_platform_version,
    ua_architecture: fingerprint.ua_architecture,
    ua_bitness: fingerprint.ua_bitness,
    ua_model: fingerprint.ua_model,
    ua_mobile: fingerprint.ua_mobile,
    device: uaParsed.device || fingerprint.device,
    os: uaParsed.os || fingerprint.os,
  };
  const present = Object.entries(parts).filter(([, item]) => item !== null && item !== "" && item !== false);
  const hasAnchor = [parts.screen, parts.webgl_renderer, parts.cores, parts.memory, parts.ua_model].some(
    (item) => item !== null && item !== "",
  );
  if (present.length < 5 || !hasAnchor) return "";
  return JSON.stringify(Object.fromEntries(present));
}

async function deviceKeysForFingerprint(secret, value = {}, uaParsed = {}) {
  const keys = [];
  const installId = cleanText(value.install_id ?? value.installId, 120);
  if (/^[a-zA-Z0-9_-]{16,120}$/.test(installId)) {
    keys.push(await identifierHash(secret, "device-install", installId));
  }
  const hardware = hardwareSignature(value, uaParsed);
  if (hardware) keys.push(await identifierHash(secret, "device-hardware", hardware));
  return [...new Set(keys.filter(Boolean))].slice(0, MAX_DEVICE_KEYS);
}

function buildFingerprint(previous, incoming, uaParsed, now) {
  const next = cleanFingerprint({ ...previous, ...incoming });
  next.device = uaParsed.device || next.device;
  next.browser = uaParsed.browser || next.browser;
  next.os = uaParsed.os || next.os;
  next.updated_at = now;
  return next;
}

function cleanGeo(value = {}) {
  return {
    country: cleanText(value.country, 8) || "unknown",
    city: cleanText(value.city, 100) || null,
    region: cleanText(value.region, 100) || null,
    timezone: cleanText(value.timezone, 80) || null,
    asn: cleanNumber(value.asn),
    isp: cleanText(value.isp, 160) || null,
    lat: cleanNumber(value.lat),
    lon: cleanNumber(value.lon),
  };
}

function cleanVisit(value = {}) {
  return {
    timestamp: cleanIso(value.timestamp),
    ip: cleanText(value.ip, 64) || "unknown",
    country: cleanText(value.country, 8) || "unknown",
    city: cleanText(value.city, 100) || null,
    region: cleanText(value.region, 100) || null,
    url: cleanUrl(value.url),
    referrer: cleanUrl(value.referrer),
    user_agent: cleanText(value.user_agent, 500),
    device: cleanText(value.device, 40) || "Unknown",
    browser: cleanText(value.browser, 40) || "unknown",
    browser_version: cleanText(value.browser_version, 40) || null,
    os: cleanText(value.os, 40) || "Unknown",
    os_version: cleanText(value.os_version, 40) || null,
    language: cleanText(value.language, 40) || null,
    cf_ray: cleanText(value.cf_ray, 60) || null,
    screen: cleanText(value.screen, 40) || null,
    tz_client: cleanText(value.tz_client, 80) || null,
    color_depth: cleanNumber(value.color_depth),
    touch: cleanNumber(value.touch),
    platform: cleanText(value.platform, 80) || null,
    memory: cleanNumber(value.memory),
    cores: cleanNumber(value.cores),
    connection: cleanText(value.connection, 80) || null,
    webgl_vendor: cleanText(value.webgl_vendor, 120) || null,
    webgl_renderer: cleanText(value.webgl_renderer, 180) || null,
    languages: cleanArray(value.languages, 12, 30),
    ua_platform: cleanText(value.ua_platform, 80) || null,
    ua_platform_version: cleanText(value.ua_platform_version, 80) || null,
    ua_architecture: cleanText(value.ua_architecture, 40) || null,
    ua_bitness: cleanText(value.ua_bitness, 20) || null,
    ua_model: cleanText(value.ua_model, 120) || null,
    ua_mobile: value.ua_mobile === true,
  };
}

function cleanIp(value = {}) {
  return {
    ip: cleanText(value.ip, 64) || "unknown",
    country: cleanText(value.country, 8) || "unknown",
    city: cleanText(value.city, 100) || null,
    region: cleanText(value.region, 100) || null,
    isp: cleanText(value.isp, 160) || null,
    asn: cleanNumber(value.asn),
    lat: cleanNumber(value.lat),
    lon: cleanNumber(value.lon),
    first_seen: cleanIso(value.first_seen),
    last_seen: cleanIso(value.last_seen),
    visits: Math.max(1, Math.floor(cleanNumber(value.visits, 1))),
  };
}

function cleanRecord(value, uid) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Invalid user record: ${uid}`);
  return {
    id: Number.isSafeInteger(Number(value.id)) ? Number(value.id) : Number(uid),
    first_name: cleanText(value.first_name, 70),
    last_name: cleanText(value.last_name, 70),
    username: cleanText(value.username, 40).replace(/^@/, ""),
    language_code: cleanText(value.language_code, 20),
    is_premium: cleanBoolean(value.is_premium),
    source: "webapp",
    registered: cleanIso(value.registered),
    last_seen: cleanIso(value.last_seen),
    visit_count: Math.max(0, Math.floor(cleanNumber(value.visit_count, 0))),
    ips: (Array.isArray(value.ips) ? value.ips : []).slice(0, MAX_IPS).map(cleanIp),
    visits: (Array.isArray(value.visits) ? value.visits : []).slice(0, MAX_VISITS).map(cleanVisit),
    fingerprint: cleanFingerprint(value.fingerprint),
    device_keys: cleanArray(value.device_keys, MAX_DEVICE_KEYS, 64).filter((key) => /^[a-f0-9]{64}$/i.test(key)),
    geo: cleanGeo(value.geo),
  };
}

function cleanDatabase(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("GitHub user database is not an object");
  const result = {};
  for (const [rawUid, record] of Object.entries(value)) {
    const uid = cleanText(rawUid, 24);
    if (!/^\d+$/.test(uid)) throw new Error("GitHub user database contains an invalid ID");
    result[uid] = cleanRecord(record, uid);
  }
  return result;
}

function createVisit(request, fingerprint, uaParsed, geo, now) {
  return cleanVisit({
    timestamp: now,
    ip: request.headers.get("CF-Connecting-IP") || "unknown",
    country: geo.country,
    city: geo.city,
    region: geo.region,
    url: request.url,
    referrer: request.headers.get("Referer") || "",
    user_agent: request.headers.get("User-Agent") || "",
    device: uaParsed.device,
    browser: uaParsed.browser,
    browser_version: uaParsed.browserVersion,
    os: uaParsed.os,
    os_version: uaParsed.osVersion,
    language: request.headers.get("Accept-Language")?.split(",")[0] || "",
    cf_ray: request.headers.get("CF-Ray") || "",
    screen: fingerprint.screen,
    tz_client: fingerprint.timezone,
    color_depth: fingerprint.colorDepth,
    touch: fingerprint.touch,
    platform: fingerprint.platform,
    memory: fingerprint.memory,
    cores: fingerprint.cores,
    connection: fingerprint.connection,
    webgl_vendor: fingerprint.webglVendor,
    webgl_renderer: fingerprint.webglRenderer,
    languages: fingerprint.languages,
    ua_platform: fingerprint.uaPlatform,
    ua_platform_version: fingerprint.uaPlatformVersion,
    ua_architecture: fingerprint.uaArchitecture,
    ua_bitness: fingerprint.uaBitness,
    ua_model: fingerprint.uaModel,
    ua_mobile: fingerprint.uaMobile,
  });
}

function requestGeo(request) {
  return cleanGeo({
    country: request.headers.get("CF-IPCountry") || "unknown",
    city: request.cf?.city,
    region: request.cf?.region,
    timezone: request.cf?.timezone,
    asn: request.cf?.asn,
    isp: request.cf?.asOrganization,
    lat: request.cf?.latitude,
    lon: request.cf?.longitude,
  });
}

function mergeUser(previousValue, user, visit, fingerprint, deviceKeys, uaParsed, geo, now) {
  const uid = String(user.id);
  const previous = previousValue ? cleanRecord(previousValue, uid) : null;
  const ips = previous ? [...previous.ips] : [];
  const currentIp = ips.find((item) => item.ip === visit.ip);
  if (currentIp) {
    currentIp.last_seen = now;
    currentIp.visits += 1;
    currentIp.country = geo.country || currentIp.country;
    currentIp.city = geo.city || currentIp.city;
    currentIp.region = geo.region || currentIp.region;
    currentIp.isp = geo.isp || currentIp.isp;
  } else {
    ips.unshift(cleanIp({ ...geo, ip: visit.ip, first_seen: now, last_seen: now, visits: 1 }));
  }

  return {
    id: Number(user.id),
    first_name: cleanText(user.first_name, 70) || previous?.first_name || "",
    last_name: cleanText(user.last_name, 70) || previous?.last_name || "",
    username: cleanText(user.username, 40).replace(/^@/, "") || previous?.username || "",
    language_code: cleanText(user.language_code, 20) || previous?.language_code || "",
    is_premium: user.is_premium === true || previous?.is_premium === true,
    source: "webapp",
    registered: previous?.registered || now,
    last_seen: now,
    visit_count: (previous?.visit_count || 0) + 1,
    ips: ips.slice(0, MAX_IPS),
    visits: [visit, ...(previous?.visits || [])].slice(0, MAX_VISITS),
    fingerprint: buildFingerprint(previous?.fingerprint || {}, fingerprint, uaParsed, now),
    device_keys: [...new Set([...(deviceKeys || []), ...(previous?.device_keys || [])])].slice(0, MAX_DEVICE_KEYS),
    geo: cleanGeo({ ...(previous?.geo || {}), ...Object.fromEntries(Object.entries(geo).filter(([, value]) => value != null)) }),
  };
}

function githubHeaders(env, extra = {}) {
  return {
    Authorization: `Bearer ${env.GITHUB_TOKEN}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "Paradise-WebApp-Users/2.0",
    "X-GitHub-Api-Version": "2022-11-28",
    ...extra,
  };
}

async function githubError(response, action) {
  let detail = "";
  try {
    detail = cleanText((await response.json())?.message, 180);
  } catch {
    // The status remains enough when GitHub returns a non-JSON error.
  }
  return `${action} (${response.status})${detail ? `: ${detail}` : ""}`;
}

async function readUsers(env, attempt) {
  const url = new URL(GITHUB_API);
  url.searchParams.set("ref", BRANCH);
  url.searchParams.set("t", `${Date.now()}-${attempt}-${crypto.randomUUID()}`);
  const response = await fetch(url, { headers: githubHeaders(env), cache: "no-store" });
  if (response.status === 404) return { data: {}, sha: "", exists: false };
  if (!response.ok) throw new Error(await githubError(response, "GitHub read failed"));

  const metadata = await response.json();
  if (!metadata?.sha) throw new Error("GitHub read returned no SHA");
  let text = "";
  if (metadata.encoding === "base64" && metadata.content) {
    text = base64ToText(metadata.content);
  } else if (metadata.git_url) {
    const blobResponse = await fetch(metadata.git_url, { headers: githubHeaders(env), cache: "no-store" });
    if (!blobResponse.ok) throw new Error(`GitHub blob read failed (${blobResponse.status})`);
    const blob = await blobResponse.json();
    if (blob.encoding !== "base64" || !blob.content) throw new Error("GitHub blob returned no content");
    text = base64ToText(blob.content);
  } else if (metadata.download_url) {
    const rawUrl = new URL(metadata.download_url);
    rawUrl.searchParams.set("t", `${Date.now()}-${attempt}`);
    const rawResponse = await fetch(rawUrl, { cache: "no-store" });
    if (!rawResponse.ok) throw new Error(`GitHub raw read failed (${rawResponse.status})`);
    text = await rawResponse.text();
  } else {
    throw new Error("GitHub did not return file content");
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("GitHub user database contains invalid JSON");
  }
  return { data: cleanDatabase(parsed), sha: metadata.sha, exists: true };
}

async function upsertUser(env, user, visit, fingerprint, deviceKeys, uaParsed, geo, now) {
  const uid = String(user.id);
  let hadConflict = false;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt += 1) {
    const current = await readUsers(env, attempt);
    const currentCount = Object.keys(current.data).length;
    const isNew = !current.data[uid];
    const data = { ...current.data, [uid]: mergeUser(current.data[uid], user, visit, fingerprint, deviceKeys, uaParsed, geo, now) };
    if (Object.keys(data).length < currentCount) throw new Error("Safety check blocked a shrinking user database");

    const body = {
      message: `webapp: ${isNew ? "new user" : "visit"} ${uid}`,
      content: textToBase64(`${JSON.stringify(data, null, 2)}\n`),
      branch: BRANCH,
      ...(current.sha ? { sha: current.sha } : {}),
    };
    const response = await fetch(GITHUB_API, {
      method: "PUT",
      headers: githubHeaders(env, { "Content-Type": "application/json" }),
      body: JSON.stringify(body),
    });
    if (response.ok) return { isNew, count: Object.keys(data).length, attempts: attempt + 1, hadConflict };
    if (response.status !== 409 && response.status !== 422) {
      throw new Error(await githubError(response, "GitHub write failed"));
    }
    hadConflict = true;
    await new Promise((resolve) => setTimeout(resolve, 150 + Math.random() * 350));
  }
  throw new Error(`GitHub conflict was not resolved after ${MAX_RETRIES} attempts`);
}

function cleanHashList(value, limit = 100) {
  return cleanArray(value, limit, 64).map((item) => item.toLowerCase()).filter((item) => /^[a-f0-9]{64}$/.test(item));
}

function normaliseBlacklist(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const entries = (Array.isArray(source.entries) ? source.entries : []).slice(0, 500).map((item, position) => {
    const userIds = cleanArray(item?.user_ids, 200, 24).filter((id) => /^\d+$/.test(id));
    const rootUserId = cleanText(item?.root_user_id || userIds[0], 24);
    const id = cleanText(item?.id || `ban-${position + 1}`, 80).replace(/[^a-zA-Z0-9_-]/g, "-");
    return {
      id,
      root_user_id: /^\d+$/.test(rootUserId) ? rootUserId : "",
      user_ids: [...new Set(userIds)],
      ip_hashes: [...new Set(cleanHashList(item?.ip_hashes))],
      device_hashes: [...new Set(cleanHashList(item?.device_hashes))],
      reason: cleanText(item?.reason, 300),
      created_at: cleanIso(item?.created_at),
      created_by: cleanText(item?.created_by, 24),
      active: item?.active !== false,
    };
  }).filter((item) => item.id && item.root_user_id && item.user_ids.length);
  return {
    version: 1,
    updated_at: cleanIso(source.updated_at),
    entries,
  };
}

async function readBlacklistFile(env, force = false, attempt = 0) {
  if (!force && blacklistCache && Date.now() - blacklistCacheAt < BLACKLIST_CACHE_MS) return blacklistCache;
  const url = new URL(BLACKLIST_API);
  url.searchParams.set("ref", BRANCH);
  url.searchParams.set("t", `${Date.now()}-${attempt}-${crypto.randomUUID()}`);
  try {
    const response = await fetch(url, { headers: githubHeaders(env), cache: "no-store" });
    if (response.status === 404) {
      const missing = { data: normaliseBlacklist({}), sha: "" };
      blacklistCache = missing;
      blacklistCacheAt = Date.now();
      return missing;
    }
    if (!response.ok) throw new Error(await githubError(response, "Blacklist read failed"));
    const metadata = await response.json();
    if (!metadata?.sha) throw new Error("Blacklist read returned no SHA");
    let text = "";
    if (metadata.encoding === "base64" && metadata.content) {
      text = base64ToText(metadata.content);
    } else if (metadata.git_url) {
      const blobResponse = await fetch(metadata.git_url, { headers: githubHeaders(env), cache: "no-store" });
      if (!blobResponse.ok) throw new Error(`Blacklist blob read failed (${blobResponse.status})`);
      const blob = await blobResponse.json();
      if (blob.encoding !== "base64" || !blob.content) throw new Error("Blacklist blob returned no content");
      text = base64ToText(blob.content);
    } else if (metadata.download_url) {
      const rawUrl = new URL(metadata.download_url);
      rawUrl.searchParams.set("t", `${Date.now()}-${attempt}`);
      const rawResponse = await fetch(rawUrl, { cache: "no-store" });
      if (!rawResponse.ok) throw new Error(`Blacklist raw read failed (${rawResponse.status})`);
      text = await rawResponse.text();
    } else {
      throw new Error("GitHub did not return blacklist content");
    }
    const result = { data: normaliseBlacklist(JSON.parse(text)), sha: metadata.sha };
    blacklistCache = result;
    blacklistCacheAt = Date.now();
    return result;
  } catch (error) {
    if (!force && blacklistCache) return blacklistCache;
    throw error;
  }
}

function findBlacklistMatch(blacklist, userId, ipHash, deviceKeys) {
  const uid = String(userId);
  const deviceSet = new Set(deviceKeys || []);
  for (const entry of blacklist.entries || []) {
    if (!entry.active) continue;
    if (entry.user_ids.includes(uid)) return { entry, matched_by: "account" };
    if (ipHash && entry.ip_hashes.includes(ipHash)) return { entry, matched_by: "network" };
    if (entry.device_hashes.some((key) => deviceSet.has(key))) return { entry, matched_by: "device" };
  }
  return null;
}

async function recordBlockedUser(env, entryId, userId) {
  const uid = String(userId);
  if (!/^\d+$/.test(uid)) return;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const current = await readBlacklistFile(env, true, attempt);
    const entryIndex = current.data.entries.findIndex((entry) => entry.id === entryId && entry.active);
    if (entryIndex < 0) return;
    if (current.data.entries[entryIndex].user_ids.includes(uid)) return;
    const data = normaliseBlacklist(current.data);
    data.entries[entryIndex].user_ids = [...data.entries[entryIndex].user_ids, uid].slice(0, 200);
    data.updated_at = new Date().toISOString();
    const response = await fetch(BLACKLIST_API, {
      method: "PUT",
      headers: githubHeaders(env, { "Content-Type": "application/json" }),
      body: JSON.stringify({
        message: "security: record blocked account",
        content: textToBase64(`${JSON.stringify(data, null, 2)}\n`),
        branch: BRANCH,
        ...(current.sha ? { sha: current.sha } : {}),
      }),
    });
    if (response.ok) {
      blacklistCache = { data, sha: (await response.json())?.content?.sha || "" };
      blacklistCacheAt = Date.now();
      return;
    }
    if (response.status !== 409 && response.status !== 422) throw new Error(await githubError(response, "Blacklist update failed"));
  }
}

async function sendMessage(env, text) {
  if (!env.BOT_TOKEN) return;
  try {
    await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: ADMIN_ID, text: cleanText(text, 3500) }),
    });
  } catch {
    // Notifications must never roll back a successful GitHub write.
  }
}

export const __test = {
  base64ToText,
  textToBase64,
  cleanText,
  cleanDatabase,
  mergeUser,
  parseUA,
  hardwareSignature,
  deviceKeysForFingerprint,
  normaliseBlacklist,
  findBlacklistMatch,
  verifyTelegramInitData,
  telegramUserFromInitData,
};

export default {
  async fetch(request, env, ctx) {
    const cors = corsHeaders(request);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (request.method !== "POST") return json({ ok: true }, 200, cors);
    if (!env.GITHUB_TOKEN || !env.BAN_SECRET) {
      return json({ ok: false, error: "Worker secrets are not configured" }, 503, cors);
    }

    try {
      const contentType = request.headers.get("Content-Type") || "";
      if (!contentType.includes("application/json")) return json({ ok: false, error: "JSON body required" }, 415, cors);
      const body = await request.json();
      const user = telegramUserFromInitData(cleanText(body?.initData, 8192));
      if (!user) return json({ ok: false, error: "Telegram user ID is missing" }, 401, cors);

      const now = new Date().toISOString();
      const geo = requestGeo(request);
      const uaParsed = parseUA(request.headers.get("User-Agent") || "");
      const fingerprint = body?.fingerprint && typeof body.fingerprint === "object" ? body.fingerprint : {};
      const deviceKeys = await deviceKeysForFingerprint(env.BAN_SECRET, fingerprint, uaParsed);
      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      const ipHash = clientIp === "unknown" ? "" : await identifierHash(env.BAN_SECRET, "ip", clientIp);
      const blacklist = await readBlacklistFile(env);
      const blocked = findBlacklistMatch(blacklist.data, user.id, ipHash, deviceKeys);
      if (blocked) {
        if (ctx?.waitUntil) ctx.waitUntil(recordBlockedUser(env, blocked.entry.id, user.id).catch(() => {}));
        return json({ ok: false, blocked: true, error: "Access denied" }, 403, cors);
      }
      const visit = createVisit(request, fingerprint, uaParsed, geo, now);
      const trackingTask = (async () => {
        const result = await upsertUser(env, user, visit, fingerprint, deviceKeys, uaParsed, geo, now);
        if (result.hadConflict) {
          await sendMessage(env, `🔄 Конфликт записи пользователя ${user.id} разрешён за ${result.attempts} попытки. Всего webapp-пользователей: ${result.count}`);
        }
        if (result.isNew) {
          const location = [geo.city, geo.region, geo.country].filter(Boolean).join(", ");
          await sendMessage(
            env,
            `👤 #new_user\n${cleanText(user.first_name, 70) || "—"} (@${cleanText(user.username, 40) || "—"})\nID: ${user.id}\n🌍 ${location || "unknown"}\n📱 ${uaParsed.device} · ${uaParsed.os} · ${uaParsed.browser}\n🕐 ${now.slice(0, 16).replace("T", " ")}`,
          );
        }
      })();
      const reportTrackingFailure = async (error) => {
        const message = cleanText(error instanceof Error ? error.message : "Unknown tracking error", 500);
        await sendMessage(env, `User tracking failed for ${user.id}: ${message}`);
      };
      if (ctx?.waitUntil) ctx.waitUntil(trackingTask.catch(reportTrackingFailure));
      else trackingTask.catch(reportTrackingFailure);
      return json({ ok: true, access: true }, 200, cors);
    } catch (error) {
      const message = cleanText(error instanceof Error ? error.message : "Unknown error", 500);
      await sendMessage(env, `🐛 ❌ Ошибка paradise-users: ${message}`);
      return json({ ok: false, error: message }, 500, cors);
    }
  },
};
