const REPO = "CyberCold/Paradise";
const BRANCH = "main";
const FILES = {
  banners: { path: "banners.json", fallback: [] },
  users: { path: "users.json", fallback: {} },
  blacklist: { path: "blacklist.json", fallback: { version: 1, updated_at: "", entries: [] } },
  catalog: {
    path: "catalog_overrides.json",
    fallback: { version: 1, products: {}, customProducts: [] },
  },
};
const ALLOWED_ORIGINS = new Set([
  "https://paradiseminiapp.pages.dev",
  "https://testikusik.vercel.app",
]);
const TELEGRAM_INIT_DATA_MAX_AGE_SECONDS = 7 * 24 * 60 * 60;
const TELEGRAM_INIT_DATA_CLOCK_SKEW_SECONDS = 5 * 60;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });
}

function originHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  if (!ALLOWED_ORIGINS.has(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Vary": "Origin",
  };
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function textToBase64(value) {
  let binary = "";
  for (const byte of encoder.encode(value)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToText(value) {
  const binary = atob(value.replace(/\n/g, ""));
  return decoder.decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
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
  const cleanValue = trimText(value, 1200);
  if (!secret || !cleanValue) return "";
  return bytesToHex(await hmac(encoder.encode(secret), encoder.encode(`paradise-ban:${kind}:${cleanValue}`)));
}

function constantTimeEqual(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function trimText(value, maxLength = 160) {
  return String(value ?? "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, maxLength);
}

function validHttpUrl(value) {
  try {
    const url = new URL(String(value || ""));
    return /^https?:$/.test(url.protocol) ? url.href : "";
  } catch {
    return "";
  }
}

async function parseJson(request) {
  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.includes("application/json")) throw new Error("JSON body required");
  return request.json();
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
    return user && Number.isSafeInteger(Number(user.id)) ? user : null;
  } catch {
    return null;
  }
}

async function createSession(userId, secret) {
  const payload = base64Url(encoder.encode(JSON.stringify({ id: String(userId), exp: Date.now() + 15 * 60 * 1000 })));
  const signature = base64Url(await hmac(encoder.encode(`admin-session:${secret}`), encoder.encode(payload)));
  return `${payload}.${signature}`;
}

async function verifySession(request, secret, adminIds) {
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const [payload, signature] = token.split(".");
  if (!payload || !signature) return null;
  const expected = base64Url(await hmac(encoder.encode(`admin-session:${secret}`), encoder.encode(payload)));
  if (!constantTimeEqual(encoder.encode(expected), encoder.encode(signature))) return null;

  try {
    const session = JSON.parse(decoder.decode(base64UrlToBytes(payload)));
    if (!session?.id || !session?.exp || Date.now() > session.exp || !adminIds.has(String(session.id))) return null;
    return session;
  } catch {
    return null;
  }
}

async function githubRequest(env, path, options = {}) {
  const response = await fetch(`https://api.github.com/repos/${REPO}/contents/${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${env.GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "Paradise-MiniApp-Admin/1.0",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.headers || {}),
    },
  });
  return response;
}

async function githubFailureMessage(response, action) {
  let detail = "";
  try {
    const payload = await response.json();
    detail = trimText(payload?.message, 180);
  } catch {
    // Keep the status-only fallback when GitHub does not return JSON.
  }
  return `${action} (${response.status})${detail ? `: ${detail}` : ""}`;
}

async function readDataFile(env, descriptor) {
  const response = await githubRequest(env, `${descriptor.path}?ref=${encodeURIComponent(BRANCH)}&t=${Date.now()}`);
  if (response.status === 404) return { data: descriptor.fallback, sha: "" };
  if (!response.ok) throw new Error(await githubFailureMessage(response, "GitHub read failed"));
  const payload = await response.json();
  if (!payload?.sha) throw new Error("GitHub read returned no SHA");
  let text = "";
  if (payload.encoding === "base64" && payload.content) {
    text = base64ToText(payload.content);
  } else if (payload.git_url) {
    const blobResponse = await fetch(payload.git_url, {
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "Paradise-MiniApp-Admin/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      cache: "no-store",
    });
    if (!blobResponse.ok) throw new Error(`GitHub blob read failed (${blobResponse.status})`);
    const blob = await blobResponse.json();
    if (blob.encoding !== "base64" || !blob.content) throw new Error("GitHub blob returned no content");
    text = base64ToText(blob.content);
  } else if (payload.download_url) {
    const rawUrl = new URL(payload.download_url);
    rawUrl.searchParams.set("t", String(Date.now()));
    const rawResponse = await fetch(rawUrl, { cache: "no-store" });
    if (!rawResponse.ok) throw new Error(`GitHub raw read failed (${rawResponse.status})`);
    text = await rawResponse.text();
  } else {
    throw new Error("GitHub did not return file content");
  }
  try {
    return { data: JSON.parse(text), sha: payload.sha };
  } catch {
    throw new Error(`${descriptor.path} contains invalid JSON`);
  }
}

async function writeDataFile(env, descriptor, data, message) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const current = await readDataFile(env, descriptor);
    const response = await githubRequest(env, descriptor.path, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message,
        content: textToBase64(`${JSON.stringify(data, null, 2)}\n`),
        branch: BRANCH,
        ...(current.sha ? { sha: current.sha } : {}),
      }),
    });
    if (response.ok) return;
    if (response.status !== 409 && response.status !== 422) {
      throw new Error(await githubFailureMessage(response, "GitHub write failed"));
    }
  }
  throw new Error("GitHub file changed while saving. Try again.");
}

function normaliseBanner(item, position) {
  const id = trimText(item?.id || `banner-${position + 1}`, 70).replace(/[^a-z0-9_-]/gi, "-").replace(/-+/g, "-");
  const image = validHttpUrl(item?.image);
  if (!id || !image) throw new Error("Each banner needs an ID and image URL");
  return {
    id,
    title: trimText(item?.title, 100),
    text: trimText(item?.text, 300),
    image,
    button: "",
    url: validHttpUrl(item?.url),
    active: item?.active !== false,
    created_at: trimText(item?.created_at, 40) || new Date().toISOString(),
  };
}

function normaliseBanners(value) {
  if (!Array.isArray(value) || value.length > 20) throw new Error("Invalid banner list");
  const ids = new Set();
  return value.map((item, index) => {
    const banner = normaliseBanner(item, index);
    if (ids.has(banner.id)) throw new Error("Banner IDs must be unique");
    ids.add(banner.id);
    return banner;
  });
}

function normaliseProduct(value, allowHidden = true) {
  const id = trimText(value?.id, 70).toLowerCase().replace(/[^a-z0-9_-]/g, "-").replace(/-+/g, "-");
  if (!id) throw new Error("Product ID is required");
  const stock = ["in", "order", "out"].includes(value?.stock) ? value.stock : "in";
  const badge = ["", "new", "hit"].includes(value?.badge) ? value.badge : "";
  const flavors = Array.isArray(value?.flavors)
    ? value.flavors.map((flavor) => trimText(flavor, 90)).filter(Boolean).slice(0, 60)
    : [];
  const image = value?.image ? validHttpUrl(value.image) : "";
  if (value?.image && !image) throw new Error("Invalid product image URL");
  return {
    id,
    name: trimText(value?.name, 120),
    tag: trimText(value?.tag, 100),
    subtitle: trimText(value?.subtitle, 180),
    price: trimText(value?.price, 240),
    image,
    flavors,
    stock,
    badge,
    ...(allowHidden ? { hidden: value?.hidden === true } : {}),
  };
}

function normaliseCatalog(value) {
  const products = {};
  const sourceProducts = value?.products && typeof value.products === "object" && !Array.isArray(value.products)
    ? value.products
    : {};
  const entries = Object.entries(sourceProducts);
  if (entries.length > 100) throw new Error("Too many product overrides");
  for (const [id, product] of entries) products[id] = normaliseProduct({ ...product, id });

  const sourceCustom = Array.isArray(value?.customProducts) ? value.customProducts : [];
  if (sourceCustom.length > 40) throw new Error("Too many custom products");
  const customProducts = sourceCustom.map((product) => normaliseProduct(product));
  const ids = new Set();
  for (const product of customProducts) {
    if (ids.has(product.id)) throw new Error("Custom product IDs must be unique");
    ids.add(product.id);
  }
  return { version: 1, products, customProducts };
}

function cleanStringArray(value, limit = 20, itemLength = 120) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, limit).map((item) => trimText(item, itemLength)).filter(Boolean);
}

function cleanHashList(value, limit = 200) {
  return cleanStringArray(value, limit, 64).map((item) => item.toLowerCase()).filter((item) => /^[a-f0-9]{64}$/.test(item));
}

function cleanUserVisit(value = {}) {
  return {
    timestamp: trimText(value.timestamp, 40),
    ip: trimText(value.ip, 64),
    country: trimText(value.country, 8),
    city: trimText(value.city, 100),
    region: trimText(value.region, 100),
    device: trimText(value.device, 40),
    browser: trimText(value.browser, 40),
    os: trimText(value.os, 40),
    user_agent: trimText(value.user_agent, 500),
    referrer: validHttpUrl(value.referrer || value.referer),
  };
}

function cleanUserIp(value = {}) {
  return {
    ip: trimText(value.ip, 64),
    country: trimText(value.country, 8),
    city: trimText(value.city, 100),
    region: trimText(value.region, 100),
    isp: trimText(value.isp, 160),
    asn: Number.isFinite(Number(value.asn)) ? Number(value.asn) : null,
    lat: Number.isFinite(Number(value.lat)) ? Number(value.lat) : null,
    lon: Number.isFinite(Number(value.lon)) ? Number(value.lon) : null,
    first_seen: trimText(value.first_seen, 40),
    last_seen: trimText(value.last_seen, 40),
    visits: Math.max(0, Math.floor(Number(value.visits) || 0)),
  };
}

function cleanUserFingerprint(value = {}) {
  return {
    screen: trimText(value.screen, 40) || null,
    timezone: trimText(value.timezone, 80) || null,
    color_depth: Number.isFinite(Number(value.color_depth ?? value.colorDepth)) ? Number(value.color_depth ?? value.colorDepth) : null,
    touch: Number.isFinite(Number(value.touch)) ? Number(value.touch) : null,
    platform: trimText(value.platform, 80) || null,
    memory: Number.isFinite(Number(value.memory)) ? Number(value.memory) : null,
    cores: Number.isFinite(Number(value.cores)) ? Number(value.cores) : null,
    webgl_vendor: trimText(value.webgl_vendor ?? value.webglVendor, 120) || null,
    webgl_renderer: trimText(value.webgl_renderer ?? value.webglRenderer, 180) || null,
    languages: cleanStringArray(value.languages, 12, 30),
    ua_platform: trimText(value.ua_platform ?? value.uaPlatform, 80) || null,
    ua_platform_version: trimText(value.ua_platform_version ?? value.uaPlatformVersion, 80) || null,
    ua_architecture: trimText(value.ua_architecture ?? value.uaArchitecture, 40) || null,
    ua_bitness: trimText(value.ua_bitness ?? value.uaBitness, 20) || null,
    ua_model: trimText(value.ua_model ?? value.uaModel, 120) || null,
    ua_mobile: value.ua_mobile === true || value.uaMobile === true,
    device: trimText(value.device, 40) || null,
    browser: trimText(value.browser, 40) || null,
    os: trimText(value.os, 40) || null,
    updated_at: trimText(value.updated_at, 40),
  };
}

function normaliseUsers(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("users.json must contain an object");
  const entries = Object.entries(value);
  if (entries.length > 20_000) throw new Error("Too many users");
  const users = {};
  for (const [rawId, rawUser] of entries) {
    const id = trimText(rawId, 24);
    if (!/^\d+$/.test(id) || !rawUser || typeof rawUser !== "object" || Array.isArray(rawUser)) continue;
    users[id] = {
      id: Number.isSafeInteger(Number(rawUser.id)) ? Number(rawUser.id) : Number(id),
      first_name: trimText(rawUser.first_name, 70),
      last_name: trimText(rawUser.last_name, 70),
      username: trimText(rawUser.username, 40).replace(/^@/, ""),
      source: trimText(rawUser.source, 40),
      sources: cleanStringArray(rawUser.sources, 10, 40),
      registered: trimText(rawUser.registered, 40),
      last_seen: trimText(rawUser.last_seen, 40),
      visit_count: Math.max(0, Math.floor(Number(rawUser.visit_count) || 0)),
      ips: (Array.isArray(rawUser.ips) ? rawUser.ips : []).slice(0, 50).map(cleanUserIp).filter((item) => item.ip),
      visits: (Array.isArray(rawUser.visits) ? rawUser.visits : []).slice(0, 50).map(cleanUserVisit),
      request_history: (Array.isArray(rawUser.request_history) ? rawUser.request_history : []).slice(0, 50).map(cleanUserVisit),
      fingerprint: cleanUserFingerprint(rawUser.fingerprint),
      device_keys: [...new Set(cleanHashList(rawUser.device_keys, 8))],
    };
  }
  return users;
}

function normaliseBlacklist(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const entries = (Array.isArray(source.entries) ? source.entries : []).slice(0, 500).map((item, position) => {
    const userIds = cleanStringArray(item?.user_ids, 200, 24).filter((id) => /^\d+$/.test(id));
    const rootUserId = trimText(item?.root_user_id || userIds[0], 24);
    return {
      id: trimText(item?.id || `ban-${position + 1}`, 80).replace(/[^a-zA-Z0-9_-]/g, "-"),
      root_user_id: /^\d+$/.test(rootUserId) ? rootUserId : "",
      user_ids: [...new Set(userIds)],
      ip_hashes: [...new Set(cleanHashList(item?.ip_hashes))],
      device_hashes: [...new Set(cleanHashList(item?.device_hashes))],
      reason: trimText(item?.reason, 300),
      created_at: trimText(item?.created_at, 40),
      created_by: trimText(item?.created_by, 24),
      active: item?.active !== false,
    };
  }).filter((item) => item.id && item.root_user_id && item.user_ids.length);
  return { version: 1, updated_at: trimText(source.updated_at, 40), entries };
}

function hardwareSignatureFromRecord(record) {
  const fingerprint = cleanUserFingerprint(record?.fingerprint || {});
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
    device: fingerprint.device,
    os: fingerprint.os,
  };
  const present = Object.entries(parts).filter(([, item]) => item !== null && item !== "" && item !== false);
  const hasAnchor = [parts.screen, parts.webgl_renderer, parts.cores, parts.memory, parts.ua_model].some(
    (item) => item !== null && item !== "",
  );
  if (present.length < 5 || !hasAnchor) return "";
  return JSON.stringify(Object.fromEntries(present));
}

function userIps(record) {
  return [...new Set([
    ...(record?.ips || []).map((item) => item?.ip),
    ...(record?.visits || []).map((item) => item?.ip),
    ...(record?.request_history || []).map((item) => item?.ip),
  ].map((item) => trimText(item, 64)).filter((item) => item && item !== "unknown"))];
}

async function userDeviceKeys(secret, record) {
  const keys = [...new Set(cleanHashList(record?.device_keys, 8))];
  const hardware = hardwareSignatureFromRecord(record);
  if (hardware) keys.push(await identifierHash(secret, "device-hardware", hardware));
  return [...new Set(keys.filter(Boolean))].slice(0, 8);
}

function cleanBanRequest(value = {}) {
  const targetId = trimText(value.target_id, 24);
  if (!/^\d+$/.test(targetId)) throw new Error("Invalid target user ID");
  return {
    targetId,
    extraIds: [...new Set(cleanStringArray(value.extra_ids, 20, 24).filter((id) => /^\d+$/.test(id) && id !== targetId))],
    scopes: { ip: value?.scopes?.ip !== false, device: value?.scopes?.device !== false },
    reason: trimText(value.reason, 300),
  };
}

async function buildBanPreview(secret, usersValue, requestValue) {
  const users = normaliseUsers(usersValue);
  const request = cleanBanRequest(requestValue);
  const seedIds = [...new Set([request.targetId, ...request.extraIds])];
  for (const id of seedIds) if (!users[id]) throw new Error(`User ${id} was not found`);

  const seedIps = new Set();
  const seedDeviceKeys = new Set();
  for (const id of seedIds) {
    if (request.scopes.ip) userIps(users[id]).forEach((ip) => seedIps.add(ip));
    if (request.scopes.device) (await userDeviceKeys(secret, users[id])).forEach((key) => seedDeviceKeys.add(key));
  }

  const matches = [];
  const ipUse = new Map();
  for (const [id, user] of Object.entries(users)) {
    const reasons = [];
    if (seedIds.includes(id)) reasons.push(id === request.targetId ? "account" : "manual");
    const ips = userIps(user);
    const matchingIps = request.scopes.ip ? ips.filter((ip) => seedIps.has(ip)) : [];
    if (matchingIps.length) {
      reasons.push("ip");
      matchingIps.forEach((ip) => ipUse.set(ip, (ipUse.get(ip) || 0) + 1));
    }
    const deviceKeys = request.scopes.device ? await userDeviceKeys(secret, user) : [];
    if (deviceKeys.some((key) => seedDeviceKeys.has(key))) reasons.push("device");
    if (reasons.length) {
      matches.push({
        id,
        first_name: user.first_name,
        username: user.username,
        matched_by: [...new Set(reasons)],
      });
    }
  }
  if (matches.length > 100) throw new Error("More than 100 accounts are linked. Narrow the ban scope.");

  const ipHashes = [];
  for (const ip of seedIps) ipHashes.push(await identifierHash(secret, "ip", ip));
  const warnings = [...ipUse.entries()]
    .filter(([, count]) => count > 5)
    .map(([, count]) => `Один общий IP связывает ${count} аккаунтов. Проверьте список перед баном.`);
  return {
    request,
    user_ids: matches.map((item) => item.id).sort(),
    ip_hashes: [...new Set(ipHashes.filter(Boolean))],
    device_hashes: [...seedDeviceKeys],
    matches,
    warnings,
  };
}

async function mutateDataFile(env, descriptor, message, mutator) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const current = await readDataFile(env, descriptor);
    const data = await mutator(current.data);
    const response = await githubRequest(env, descriptor.path, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message,
        content: textToBase64(`${JSON.stringify(data, null, 2)}\n`),
        branch: BRANCH,
        ...(current.sha ? { sha: current.sha } : {}),
      }),
    });
    if (response.ok) return data;
    if (response.status !== 409 && response.status !== 422) throw new Error(await githubFailureMessage(response, "GitHub write failed"));
  }
  throw new Error("GitHub file changed while saving. Try again.");
}

export const __test = {
  createSession,
  verifySession,
  normaliseUsers,
  normaliseBlacklist,
  hardwareSignatureFromRecord,
  userIps,
  buildBanPreview,
  verifyTelegramInitData,
};

export default {
  async fetch(request, env) {
    const cors = originHeaders(request);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (!env.BOT_TOKEN || !env.GITHUB_TOKEN || !env.ADMIN_IDS || !env.BAN_SECRET) {
      return json({ error: "Worker secrets are not configured" }, 503, cors);
    }

    try {
      const url = new URL(request.url);
      const adminIds = new Set(String(env.ADMIN_IDS).split(",").map((id) => id.trim()).filter(Boolean));

      if (url.pathname === "/session" && request.method === "POST") {
        const body = await parseJson(request);
        const user = await verifyTelegramInitData(String(body?.initData || ""), env.BOT_TOKEN);
        if (!user) return json({ error: "Telegram session is invalid" }, 401, cors);
        if (!adminIds.has(String(user.id))) return json({ error: `Not authorised (Telegram ID: ${user.id})` }, 403, cors);
        return json({ session: await createSession(user.id, env.BAN_SECRET), user: { id: user.id, first_name: trimText(user.first_name, 70) } }, 200, cors);
      }

      const session = await verifySession(request, env.BAN_SECRET, adminIds);
      if (!session) return json({ error: "Session expired" }, 401, cors);

      if (url.pathname === "/blacklist/preview" && request.method === "POST") {
        const body = await parseJson(request);
        const usersFile = await readDataFile(env, FILES.users);
        const preview = await buildBanPreview(env.BAN_SECRET, usersFile.data, body);
        return json({
          user_ids: preview.user_ids,
          matches: preview.matches,
          warnings: preview.warnings,
          identifier_counts: { ips: preview.ip_hashes.length, devices: preview.device_hashes.length },
        }, 200, cors);
      }

      if (url.pathname === "/blacklist/ban" && request.method === "POST") {
        const body = await parseJson(request);
        const usersFile = await readDataFile(env, FILES.users);
        const preview = await buildBanPreview(env.BAN_SECRET, usersFile.data, body);
        const expected = [...new Set(cleanStringArray(body?.expected_user_ids, 100, 24).filter((id) => /^\d+$/.test(id)))].sort();
        if (JSON.stringify(expected) !== JSON.stringify(preview.user_ids)) {
          return json({ error: "Linked accounts changed. Preview the ban again.", user_ids: preview.user_ids }, 409, cors);
        }
        const now = new Date().toISOString();
        const entry = {
          id: `ban-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`,
          root_user_id: preview.request.targetId,
          user_ids: preview.user_ids,
          ip_hashes: preview.ip_hashes,
          device_hashes: preview.device_hashes,
          reason: preview.request.reason,
          created_at: now,
          created_by: String(session.id),
          active: true,
        };
        const blacklist = await mutateDataFile(env, FILES.blacklist, "security: add blacklist entry", (currentValue) => {
          const current = normaliseBlacklist(currentValue);
          const linkedIds = new Set(entry.user_ids);
          const overlap = current.entries.find((item) => item.active && item.user_ids.some((id) => linkedIds.has(id)));
          if (overlap) throw new Error("One of these accounts is already blocked");
          current.entries.push(entry);
          current.updated_at = now;
          return normaliseBlacklist(current);
        });
        return json({ ok: true, entry, blacklist }, 200, cors);
      }

      const unbanMatch = url.pathname.match(/^\/blacklist\/([a-zA-Z0-9_-]{1,80})$/);
      if (unbanMatch && request.method === "DELETE") {
        const entryId = unbanMatch[1];
        let removed = false;
        const now = new Date().toISOString();
        const blacklist = await mutateDataFile(env, FILES.blacklist, "security: remove blacklist entry", (currentValue) => {
          const current = normaliseBlacklist(currentValue);
          const before = current.entries.length;
          current.entries = current.entries.filter((item) => item.id !== entryId);
          removed = current.entries.length !== before;
          current.updated_at = now;
          return current;
        });
        if (!removed) return json({ error: "Blacklist entry not found" }, 404, cors);
        return json({ ok: true, blacklist }, 200, cors);
      }

      const resource = url.pathname.match(/^\/data\/(banners|catalog|users|blacklist)$/)?.[1];
      if (!resource || !FILES[resource]) return json({ error: "Not found" }, 404, cors);

      if (request.method === "GET") {
        const file = await readDataFile(env, FILES[resource]);
        const data = resource === "banners"
          ? normaliseBanners(file.data)
          : resource === "catalog"
            ? normaliseCatalog(file.data)
            : resource === "users"
              ? normaliseUsers(file.data)
              : normaliseBlacklist(file.data);
        return json({ data }, 200, cors);
      }

      if (request.method === "PUT") {
        if (!new Set(["banners", "catalog"]).has(resource)) return json({ error: "Method not allowed" }, 405, cors);
        const body = await parseJson(request);
        const data = resource === "banners" ? normaliseBanners(body?.data) : normaliseCatalog(body?.data);
        await writeDataFile(env, FILES[resource], data, `admin: update ${resource}`);
        return json({ ok: true, data }, 200, cors);
      }

      return json({ error: "Method not allowed" }, 405, cors);
    } catch (error) {
      return json({ error: error instanceof Error ? error.message : "Unknown error" }, 400, cors);
    }
  },
};
