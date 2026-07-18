const REPO = "CyberCold/Paradise";
const BRANCH = "main";
const FILES = {
  banners: { path: "banners.json", fallback: [] },
  catalog: {
    path: "catalog_overrides.json",
    fallback: { version: 1, products: {}, customProducts: [] },
  },
};

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
  if (origin !== "https://paradiseminiapp.pages.dev") return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
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

async function verifyTelegramInitData(initData, botToken) {
  if (!initData || initData.length > 8192) return null;

  const values = new URLSearchParams(initData);
  const givenHash = values.get("hash");
  const authDate = Number(values.get("auth_date"));
  const userText = values.get("user");
  values.delete("hash");
  if (!givenHash || !authDate || !userText) return null;
  if (Math.abs(Math.floor(Date.now() / 1000) - authDate) > 24 * 60 * 60) return null;

  const dataCheckString = [...values.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");
  const webAppKey = await hmac(encoder.encode("WebAppData"), encoder.encode(botToken));
  const expected = await hmac(webAppKey, encoder.encode(dataCheckString));
  const supplied = Uint8Array.from(givenHash.match(/.{1,2}/g) || [], (pair) => Number.parseInt(pair, 16));
  if (!constantTimeEqual(expected, supplied)) return null;

  try {
    const user = JSON.parse(userText);
    return user && Number.isSafeInteger(Number(user.id)) ? user : null;
  } catch {
    return null;
  }
}

async function createSession(userId, botToken) {
  const payload = base64Url(encoder.encode(JSON.stringify({ id: String(userId), exp: Date.now() + 15 * 60 * 1000 })));
  const signature = base64Url(await hmac(encoder.encode(`admin-session:${botToken}`), encoder.encode(payload)));
  return `${payload}.${signature}`;
}

async function verifySession(request, botToken, adminIds) {
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const [payload, signature] = token.split(".");
  if (!payload || !signature) return null;
  const expected = base64Url(await hmac(encoder.encode(`admin-session:${botToken}`), encoder.encode(payload)));
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
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.headers || {}),
    },
  });
  return response;
}

async function readDataFile(env, descriptor) {
  const response = await githubRequest(env, descriptor.path);
  if (response.status === 404) return { data: descriptor.fallback, sha: "" };
  if (!response.ok) throw new Error(`GitHub read failed (${response.status})`);
  const payload = await response.json();
  return { data: JSON.parse(base64ToText(payload.content)), sha: payload.sha };
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
    if (response.status !== 409 && response.status !== 422) throw new Error(`GitHub write failed (${response.status})`);
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

export default {
  async fetch(request, env) {
    const cors = originHeaders(request);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (!env.BOT_TOKEN || !env.GITHUB_TOKEN || !env.ADMIN_IDS) {
      return json({ error: "Worker secrets are not configured" }, 503, cors);
    }

    try {
      const url = new URL(request.url);
      const adminIds = new Set(String(env.ADMIN_IDS).split(",").map((id) => id.trim()).filter(Boolean));

      if (url.pathname === "/session" && request.method === "POST") {
        const body = await parseJson(request);
        const user = await verifyTelegramInitData(String(body?.initData || ""), env.BOT_TOKEN);
        if (!user || !adminIds.has(String(user.id))) return json({ error: "Not authorised" }, 403, cors);
        return json({ session: await createSession(user.id, env.BOT_TOKEN), user: { id: user.id, first_name: trimText(user.first_name, 70) } }, 200, cors);
      }

      const session = await verifySession(request, env.BOT_TOKEN, adminIds);
      if (!session) return json({ error: "Session expired" }, 401, cors);
      const resource = url.pathname.match(/^\/data\/(banners|catalog)$/)?.[1];
      if (!resource || !FILES[resource]) return json({ error: "Not found" }, 404, cors);

      if (request.method === "GET") {
        const file = await readDataFile(env, FILES[resource]);
        return json({ data: resource === "banners" ? normaliseBanners(file.data) : normaliseCatalog(file.data) }, 200, cors);
      }

      if (request.method === "PUT") {
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
