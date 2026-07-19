import { createAccessToken, telegramUserId } from "./_shared/session.js";

const MAX_REQUEST_BYTES = 64 * 1024;

function json(body, status, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, private",
      "X-Content-Type-Options": "nosniff",
      ...headers,
    },
  });
}

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method !== "POST") return json({ error: "Not found" }, 404);
  if (!env.PARADISE_USERS || !env.BAN_SECRET) return json({ error: "Access gateway is not configured" }, 503);
  if (!(request.headers.get("Content-Type") || "").includes("application/json")) {
    return json({ error: "JSON body required" }, 415);
  }
  const declaredLength = Number(request.headers.get("Content-Length") || 0);
  if (declaredLength > MAX_REQUEST_BYTES) return json({ error: "Request too large" }, 413);

  const accessRequest = request.clone();
  let body;
  try {
    body = await request.text();
  } catch {
    return json({ error: "Invalid request" }, 400);
  }
  if (!body || new TextEncoder().encode(body).byteLength > MAX_REQUEST_BYTES) {
    return json({ error: "Invalid request size" }, 413);
  }
  let requestData;
  try {
    requestData = JSON.parse(body);
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }
  const userId = telegramUserId(requestData?.initData);
  if (!userId) return json({ error: "Invalid Telegram initData" }, 401);

  let access;
  try {
    access = await env.PARADISE_USERS.fetch(accessRequest);
  } catch {
    return json({ error: "Access service unavailable" }, 503);
  }

  let accessPayload = {};
  try {
    accessPayload = await access.json();
  } catch {}
  if (!access.ok) {
    let payload = { error: access.status === 403 ? "Access denied" : "Access check failed" };
    if (accessPayload?.blocked === true) payload.blocked = true;
    return json(payload, access.status >= 400 && access.status < 600 ? access.status : 502);
  }
  if (accessPayload?.access !== true) return json({ error: "Access was not granted" }, 502);

  const accessToken = await createAccessToken(env.BAN_SECRET, userId);
  return json({
    ok: true,
    access: true,
    location: `/catalog?access=${encodeURIComponent(accessToken)}`,
  }, 200);
}
