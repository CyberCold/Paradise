const SESSION_COOKIE = "__Host-paradise_session";
const SESSION_TTL_SECONDS = 300;

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function textToBase64Url(value) {
  return bytesToBase64Url(new TextEncoder().encode(value));
}

function base64UrlToText(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  return new TextDecoder().decode(Uint8Array.from(binary, character => character.charCodeAt(0)));
}

async function signature(secret, payload) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload))));
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function cookieValue(header, name) {
  for (const pair of String(header || "").split(";")) {
    const separator = pair.indexOf("=");
    if (separator < 0) continue;
    if (pair.slice(0, separator).trim() === name) return pair.slice(separator + 1).trim();
  }
  return "";
}

export function telegramUserId(initData) {
  try {
    const user = JSON.parse(new URLSearchParams(String(initData || "")).get("user") || "null");
    const id = String(user?.id || "");
    return /^\d{5,20}$/.test(id) ? id : "";
  } catch {
    return "";
  }
}

export async function createSessionCookie(secret, userId, now = Date.now()) {
  if (!secret || !/^\d{5,20}$/.test(String(userId || ""))) throw new Error("Session configuration is invalid");
  const payload = textToBase64Url(JSON.stringify({ uid: String(userId), exp: Math.floor(now / 1000) + SESSION_TTL_SECONDS }));
  const token = `${payload}.${await signature(secret, payload)}`;
  return `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${SESSION_TTL_SECONDS}; HttpOnly; Secure; SameSite=Strict`;
}

export async function verifySessionCookie(secret, cookieHeader, now = Date.now()) {
  if (!secret) return null;
  const token = cookieValue(cookieHeader, SESSION_COOKIE);
  const separator = token.lastIndexOf(".");
  if (separator <= 0) return null;
  const payload = token.slice(0, separator);
  const provided = token.slice(separator + 1);
  const expected = await signature(secret, payload);
  if (!constantTimeEqual(provided, expected)) return null;
  try {
    const value = JSON.parse(base64UrlToText(payload));
    if (!/^\d{5,20}$/.test(String(value?.uid || ""))) return null;
    if (!Number.isFinite(value?.exp) || value.exp < Math.floor(now / 1000)) return null;
    return { userId: String(value.uid), expiresAt: value.exp };
  } catch {
    return null;
  }
}
