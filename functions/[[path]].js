import { verifyAccessToken } from "./_shared/session.js";

const PUBLIC_PATHS = new Set(["/", "/index.html"]);
const SESSION_ASSETS = new Set(["/banners.json", "/catalog_overrides.json"]);

function notFound() {
  return new Response("Not found", {
    status: 404,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store, private",
      "X-Content-Type-Options": "nosniff",
      "X-Robots-Tag": "noindex, nofollow, noarchive",
    },
  });
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  if (!new Set(["GET", "HEAD"]).has(request.method)) return notFound();

  if (PUBLIC_PATHS.has(url.pathname)) {
    const asset = await env.ASSETS.fetch(request);
    const headers = new Headers(asset.headers);
    headers.set("Cache-Control", "no-store, max-age=0");
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Referrer-Policy", "no-referrer");
    headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
    return new Response(asset.body, { status: asset.status, headers });
  }

  if (SESSION_ASSETS.has(url.pathname)) {
    const session = await verifyAccessToken(env.BAN_SECRET, url.searchParams.get("access") || "");
    if (!session) return notFound();
    const asset = await env.ASSETS.fetch(request);
    const headers = new Headers(asset.headers);
    headers.set("Cache-Control", "no-store, private, max-age=0");
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
    return new Response(asset.body, { status: asset.status, headers });
  }

  return notFound();
}
