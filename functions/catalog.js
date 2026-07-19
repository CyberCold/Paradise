import { verifySessionCookie } from "./_shared/session.js";

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

function unavailable() {
  return new Response("Application unavailable", {
    status: 503,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store, private",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

export async function onRequest(context) {
  const { request, env } = context;
  if (!new Set(["GET", "HEAD"]).has(request.method)) return notFound();
  if (!env.BAN_SECRET || !env.ASSETS) return unavailable();

  const session = await verifySessionCookie(env.BAN_SECRET, request.headers.get("Cookie"));
  if (!session) return notFound();

  const assetUrl = new URL("/protected/index.html", request.url);
  const asset = await env.ASSETS.fetch(assetUrl);
  if (!asset.ok) return unavailable();

  let html;
  try {
    html = await asset.text();
  } catch {
    return unavailable();
  }
  if (!/<html[\s>]/i.test(html)) return unavailable();

  const securedHtml = html.replace(
    /<head(\s[^>]*)?>/i,
    match => `${match}<script>window.__PARADISE_GATE_GRANTED__=true;<\/script>`,
  );
  const headers = new Headers(asset.headers);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "no-store, private, max-age=0");
  headers.set("Pragma", "no-cache");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
  headers.delete("Content-Length");
  headers.delete("Content-Encoding");
  headers.delete("ETag");
  return new Response(request.method === "HEAD" ? null : securedHtml, { status: 200, headers });
}
