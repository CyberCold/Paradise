# Paradise admin Worker

Deploy `paradise-admin.js` as the Cloudflare Worker named `paradise-admin`.

Add these **Secrets** in Cloudflare Worker Settings:

- `BOT_TOKEN` — token of the Paradise Telegram bot;
- `GITHUB_TOKEN` — GitHub fine-grained token with Contents read/write access to `CyberCold/Paradise`;
- `ADMIN_IDS` — comma-separated Telegram user IDs allowed to use the web admin panel;
- `BAN_SECRET` — a long random secret shared with `paradise-users` and used only for HMAC hashing of IP/device identifiers.

The worker verifies Telegram Web App `initData` before it issues a 15-minute admin session. It serves user data only to that session, previews linked accounts, and writes hashed blacklist entries without exposing raw IP/device identifiers in `blacklist.json`.

# Paradise users Worker

Deploy `paradise-users.js` as the Cloudflare Worker named `paradise-users`.

Add these **Secrets** in Cloudflare Worker Settings:

- `BOT_TOKEN` — token of the Paradise Telegram bot;
- `GITHUB_TOKEN` — GitHub fine-grained token with Contents read/write access to `CyberCold/Paradise`;
- `BAN_SECRET` — exactly the same secret as on `paradise-admin`.

The worker verifies signed Telegram Web App `initData`, checks Telegram ID, exact IP, and HMAC device keys before granting access, stores a bounded visit history, and updates `webapp_users.json` with SHA-based conflict retries. Existing GitHub data is never replaced when a read or JSON parse fails.

# Paradise Pages gateway

The `paradiseminiapp` Pages project must have:

- the same `BAN_SECRET` configured as an encrypted runtime secret;
- a Service binding named `PARADISE_USERS` targeting the `paradise-users` Worker.

The public `index.html` is only a Telegram access gateway. Pages Functions return the protected catalogue HTML only after the Worker validates Telegram `initData` and the blacklist. A five-minute signed, HttpOnly cookie permits access to `banners.json` and `catalog_overrides.json`; all other repository files and JSON routes return `404` through Pages.
