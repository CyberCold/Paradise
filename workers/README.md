# Paradise admin Worker

Deploy `paradise-admin.js` as the Cloudflare Worker named `paradise-admin`.

Add these **Secrets** in Cloudflare Worker Settings:

- `BOT_TOKEN` — token of the Paradise Telegram bot;
- `GITHUB_TOKEN` — GitHub fine-grained token with Contents read/write access to `CyberCold/Paradise`;
- `ADMIN_IDS` — comma-separated Telegram user IDs allowed to use the web admin panel.

The worker verifies Telegram Web App `initData` before it issues a 15-minute admin session. It never exposes these values to the Mini App.

# Paradise users Worker

Deploy `paradise-users.js` as the Cloudflare Worker named `paradise-users`.

Add these **Secrets** in Cloudflare Worker Settings:

- `BOT_TOKEN` — token of the Paradise Telegram bot;
- `GITHUB_TOKEN` — GitHub fine-grained token with Contents read/write access to `CyberCold/Paradise`.

The worker verifies signed Telegram Web App `initData`, stores a bounded visit history, and updates `webapp_users.json` with SHA-based conflict retries. Existing GitHub data is never replaced when a read or JSON parse fails.
