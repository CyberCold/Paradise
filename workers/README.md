# Paradise admin Worker

Deploy `paradise-admin.js` as the Cloudflare Worker named `paradise-admin`.

Add these **Secrets** in Cloudflare Worker Settings:

- `BOT_TOKEN` — token of the Paradise Telegram bot;
- `GITHUB_TOKEN` — GitHub fine-grained token with Contents read/write access to `CyberCold/Paradise`;
- `ADMIN_IDS` — comma-separated Telegram user IDs allowed to use the web admin panel.

The worker verifies Telegram Web App `initData` before it issues a 15-minute admin session. It never exposes these values to the Mini App.
