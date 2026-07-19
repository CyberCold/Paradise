# Paradise access regression map

## Data flow

```text
users.json + webapp_users.json
          |
          | dashboard preview: linked accounts, exact IPs, device keys
          v
blacklist.json
  - user_ids
  - HMAC ip_hashes
  - HMAC device_hashes
          |
          v
Mini App -> POST /app -> paradise-users
                         | hash current IP/device
                         | compare with active blacklist entries
                         +-- match -> 403, catalogue stays protected
                         +-- no match -> 200, signed /catalog URL
                                           |
                                           v
                              GET form navigation -> catalogue

Tracking -> webapp_users.json runs in waitUntil and never gates access.
```

The large user databases are used to build the compact blacklist in the dashboard. The access path reads only the compact blacklist, so tracking or a large user export cannot delay a decision.

## Required regression cases

| Case | Expected result |
|---|---|
| Telegram ID is in an active entry | `403`, no catalogue token |
| Current IP hash is in an active entry | `403`, account is attached to the entry in background |
| Current device hash is in an active entry | `403`, account is attached to the entry in background |
| Entry is inactive | `200`, signed catalogue URL |
| Empty blacklist | `200`, signed catalogue URL |
| No ID/IP/device match | `200`, signed catalogue URL |
| Tracking write fails after access decision | Access remains `200`; error is reported separately |
| Optional browser entropy hangs | `/app` starts within 1.2 seconds |
| Access request hangs | Visible service error after 15 seconds |
| Access returns `200` on iOS WebView | GET form opens `/catalog`; `location.href` is fallback |
| Protected catalogue receives the server grant marker | Internal `#accessGate` is removed and cannot cover the catalogue |
| Access returns `403` | Loading screen becomes access denied; no navigation |
| `/catalog` token is absent, invalid, or expired | `404`; protected HTML is not served |
| `/catalog` token is valid | Protected HTML is served with session markers |
| Direct request for protected JSON/source | `404` without a valid token |
