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
                         | require Cloudflare country = LV
                         | reject known hosting/VPN network signals
                         | hash current IP/device
                         | compare with active blacklist entries
                         +-- geo/network/blacklist match -> 403, catalogue stays protected
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
| Cloudflare country is LV on a normal residential/mobile network | Continue to blacklist check |
| Cloudflare reports a neighbouring country, but the ASN/organisation is a known Latvian mobile carrier and the client timezone is Europe/Riga | Continue to blacklist check; log `latvian_mobile_geo_fallback` |
| Cloudflare country is not LV without the strict mobile-carrier fallback, is unknown, or is Tor (T1) | 403, no catalogue token |
| Latvian network organisation matches a hosting/VPN marker | 403, no catalogue token |
| Latvian ASN is present in VPN_DENY_ASNS | 403, no catalogue token |
| Telegram ID is in an active entry | 403, no catalogue token |
| Current IP hash is in an active entry on a fixed/residential network | `403`, account is attached to the entry in background |
| Only the current IP hash matches on Tele2 Latvia, Bite Latvija, or LMT mobile networks | `200`; CGNAT IPs are shared and cannot identify one subscriber |
| Telegram ID or device hash matches on a Latvian mobile network | `403`; the CGNAT exception never overrides strong identity matches |
| Current device hash is in an active entry | `403`, account is attached to the entry in background |
| Entry is inactive | `200`, signed catalogue URL |
| Empty blacklist | `200`, signed catalogue URL |
| No ID/IP/device match | `200`, signed catalogue URL |
| Tracking write fails after access decision | Access remains `200`; error is reported separately |
| Optional browser entropy hangs | `/app` starts within 1.2 seconds |
| Access request hangs | Visible service error after 15 seconds |
| Access returns `200` on iOS WebView | GET form opens `/catalog`; `location.href` is fallback |
| Protected catalogue receives the server grant marker | Internal `#accessGate` is removed and cannot cover the catalogue |
| First interaction is a touch, pointer press, or click | Background music starts after Web Audio is unlocked |
| Access returns `403` | Loading screen becomes access denied; no navigation |
| `/catalog` token is absent, invalid, or expired | `404`; protected HTML is not served |
| `/catalog` token is valid | Protected HTML is served with session markers |
| Direct request for protected JSON/source | `404` without a valid token |

## VPN detection boundary

Country blocking uses Cloudflare's request country and is deterministic. VPN detection on the current non-Enterprise setup is intentionally layered: known hosting/VPN organisation markers plus optional VPN_DENY_ASNS and VPN_ORG_DENYLIST Worker variables. This blocks common datacentre VPN exits, but a residential proxy can look identical to an ordinary Latvian household. Guaranteed classification requires Cloudflare Enterprise managed VPN/anonymizer lists or a maintained third-party IP intelligence source.
