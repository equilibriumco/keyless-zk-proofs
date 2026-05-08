# movement-keyless-pepper-service

HMAC-SHA256 derives a per-user "pepper" from `(sub, aud)` using an operator-held secret. Verifies the JWT's signature + issuer + expiry before deriving, so a forged JWT cannot drain a real user's pepper. Listens on `$PEPPER_ADDR` (default `0.0.0.0:3002`).

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `PEPPER_ADDR` | `0.0.0.0:3002` | Listen address. |
| `PEPPER_SECRET_FILE` | _(unset)_ | Path to raw-bytes secret file (tmpfs or k8s/Vault-mounted). Min 32 bytes. |
| `PEPPER_SECRET` | _(unset)_ | Hex-encoded secret. Dev only; prefer `PEPPER_SECRET_FILE` in production. |
| `PEPPER_ALLOWED_ISS` | `https://accounts.google.com` | Comma-separated OIDC issuers accepted. Empty = any issuer (dev-only). |
| `PEPPER_RL_IP_PER_MIN` | `30` | Per-IP rate limit. `0` disables. |
| `PEPPER_RL_IP_BURST` | `10` | Per-IP burst. |
| `PEPPER_RL_SUB_PER_MIN` | `10` | Per-`(iss, sub)` rate limit (enforced AFTER signature verification). `0` disables. |
| `PEPPER_RL_SUB_BURST` | `5` | Per-`(iss, sub)` burst. |
| `PEPPER_BODY_LIMIT_BYTES` | `8192` | Max request body size; larger bodies get 413. |
| `PEPPER_TRUSTED_PROXY_CIDRS` | _(empty)_ | Comma-separated CIDRs whose `X-Forwarded-For` is trusted. |

## HTTP response codes

Handler-emitted (response body is `{"error": "<message>"}`):

- `200` — pepper returned.
- `400` — JWT parse / signature / issuer / exp failure.
- `429` — rate limit exceeded (includes `Retry-After`).
- `500` — unexpected failure (HMAC error, server bug). Body is the constant string-in-JSON `"internal error"`; the full chain is logged server-side at `error!`.
- `503` — upstream JWKS unreachable (e.g. Google `5xx` or connection refused). Includes `Retry-After` when the upstream provided one.

Extractor / router-emitted (axum default plaintext bodies, _not_ `{"error":...}` — clients should distinguish by status code):

- `400` — malformed JSON body.
- `404` — unknown path.
- `405` — wrong HTTP method on a known path.
- `413` — request body larger than `PEPPER_BODY_LIMIT_BYTES`.
- `415` — missing or non-`application/json` content-type.
- `422` — valid JSON but missing required field (e.g. `jwt`).

## Deployment topology

- **Direct-TCP** (local/dev, or cloud with a TCP LB): leave `PEPPER_TRUSTED_PROXY_CIDRS` empty. The per-IP rate limiter keys on the peer address.
- **Behind an L7 reverse proxy / CDN**: set `PEPPER_TRUSTED_PROXY_CIDRS` to the CIDR ranges of your proxies so the limiter can read `X-Forwarded-For` without trusting forged headers. Without this, every request appears to come from the proxy and the per-IP limiter becomes a global cap.
