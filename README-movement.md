# Movement Keyless — fork notes

This is `movementlabsxyz/keyless-zk-proofs`'s `movement-main` branch — a
fork of [`aptos-labs/keyless-zk-proofs`](https://github.com/aptos-labs/keyless-zk-proofs)
that runs Aptos Keyless on the Movement network.

The fork keeps the upstream architecture: a `prover-service` that mints
Groth16 proofs from JWTs and a `pepper-service` that derives per-user
peppers via HMAC. All Movement-specific changes live on this branch as
named, additive commits — see `git log --oneline main..movement-main`.

Read the upstream [`README.md`](README.md) first for the protocol-level
explanation. This file documents only what's different on the Movement
fork.

## Quick start

Local dev with Docker:

```sh
# 1. Generate dev secrets (NEVER commit; secrets/ is gitignored).
mkdir -p secrets
openssl rand 32 > secrets/pepper
chmod 644 secrets/pepper
openssl rand -hex 32 > secrets/training_wheels
chmod 644 secrets/training_wheels

# 2. Bring everything up (the prover image downloads the trusted-setup
#    artifacts during the build; first build takes a while).
docker compose up --build
```

Once running:
- prover-service: `http://localhost:8080` (POST `/v0/prove`, GET `/healthcheck`, `/cached/jwk`, `/about`, `/config`)
- pepper-service: `http://localhost:3002` on the host (`POST /pepper`, `GET /health`); also reachable inside the compose network as `http://pepper-service:3002`.

To configure the prover for a specific Movement network, set the
`PROVER_*` env vars in `docker-compose.yml` (see the table below).

## Movement-specific env vars (prover-service)

All hardening knobs are read at startup and cannot be changed without
restart. Sensible defaults are baked in — override only when needed.

| Variable | Default | Effect |
|---|---|---|
| `PROVER_BODY_LIMIT_BYTES` | `65536` | Reject POSTs with body larger than this (returns 413). Real prove requests are well under 64 KiB. |
| `PROVER_ALLOWED_ORIGINS` | _(unset)_ | Comma-separated CORS allowlist (`https://wallet.example.com,https://...`). Empty / unset emits no CORS headers — cross-origin browser callers are blocked by same-origin policy. CORS does NOT defend against server-to-server callers. |
| `PROVER_ALLOWED_AUDS` | _(unset)_ | Comma-separated JWT `aud` allowlist. Empty / unset accepts any aud (testing). Disallowed auds are rejected with 403 BEFORE the JWK fetch — useful both as a security control and to prevent the prover from amplifying traffic to upstream JWKS endpoints. |
| `PROVER_MAX_CONCURRENCY` | `4` | Cap on simultaneous proof generations. Over-cap returns 503. Tune to the host's CPU/memory budget — proof generation is CPU-heavy (~10s per proof). |
| `PROVER_IP_RATE_PER_MIN` | `60` | Per-peer-IP rate limit on `/v0/prove`. `0` disables. |
| `PROVER_IP_RATE_BURST` | `10` | Burst capacity for the per-IP limit. Must be ≥ `ceil(per_min / 60)`. |
| `PROVER_SUB_RATE_PER_MIN` | `30` | Per-`(iss, sub)` rate limit, charged AFTER successful JWT signature verification. `0` disables. |
| `PROVER_SUB_RATE_BURST` | `5` | Burst capacity for the per-`(iss, sub)` limit. |
| `PROVER_TRUSTED_PROXY_CIDRS` | _(unset)_ | Comma-separated CIDRs whose `X-Forwarded-For` is trusted for resolving the real client IP. Set to your L7 proxy's CIDRs when running behind one; empty / unset uses the peer address. |

When any rate limit is exceeded, the response is `429 Too Many Requests`
with body `{"error":"rate limit exceeded"}` and a `retry-after` header
on the per-IP path. The body intentionally does not disclose the
bucketing dimension so an attacker cannot probe for sub-keys.

`pepper-service` reads an analogous set of `PEPPER_*` knobs — see the
comments in `docker-compose.yml` and `pepper-service/Dockerfile`.

## Trusted setup artifacts

The prover-service Docker build downloads the upstream `circuit-v4.0.0`
ceremony artifacts. Movement testnet's on-chain VK matches that
ceremony as of 2026-05-08, so v4.0.0 artifacts produce on-chain-
verifiable proofs. Do NOT swap in `circuit-v1.0.1` or `circuit-v1.2.0`
artifacts without first confirming the on-chain VK matches that
ceremony — proofs minted against a mismatched zkey verify locally but
are rejected by the chain. (Each Groth16 ceremony embeds its own
trusted-setup randomness; the curve points agree across ceremonies but
`delta_g2` and `gamma_abc_g1` do not.)

## Upstream sync

To pull updates from the upstream `aptos-labs/keyless-zk-proofs`:

```sh
git remote add upstream https://github.com/aptos-labs/keyless-zk-proofs.git  # once
git fetch upstream
# Cherry-pick or merge specific upstream commits onto movement-main.
# Avoid `git merge upstream/main` wholesale — Movement-specific
# additions should remain readable as named commits ahead of upstream.
```

Movement-specific code lives in:
- `prover-service/src/main.rs` — env-driven hardening wiring.
- `prover-service/src/request_handler/{prover_state,training_wheels,prover_handler,handler}.rs` — the rate-limit, aud-allowlist, body-limit, and concurrency-cap call sites.
- `prover-service/src/error.rs` — `SubRateLimited` and `AudNotAllowed` variants.
- `keyless-common/src/{rate_limit,jwk,jwt,observability,logging}.rs` — modules shared between the two services.
- `pepper-service/` — Movement-built service; not present upstream.

When upstream churns these files, prefer rebasing the Movement commits
onto the new upstream rather than merging — keeps the additive-commit
shape that makes review easy.
