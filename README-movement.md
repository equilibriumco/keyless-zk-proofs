# Movement Keyless — fork notes

This is `equilibriumco/keyless-zk-proofs`'s `movement-main` branch — a
fork of [`aptos-labs/keyless-zk-proofs`](https://github.com/aptos-labs/keyless-zk-proofs)
that runs Aptos Keyless on the Movement network.

The fork keeps the upstream architecture: a `prover-service` that mints
Groth16 proofs from JWTs and a `pepper-service` that derives per-user
peppers via HMAC. All Movement-specific changes live on this branch as
named, additive commits — see `git log --oneline main..movement-main`.

Read the upstream [`README.md`](README.md) first for the protocol-level
explanation. This file documents only what's different on the Movement
fork.

## End-to-end testing

The reference end-to-end test drives the prover from a Movement
keyless wallet (the customer's `motion-wallet` repo, branch
`feat/keyless-wallet` — ask the customer for the URL): Google OAuth →
pepper-service → Groth16 proof → on-chain tx on Movement Bardock
testnet.

> **Check out the `movement-main` branch first.** All Movement-specific
> additions — `docker-compose.yml`, the hardened prover wiring, the
> pepper-service crate, this file itself — live on `movement-main`,
> not on `main` (which mirrors upstream Aptos). If `docker compose up`
> says "no configuration file provided" or you don't see
> `pepper-service/` in the tree, you're on the wrong branch.
>
> ```sh
> git switch movement-main   # or `git checkout movement-main`
> ```

### 1. Sibling-clone layout

motion-wallet pins its keyless + WDK dependencies via `file:../` paths,
so each repo needs to live next to the others as siblings:

```
~/Projects/
├── keyless-zk-proofs/                              (this repo — prover + pepper)
├── motion-wallet/                                  Chrome MV3 extension
├── movement-keyless/                               @eigerco/movement-keyless SDK
├── wdk-wallet-movement/                            customer-owned
├── wdk-protocol-bridge-layerzero-movement/         customer-owned
└── wdk-protocol-swap-mosaic-movement/              customer-owned
```

```sh
cd ~/Projects   # or wherever
git clone git@github.com:equilibriumco/keyless-zk-proofs.git
git -C keyless-zk-proofs switch movement-main

git clone <motion-wallet-url>                     # customer-owned; ask for it
git -C motion-wallet switch feat/keyless-wallet   # keyless work isn't on main

git clone git@github.com:equilibriumco/movement-keyless.git
# (no branch switch needed — SDK lives on master)

# The three wdk-* repos are customer-owned; ask whoever maintains them
# for the SSH URLs and clone them as siblings.
```

> Whenever you switch branches in motion-wallet (e.g. `main` ↔
> `feat/keyless-wallet`), the lockfile changes and you need to redo
> `rm -rf node_modules && npm ci --engine-strict=false` before
> building — `npm ci` is the only step that reconciles `node_modules/`
> with the new lockfile, and skipping it leaves stale or missing deps
> like `lottie-react` from whichever branch you came from.

### 2. Start the prover + pepper services

Generate dev secrets — the training-wheels secret MUST be exactly 64
hex chars with NO trailing newline (`openssl rand -hex 32 > …` appends
`\n` and Aptos's hex decoder rejects it, panicking with `Failed to parse
the training wheels private key from hex string: DeserializationError`):

```sh
cd keyless-zk-proofs
mkdir -p secrets   # gitignored
openssl rand 32 > secrets/pepper && chmod 644 secrets/pepper
printf '%s' "$(openssl rand -hex 32)" > secrets/training_wheels
chmod 644 secrets/training_wheels
```

Then bring everything up:

```sh
docker compose up --build
```

First build takes a while (~10 min — the prover image downloads ~6 GB
of `circuit-v4.0.0` ceremony artifacts during the build step). Subsequent
runs are seconds because the cached layer with the artifacts is reused.

Once running:
- prover-service on `http://localhost:8080` — POST `/v0/prove`, GET `/healthcheck`, `/cached/jwk`, `/about`, `/config`.
- pepper-service on `http://localhost:3002` on the host (`POST /pepper`, `GET /health`); also reachable inside the compose network as `http://pepper-service:3002`.

To configure the prover for a specific Movement network, set the
`PROVER_*` env vars in `docker-compose.yml` (see the env-vars table below).

### 3. Build the SDK + install WDK dependencies

Two things need to happen inside the sibling repos before the wallet
build can resolve types:

1. The SDK (`movement-keyless/sdk`) needs `npm run build` to emit
   `dist/` — `@eigerco/movement-keyless`'s `package.json` points
   `main`/`types` at `dist/`, and the wallet's `tsc` fails with
   `Cannot find module '@eigerco/movement-keyless' or its
   corresponding type declarations` if `dist/` is missing.

2. Each `wdk-*` repo needs `npm install` to populate its own
   `node_modules/`. The WDK packages ship pre-generated `.d.ts`
   files (no build step), but their type chains extend classes from
   `@tetherto/wdk-wallet`. Without each WDK repo's `node_modules/`
   in place, the wallet sees `WalletAccountMovement` as a class with
   an unresolved parent, and `tsc` reports missing methods like
   `Property 'getAddress' does not exist on type 'WalletAccountMovement'`
   that are actually inherited from `@tetherto/wdk-wallet`'s
   `WalletAccountReadOnly`.

```sh
cd movement-keyless/sdk
npm install
npm run build                        # emits sdk/dist/

cd ../../wdk-wallet-movement                       && npm install
cd ../wdk-protocol-bridge-layerzero-movement       && npm install
cd ../wdk-protocol-swap-mosaic-movement            && npm install
```

### 4. Configure + build the wallet

**Google OAuth setup.** The wallet needs an OAuth 2.0 client_id from
Google Cloud Console and a registered redirect URI pointing at your
extension. Chrome MV3 extensions use the `chrome.identity.launchWebAuthFlow`
helper, which redirects to `https://<extension-id>.chromiumapp.org/` —
where `<extension-id>` is assigned by Chrome the first time you load
the unpacked extension. So there's a small chicken-and-egg:

1. Build + load the extension once with any non-empty placeholder for
   `VITE_GOOGLE_CLIENT_ID` (e.g. `placeholder.apps.googleusercontent.com`)
   — `keyless-config.ts` only checks that it's non-empty.
2. After "Load unpacked" in step 5, copy the extension ID shown on
   the extension's card at `chrome://extensions`.
3. In [Google Cloud Console](https://console.cloud.google.com/)
   → **APIs & Services** → **Credentials** → **Create Credentials**
   → **OAuth client ID**. Application type: **Web application**.
   Add `https://<your-extension-id>.chromiumapp.org/` (note the
   trailing slash) under **Authorized redirect URIs**.
4. The "OAuth consent screen" needs to exist for the project — set
   it to "External" with your Google account as a test user. The
   only scope keyless needs is the default `openid email` pair the
   SDK requests; no API enablement required.
5. Copy the resulting Client ID, paste it into `.env.local` as
   `VITE_GOOGLE_CLIENT_ID`, rebuild the wallet, reload the unpacked
   extension. Now `chrome.identity.launchWebAuthFlow` will round-trip.

> The Client ID is baked into every user's keyless address as the JWT
> `aud` claim — changing it later orphans every existing address
> derived under the old ID. Treat it as a deploy-time constant.

`.env.local` in `motion-wallet/`:

```
VITE_PROVER_URL=http://localhost:8080
VITE_PEPPER_SERVICE_URL=http://localhost:3002
VITE_GOOGLE_CLIENT_ID=<your-google-oauth-client-id>
# Movement Bardock testnet's max_exp_horizon_secs; override for other chains.
# VITE_EXP_HORIZON_SECS=10000000
```

If you set `PROVER_ALLOWED_AUDS` on the prover, the same client_id
must be in that list — otherwise the prover rejects with 403
`AudNotAllowed` before generating the proof. (For local dev with
`docker-compose.override.yml`, the env var defaults to unset =
"allow any aud", so this only matters in production.)

Build:

```sh
cd ../motion-wallet            # from the last wdk-* repo
npm ci --engine-strict=false   # some transitive dep mis-pins engines.node
npm run build
```

### 5. Load the extension + run the flow

In Chrome: `chrome://extensions` → toggle Developer Mode on → "Load
unpacked" → select `motion-wallet/dist/`.

The wallet's keyless onboarding will:
1. Generate an ephemeral keypair + Poseidon-committed OAuth nonce.
2. Open Google OAuth (`chrome.identity.launchWebAuthFlow`) → receive JWT.
3. `POST localhost:3002/pepper { jwt }` → pepper.
4. Derive the on-chain address locally from `jwt + pepper + uidKey`.
5. `POST localhost:8080/v0/prove` with the full `RequestInput` → proof + TW signature.
6. Build a `KeylessAccount` and expose the on-chain address to the UI.

### 6. Fund the address + submit a tx

At this point the account exists in the keyless sense — the wallet
knows its address and can sign — but it has **zero balance**. The
chain considers any account "real" only after at least one tx
funds it (creates the account resource on-chain). To submit
transactions, fund the address first:

- **Faucet**: the Movement Bardock testnet faucet drops a small amount
  to any address. URL + interface change occasionally; check
  https://docs.movementnetwork.xyz for the current endpoint.
- **From another testnet account**: if you already hold testnet MOVE,
  send some to the new keyless address with the Aptos / Movement CLI
  or any wallet.

After funding, submit a tx from the wallet (e.g. a 1-MOVE self-transfer)
to confirm the end-to-end pipeline produces an on-chain-valid proof. The
migration was originally verified by tx
[`0x0183cd8f…02896`](https://explorer.movementnetwork.xyz/txn/0x0183cd8f6e75086f8381895e08dfb7e5fb3d4f6433400d5365accbcceb402896?network=bardock%20testnet)
on Movement Bardock testnet.

### Common gotchas

- **CORS error fetching pepper from the SW.** The wallet's MV3 manifest
  must include the pepper-service host in `host_permissions` —
  `motion-wallet/vite.config.ts` derives this from
  `VITE_PEPPER_SERVICE_URL` so it just needs to be set at build time.
- **`INVALID_SIGNATURE` on tx submission with a valid proof.** Either
  the on-chain VK doesn't match the prover's zkey (run
  `scripts/check-infra.sh` against the target network to compare), or
  the on-chain keyless module enforces a registered training-wheels
  pubkey that doesn't match the one in `secrets/training_wheels`.
- **`PROVER_ALLOWED_AUDS` empty.** Fine for testing, but in production
  set it to the OAuth client_ids of every wallet the prover should
  mint proofs for — otherwise anyone with a Google JWT can use the
  prover. (For Movement Bardock testnet the wallet's client_id is
  `733227620215-…apps.googleusercontent.com`.)

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

## Hardening smoke tests (optional)

The wallet flow above is the headline E2E. If you also want to verify
the Movement-specific hardening layer (rate limits, body-size cap,
CORS, concurrency semaphore) without firing up a wallet or producing
a real JWT, the following curl recipes exercise each control directly.
Each test uses a `docker-compose.override.yml` (gitignored) to inject
the tight env knob; restore it to empty between tests.

```sh
# Healthchecks — sanity-check both services are up.
curl -sf http://localhost:8080/healthcheck         # → "OK"
curl -sf http://localhost:3002/health              # → "ok"

# Body limit: default 64 KiB, so a 128 KiB POST returns 413.
head -c $((128*1024)) /dev/urandom | base64 > /tmp/big.json
curl -s -o /dev/null -w "%{http_code}\n" \
     -X POST -H 'Content-Type: application/json' \
     --data-binary @/tmp/big.json http://localhost:8080/v0/prove
# → 413

# Per-IP rate limit: tighten to 5/min burst 2, then hammer 10×.
cat > docker-compose.override.yml <<'EOF'
services:
  prover-service:
    environment:
      PROVER_IP_RATE_PER_MIN: "5"
      PROVER_IP_RATE_BURST: "2"
EOF
docker compose up -d --force-recreate prover-service
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code}\n" \
       -X POST -H 'Content-Type: application/json' \
       -d '{}' http://localhost:8080/v0/prove
done | sort | uniq -c
# → ~2× 400 (passed the rate-limit, rejected at handler for empty body)
#   ~8× 429 (rate-limited)

# Concurrency semaphore: capacity 1, 20 concurrent.
cat > docker-compose.override.yml <<'EOF'
services:
  prover-service:
    environment:
      PROVER_MAX_CONCURRENCY: "1"
EOF
docker compose up -d --force-recreate prover-service
> /tmp/codes.txt
for i in $(seq 1 20); do
  (curl -s -o /dev/null -w "%{http_code}\n" \
        -X POST -H 'Content-Type: application/json' \
        -d '{}' http://localhost:8080/v0/prove >> /tmp/codes.txt) &
done; wait
sort /tmp/codes.txt | uniq -c
# → some 400 / some 429 / some 503 (semaphore over-cap)

# CORS allowlist: only the listed origin gets an ACAO header back.
cat > docker-compose.override.yml <<'EOF'
services:
  prover-service:
    environment:
      PROVER_ALLOWED_ORIGINS: https://wallet.example.com
EOF
docker compose up -d --force-recreate prover-service
curl -i -s -X OPTIONS \
     -H 'Origin: https://wallet.example.com' \
     -H 'Access-Control-Request-Method: POST' \
     http://localhost:8080/v0/prove | grep -i access-control-allow-origin
# → access-control-allow-origin: https://wallet.example.com
curl -i -s -X OPTIONS \
     -H 'Origin: https://attacker.example.com' \
     -H 'Access-Control-Request-Method: POST' \
     http://localhost:8080/v0/prove | grep -i access-control-allow-origin
# → (no header)

# Reset the override when done.
rm docker-compose.override.yml
docker compose up -d --force-recreate prover-service
```

The `(iss, sub)` rate limit, aud allowlist, and the
forged-signature-doesn't-drain-bucket security property need a JWT
(real or locally signed) to exercise; the in-tree Rust tests cover
them. Run the full suite with:

```sh
RUSTFLAGS="--cfg tokio_unstable" cargo test \
  -p prover-service -p pepper-service -p aptos-keyless-common
```

At the time of writing 30+ tests pass without external setup; anything
needing `LOCAL_SETUP_PROCURED` (circuit/witness binaries) is skipped or
fails only on the artifact dependency, not on logic.
