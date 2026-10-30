# tlsnotary-cashu: design

A [TLSNotary](https://tlsnotary.org) notary that signs attestations, paid
per session with Cashu ecash from a whitelist of mints, plus the client
libraries (Rust, WebAssembly, TypeScript) needed to use it from a native
program or a web page. It is meant to run as a public service, so an
operator can sell attestations to anyone; there is no public instance at the
moment ([deploy/DEPLOY.md](deploy/DEPLOY.md) sets one up).

## 1. Why this exists

Upstream TLSNotary removed its notary server in alpha.13 and shut down
`notary.pse.dev`. What upstream ships today:

- `tlsn` (pinned here at **`main` `24b10ba`**, `0.1.0-alpha.16-pre`: alpha.15 plus
  the verifier-side bound on prover commitment ranges and prover stall fixes;
  move to the next tag when one is released): prover and verifier for MPC-TLS
  and proxy mode, and `tlsn::attestation` (signed attestations, presentations
  with selective disclosure, presentation verification).
- `tlsn-wasm`: a browser prover and verifier, **without attestations**.
- `tlsn-extension/servers/verifier`: a demo verifier server. No auth, client-chosen
  limits, an open WebSocket-to-TCP bridge (`/proxy?token=host:port`), results
  delivered by webhook to the operator, nothing signed.

A verifier that only tells its own operator what it saw is useless to third
parties. What a public service can offer is a **notary**: a party with a
published key that signs attestations about TLS sessions it took part in. A
relying party that trusts the key can then verify a presentation built from
the attestation, without ever talking to us.

Paying with ecash keeps the prover anonymous towards the notary, which is the
point of running it as a public service.

## 2. Components

```
crates/
  protocol/      tlsnc-protocol   wire types shared by server and clients (serde only)
  notary/        tlsnc-notary     the server: axum + cdk wallet + tlsn verifier + attestation signer
  client/        tlsnc-client     prover flow, attestation, presentation (native + wasm)
  verify/        tlsnc-verify     presentation verification (native + small wasm build)
  cli/           tlsnc            native CLI: Cashu wallet, buy ticket, notarize, present, verify
wasm/
  prover/        tlsnc-wasm       wasm-bindgen bindings for tlsnc-client (nightly, threads)
packages/
  client/        @tlsnc/client    TS: payment (NUT-24), transport (WebSocket), high-level API
  verify/        @tlsnc/verify    TS: presentation verification (no threads, no COOP/COEP)
apps/
  site/          static info page, llms.txt (agents), install.sh — served at /
  demo/          PWA at /app/: pay, notarize an API endpoint, present, verify
  extension/     Chrome MV3 extension: notarize the current tab, built-in Cashu wallet
deploy/          systemd unit, nftables egress table, nginx vhost, config example
```

Everything pins one `tlsn` version. Alpha releases are not wire-compatible, so
the server advertises its version in `/info` and every client refuses to pay a
server with a different one.

## 3. Pricing and tiers

The cost driver of MPC-TLS is **sent** data (the request): every request byte
is encrypted inside 2PC. Received data is cheap with deferred decryption
(upstream FAQ: ~40 KB of prover upload per 1 KB received). So tiers are cut by
`max_sent`, and `max_recv` is generous.

Prices are set deliberately high. Compute cost per session is a fraction of a
sat; the price exists so that nobody uses the service as a cheap proxy for
brute force or attacks. A VPN must stay cheaper.

Prices depend on **who opens the TCP connection to the target** (`egress`):

| Tier | `max_sent` | `max_recv` | Timeout | `egress=client` | `egress=notary` |
|---|---|---|---|---|---|
| S | 4 KiB | 1 MiB | 180 s | 42 sat | 210 sat |
| M | 16 KiB | 2 MiB | 300 s | 100 sat | 500 sat |
| L | 32 KiB | 2 MiB | 600 s | 200 sat | 1 000 sat |

- **`egress=client`**: MPC-TLS where the prover connects to the target itself
  (native CLI, or a browser using someone else's bridge). Our IP never appears.
- **`egress=notary`**: the browser bridge (`/v1/bridge`) or tlsn proxy mode,
  where the notary connects to the target. Traffic leaves from our IP, so it
  costs 5× more.

All of this is configuration (`config.toml`), not code. Nothing above 32 KiB
is sold: at 128 KiB an MPC session needs ~4.4 GB on the notary side.

## 4. Payment: tickets via NUT-24

Browsers cannot set headers on a WebSocket, and a token in a query string
lands in nginx access logs (bearer money in logs). So payment is a separate
HTTP step that buys a **ticket**:

```
POST /v1/tickets?tier=S&egress=client
  → 402 Payment Required
    X-Cashu: creqA…   (NUT-18 request: a = price, u = sat, m = whitelisted mints)

POST /v1/tickets?tier=S&egress=client
X-Cashu: cashuB…
  → 200 {"ticket": "tk_…", "expires_at": …, "attempts": 3, "tier": {…}, "egress": "client"}
  → 400 wrong mint / unit / amount (NUT-24)
  → 400 insufficient_after_fees + {"refund": "cashuB…"}: the mint's input fees
    took the payment below the price; the notary hands back what it received
  → 503 mint unreachable (the token is not spent; retry later)

POST /v1/tickets/status  {"ticket": "tk_…"}
  → attempts left, spent/expired, whether a session runs, whether there is room
```

The status endpoint exists for browsers: they cannot see the HTTP status of a
failed WebSocket upgrade, so the client asks why afterwards.

- The token is swapped at its mint immediately (`cdk` `Wallet::receive`). The
  received amount, **net of the mint's input fees**, must be ≥ the price
  (NUT-18 defines `a` as net of fees). Overpayment is kept.
- A ticket is a random 32-byte bearer string. Only its SHA-256 is stored
  (SQLite). It is worthless once used or expired.
- A ticket is valid for 30 minutes and up to 3 attempts. An attempt is
  consumed when a notarization session starts; the ticket is spent when an
  attestation is issued. A failed session therefore needs no refund: retry
  with the same ticket.
- A notary-egress ticket also covers client egress (it is strictly more).

## 5. Notarization protocol

```
WS /v1/notarize        Sec-WebSocket-Protocol: tlsnc, tlsnc.tk_…
```

The ticket travels as a second WebSocket subprotocol (browsers can set
those, not headers), so it never appears in a URL or an access log. The
server selects `tlsnc`. A `?ticket=` query parameter is accepted as a
fallback.

Checks before the upgrade (HTTP errors, no attempt consumed): ticket valid,
attempts left, capacity available (else 503 + `Retry-After`).

Over the WebSocket (binary frames, treated as one byte stream):

1. A `tlsn` session (`Session::new`) runs directly on the stream.
2. The notary waits for the prover's commit and enforces the ticket:
   - MPC: `max_sent_data`, `max_recv_data`, `max_recv_data_online` and record
     counts must fit the tier, otherwise `reject` before any preprocessing.
   - Proxy mode: only with an `egress=notary` ticket; the server name goes
     through the egress policy (§6) before the notary dials it.
3. MPC-TLS (or proxy) runs; the prover commits to its transcript
   (`DefaultHttpCommitter`), `prove` and `close`.
4. Both sides close the tlsn session and reclaim the stream. The prover sends
   one length-prefixed frame with the bincode `AttestationRequest`; the notary
   answers with one frame: status byte + bincode `Attestation` or an error
   string. (Upstream's example uses a TCP half-close here; WebSockets have none,
   hence the framing.)
5. The notary builds the attestation exactly as upstream's
   `examples/attestation/prove.rs`, signs it with its secp256k1 key, marks the
   ticket spent and closes.

In MPC mode the notary never learns the server name or the plaintext; it signs
commitments. The relying party learns the server identity from the
presentation and checks the certificate chain itself.

### Browser bridge

```
WS /v1/bridge?host=api.example.com   Sec-WebSocket-Protocol: tlsnc, tlsnc.tk_…
```

A browser cannot open TCP, so a browser prover connects to the target through
this bridge. It only relays ciphertext (TLS runs inside WASM, the bridge has no
keys). It is allowed only with an `egress=notary` ticket that has a
notarization session in progress, once per attempt, with byte caps
(`max_sent` + 16 KiB up, `max_recv` + 64 KiB down) and the tier's timeout.

## 6. Egress policy: the internet, never us

Anything that makes the notary open a connection (bridge, proxy mode) goes
through three independent layers.

1. **Code** (`notary/src/egress.rs`):
   - the host must be a DNS name (no IP literals, no port; the port is always 443);
   - it is resolved once through the configured public resolvers (not
     `/etc/resolv.conf`); if **any** address is not allowed, the host is
     rejected, and the connection goes to the checked IP (no DNS rebinding);
   - allowed are only globally routable unicast addresses: no loopback,
     RFC 1918, CGNAT, link-local, multicast, documentation, benchmarking,
     reserved, 6to4/Teredo/NAT64, IPv4-mapped IPv6;
   - plus a configured deny list: the operator's own public addresses (this
     host, its neighbours, other machines and VPN ranges);
   - per-target rate limit (sessions per host per hour).
2. **systemd** (`deploy/tlsnc-notary.service`): the service gets its Unix
   socket from systemd (socket activation, `deploy/tlsnc-notary.socket`, group
   `nginx`), so `IPAddressDeny=` can block localhost, IPv6 and every private
   and own range for the whole cgroup without breaking ingress.
3. **nftables** (`deploy/tlsnc-egress.nft`): for packets owned by uid `tlsnc`,
   only TCP 443 to global addresses and DNS to the configured resolvers;
   everything else is dropped. An optional SNAT rule moves this traffic to a
   dedicated IP address, so abuse never touches the address the operator's
   other services use.

## 7. Resource limits

- Weighted capacity: each session reserves its tier's memory estimate
  (S 400 MB, M 900 MB, L 1 600 MB) from a configured budget (code default
  6 000 MB; the example config uses 3 000 MB, which fits a host with about
  7 GB to spare) before the upgrade, when the mode is not known yet; proxy-mode
  sessions are over-reserved, which errs on the safe side. No room → 503
  before the upgrade, and the ticket attempt is not used.
- systemd `MemoryMax=4G` and `CPUQuota=300%` as the hard backstop.
- Per-tier session timeout; a stuck session releases its capacity.
- nginx: `limit_req` on `/v1/tickets`, long `proxy_read_timeout` on WebSockets.

## 8. Notary key

- secp256k1 (`tlsn` `Secp256k1Signer`; tlsn names the algorithm `k256`),
  32-byte key in a 0600 file.
- Published in `/info` and `/.well-known/tlsnc-notary.json`, together with
  retired keys and their validity window, so verifiers can keep accepting old
  attestations after a rotation and reject new ones made with a leaked key.
- Clients pin the key: the client libraries refuse to pay a notary whose key
  is not the expected one, if one was given.

## 9. Client libraries

### tlsnc-client (Rust, native and wasm)

- `notarize(notary_io, target, request, limits)` runs the full flow of §5
  and returns the attestation, the secrets and the HTTP response. `target` is
  either a byte stream to the server (MPC) or proxy mode.
- The TLS client runs on the prover side and verifies the server certificate
  against the Mozilla roots (`tlsn` `mozilla-certs`).
- Requests are HTTP/1.1 with `Accept-Encoding: identity` and
  `Connection: close` (TLSNotary cannot handle compression).
- `request_len()` lets the caller pick the smallest tier before paying.
- The server stream must be opened lazily (MPC setup takes a minute or more
  over the internet). The client also holds the server's end of stream until
  it has written its first application-data record: a `Connection: close`
  server usually closes while the MPC handshake is still running, and tlsn
  then recurses until the stack overflows
  ([tlsnotary/tlsn#1205](https://github.com/tlsnotary/tlsn/issues/1205)).
- `present(attestation, secrets, reveal)` builds a presentation with selective
  disclosure. `Authorization`, `Cookie`, `Set-Cookie` and `Proxy-Authorization`
  values are never revealed unless explicitly asked for.

### tlsnc (CLI)

The CLI is the cheapest client (it connects to the target itself) and the one
`llms.txt` points agents to, so it needs no setup beyond a notary URL
(`--notary` or `TLSNC_NOTARY`; there is no default) and a funded wallet in
`~/.tlsnc`.

- The wallet (cdk + SQLite) derives its seed from a 12-word BIP39 mnemonic
  (`~/.tlsnc/mnemonic`, 0600). `backup` prints the words; `restore` recreates
  the wallet and recovers its proofs by NUT-09/13 restore at the notary's
  mints. Wallets created before this kept a raw 64-byte `seed` file, still
  read.
- `receive`: a number mints that many sat over
  Lightning (an invoice with a terminal QR code, polled until paid) at the
  notary's first mint; anything else is received as a token.
- Prebuilt binaries (Linux x86_64/aarch64 against glibc 2.28, macOS arm64)
  are served from `/dl/` with `SHA256SUMS`; `install.sh` checks the sum.

### tlsnc-verify (Rust, wasm)

- `verify(presentation, trusted_keys)` → notary key, server name, connection
  time, revealed sent/received data with undisclosed bytes masked.
- Checks the notary signature against the pinned keys (with validity windows)
  and the server identity (certificate chain, hostname, handshake signature)
  against the Mozilla roots at the connection time.
- Builds on stable Rust without threads, so a relying party's page needs no
  cross-origin isolation.

### tlsnc-wasm and @tlsnc/client (browser)

- Multithreaded WASM (rayon over web workers) needs `SharedArrayBuffer`, so the
  embedding page must be cross-origin isolated (`COOP: same-origin`,
  `COEP: require-corp`). This is the main integration cost.
- The prover runs in a dedicated worker started by `@tlsnc/client`. The
  `@tlsnc/wasm` package is loaded at run time from a URL and must be served
  as static files with its layout intact: its thread spawner finds its own
  files (`snippets/…/spawn.js`, the `.wasm`) by relative paths, which
  bundlers rewrite.
- The bridge stream is opened lazily, when the prover first touches it after
  MPC setup: the notary only accepts a bridge for a running session, and the
  target should not sit on an idle TCP connection during preprocessing.
- `@tlsnc/client`: `info()`, `quote()`, `notarize()` (picks the tier, shows the
  price via `confirm`, buys the ticket over NUT-24, uses our bridge, proxy
  mode, or a third-party bridge priced as client egress), `present()`.
- Payment is a callback, `pay(paymentRequest) → token`. The library holds no
  wallet. Adapters: a pasted token, a UI callback, and `@cashu/cashu-ts`
  wallets. Before paying, the client checks that the requested amount equals
  the advertised price.

### Limits of a web page

A page has no access to other sites' cookies, so the browser library can
notarize what the app itself has credentials for: API tokens the user enters,
OAuth access tokens, public data. Data behind a session the user is logged in
to in their own browser needs the extension (below).

### Browser extension (apps/extension)

Upstream `tlsn-extension` is built around its own verifier server, plugins
and webhooks; it produces no signed attestation and has no payment step, so
it cannot use this notary. The extension here reuses `@tlsnc/wasm`,
`@tlsnc/client` and `@tlsnc/verify` instead:

- "Notarize this tab" opens an extension page that is cross-origin isolated
  through the manifest (the prover needs threads). It sends the tab's cookies
  only if the user ticks the box, and Chrome then asks for that one host
  (optional host permission). The session goes through the bridge (notary
  egress price) or proxy mode.
- The wallet is cashu-ts with NUT-13 deterministic secrets from a 12-word
  BIP39 mnemonic, proofs in `chrome.storage.local`: balance per mint (mints
  the notary does not accept are marked), receive by token or Lightning (the
  background worker finishes minting after the popup closes), send, history
  of every payment, export, and restore from the words.
- A ticket purchase that returns no ticket gives the payment back to the
  wallet; reveal choices default to hiding cookies and authorization.

## 10. Mints

The whitelist in `deploy/config.example.toml`, with what we saw while
running it. The first entry is where `tlsnc receive <amount>` and the
extension mint by default:

- `https://cashu.cz`: first. Its own description warns of a rug pull; sweep
  often.
- `https://mint.mountainlake.io`: no fees, fast, but it answered every
  Lightning quote check from one client IP with 429 for over ten minutes,
  so it is not the default for minting.
- `https://21mint.me`: no fees, fast.
- `https://mint.coinos.io`: watch `/v1/keysets` regressions.
- `https://mint.minibits.cash/Bitcoin`: rate-limits a server IP at about 80
  requests per 15 minutes; every ticket is one swap.

The notary has a wallet of its own. `tlsnc-notary wallet balance` and
`tlsnc-notary wallet send` (prints a token) are the sweep path.

## 11. What is deliberately not here

- Sizes above 32 KiB sent.
- Refunds (tickets are retried instead).
- Online decryption beyond a small cap (no live streaming of responses).
