# tlsnotary-cashu

**[Project page](https://jooray.github.io/tlsnotary-cashu/)** ·
[llms.txt](https://jooray.github.io/tlsnotary-cashu/llms.txt) (instructions for AI agents) ·
[Run a notary](deploy/DEPLOY.md)

A [TLSNotary](https://tlsnotary.org) notary server that signs attestations
and charges per session in Cashu ecash, with clients for it: a CLI with a
built-in wallet, libraries for native programs and web pages, a web app and
a browser extension.

**There is no public instance.** To use any of the clients you need a notary,
so run your own: [deploy/DEPLOY.md](deploy/DEPLOY.md). A public one ran at
`tlsn.cypherpunk.today` for a few days in October 2026 and is shut down.

You make an HTTPS request; the notary takes part in the TLS session through
multi-party computation without seeing the request or the response, and signs
an attestation of it. From the attestation you build a presentation that
reveals only what you choose (say, one JSON field of your bank's API
response). Anyone who trusts the notary's key can verify it offline.

Upstream TLSNotary no longer ships a notary server (removed in alpha.13); this
project wraps upstream `tlsn` (unchanged, pinned to a `main` revision after
v0.1.0-alpha.15, see `Cargo.toml`) with payment, limits and an egress policy.
The design and its rationale are in [DESIGN.md](DESIGN.md).

## Pieces

| Path | What |
|---|---|
| `crates/notary` | `tlsnc-notary`, the server: `/info`, tickets via NUT-24, `/v1/notarize`, `/v1/bridge` |
| `crates/client` | `tlsnc-client`, the prover flow and presentations (native and wasm) |
| `crates/verify` | `tlsnc-verify`, presentation verification (native and a small wasm build) |
| `crates/cli` | `tlsnc`, the command-line client, with a small Cashu wallet |
| `crates/protocol` | wire types shared by all of the above |
| `wasm/prover` | `@tlsnc/wasm`, the browser prover (nightly, threads) |
| `packages/client` | `@tlsnc/client`, browser API: pay, notarize, present |
| `packages/verify` | `@tlsnc/verify`, browser/Node verification (no threads, no COOP/COEP) |
| `apps/site` | the project page on GitHub Pages and `llms.txt` |
| `apps/demo` | the web app (PWA), served by the notary at `/app/` |
| `apps/extension` | Chrome extension: notarize the current tab (with its cookies), built-in Cashu wallet with backup ([README](apps/extension/README.md)) |
| `deploy` | systemd units, nftables egress table, nginx template, deploy scripts, [DEPLOY.md](deploy/DEPLOY.md) |

## Prices

The defaults in `deploy/config.example.toml`, per session in sat; each
operator sets their own (`/info` shows them). They are high on purpose, so a
notary is not worth using as a cheap proxy. Who opens the connection to the target decides the
column: the native CLI connects itself, a browser goes through the notary.

| Tier | Request (sent) | Response | Client connects | Notary connects |
|---|---|---|---|---|
| S | ≤ 4 KiB | ≤ 1 MiB | 42 | 210 |
| M | ≤ 16 KiB | ≤ 2 MiB | 100 | 500 |
| L | ≤ 32 KiB | ≤ 2 MiB | 200 | 1 000 |

A ticket allows 3 attempts within 30 minutes; a failed session is retried
with the same ticket, not refunded.

## CLI

```sh
cargo install --locked --git https://github.com/jooray/tlsnotary-cashu tlsnc   # or a binary from the latest release
export TLSNC_NOTARY=https://notary.example.org   # your notary

tlsnc receive 500                          # Lightning invoice (with a QR code) for 500 sat; or: tlsnc receive cashuB…
tlsnc notarize https://httpbin.org/json    # pays 42 sat from the wallet, writes notarized.attestation + .secrets
tlsnc present --json slideshow.author      # writes notarized.presentation
tlsnc verify notarized.presentation        # against the notary's published keys
```

The notary comes from `--notary` or `TLSNC_NOTARY` (there is no default) and
the wallet lives in `~/.tlsnc`
(`--wallet`, `TLSNC_WALLET`). Wallet commands: `balance`, `receive
<token|amount>`, `send <amount>`, `backup` (12 words) and `restore "<words>"`
(NUT-09/13 restore from the notary's mints).

`--mode proxy` or `--mode bridge` make the notary connect (5× the price);
`--token cashuB…` pays with a token instead of the wallet; `--ticket` retries
a failed attempt; `--expect-key` refuses a notary with another key.

## Browser

```ts
import { TlsnClient, tokenPayer } from "@tlsnc/client";
import { verify, fetchNotaryKeys } from "@tlsnc/verify";

const client = new TlsnClient({ notary: "https://notary.example.org" });
const n = await client.notarize({
  request: { url: "https://api.example.com/me", headers: [["Authorization", "Bearer …"]] },
  pay: tokenPayer(token),
  onStep: (s) => console.log(s),
});
const presentation = await client.present(n, { response: { body: { json_paths: ["name"] } } });

// Anywhere, later (no COOP/COEP needed):
const v = await verify(presentation, await fetchNotaryKeys("https://notary.example.org"));
```

The page that notarizes must be cross-origin isolated
(`Cross-Origin-Opener-Policy: same-origin`,
`Cross-Origin-Embedder-Policy: require-corp`), and must serve the
`@tlsnc/wasm` package directory as static files (default path
`/tlsnc-wasm/`); `apps/demo/vite.config.ts` shows both.

A web page has no access to other sites' cookies: it can notarize what it
has credentials for (API tokens the user enters, OAuth tokens, public data).
Sessions the user is logged in to in their own browser need the extension
(`apps/extension`).

## Building

```sh
cargo test                                   # unit tests
cargo test --release -p tlsnc-notary --test e2e -- --ignored   # real MPC-TLS to httpbin.org
wasm/prover/build.sh                         # nightly + wasm-pack + Homebrew llvm (for ring)
packages/verify/build-wasm.sh
npm install && npm run build                 # TS packages and the demo
```

## License

MIT. Upstream TLSNotary code used or adapted here (`tlsn` crates as
dependencies; `wasm/prover/src/io.rs` copied from `tlsn-wasm`) is MIT OR
Apache-2.0, © the TLSNotary team.
