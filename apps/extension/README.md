# tlsnc browser extension

A Chrome (MV3) extension that notarizes the page you are on with a
tlsnotary-cashu notary and pays for it from a built-in Cashu wallet.

Unlike a web page, an extension can send the cookies of the site you are
logged in to, so it can prove what *your* account page shows: a balance, an
order, a profile. The cookies travel only to the site, inside the TLS
session. The notary takes part in that session through MPC and never sees
them, and the presentation hides them unless you choose otherwise.

## Why not a fork of tlsn-extension

Upstream [tlsn-extension](https://github.com/tlsnotary/tlsn-extension) is
built around its own verifier server: `/session`, `/verifier` and `/proxy`,
with plugins that reveal data to that verifier and webhooks that report the
result. It does not produce a signed attestation that a third party can
check offline, and it has no payment step. Our notary speaks a different
protocol: a ticket bought with Cashu (NUT-24), MPC-TLS over `/v1/notarize`,
and a signed attestation that turns into a presentation.

A fork would have to replace upstream's transport, result model and plugin
runtime, and then keep up with its changes. This extension is small and
reuses this repository's pieces:

- `@tlsnc/wasm`, the upstream `tlsn` prover;
- `@tlsnc/client`, for tickets and the session;
- `@tlsnc/verify`, to check the presentation.

Upstream plugins could be supported later if they become
notary-agnostic.

## What it does

**Wallet** (popup, or the full page via "Open in tab"):

- **Receive**: paste a Cashu token, or enter an amount to get a Lightning
  invoice with a QR code at one of the notary's mints.
  - The invoice is minted as soon as it is paid. The background worker keeps
    checking it after the popup closes.
- **Send:** creates a token. Until somebody redeems it, History can take it
  back.
- **History** of received, minted, sent, notarization, refund and restored
  amounts, with mint fees and the ticket bought.
- **Backup:**
  - 12 BIP-39 words. Secrets are deterministic (NUT-13), so the words alone
    restore the wallet. Restoring asks each listed mint (NUT-09) for its
    signatures and keeps the unspent proofs. By default the list is the
    notary's mints plus the mints the wallet used.
  - "Export as token" moves a mint's whole balance out.
  - "Check spent" drops proofs that were spent elsewhere.
- **Settings:** the notary URL (required: there is no public notary, so
  enter the one you run or use), an optional pinned key, and the notary's
  prices and mints. Mints the notary does not accept are flagged in red.
- **Verify:** checks a `.presentation` file against the keys the configured
  notary publishes.

**Notarize** (the "Notarize this tab" button opens `notarize.html` for the
active tab's URL):

1. It builds a GET request. On request it adds the site's cookies: ticking
   the checkbox asks for the `cookies` permission and access to that one
   site, only at that moment. Extra headers can be added, such as
   `Authorization`.
2. It shows the tier and price and checks that the wallet holds enough at a
   mint the notary accepts.
3. "Pay N sat & notarize":
   - It buys a ticket (HTTP 402, `X-Cashu`, pay, retry). The wallet adds the
     notary's input fees.
   - It runs MPC-TLS through the notary's bridge or in proxy mode. Both are
     priced as "notary connects", because a browser cannot open TCP
     connections itself.
   - If the ticket is not issued, the wallet takes the token back, or
     receives the refund the notary sends.
   - A ticket that fails later can be retried with the same ticket.
4. It shows the response.
5. You choose what to reveal: request path, headers, and the response
   headers and body (all, none, or JSON paths). Cookie, Authorization and
   similar values stay locked unless you tick "allow revealing credentials".
6. "Build presentation" downloads `<host>-<time>.presentation` and verifies
   it on the spot. The attestation and secrets can be downloaded too, for
   `tlsnc present` later. The secrets file holds the whole transcript, so
   keep it private.

## Build and load

```sh
wasm/prover/build.sh                 # once: the threaded prover (nightly)
packages/verify/build-wasm.sh        # once: the verifier
npm run build -w @tlsnc/client -w @tlsnc/verify
cd apps/extension && npm install && npm run build
```

Then open `chrome://extensions`, turn on Developer mode, choose "Load
unpacked" and select `apps/extension/dist`.

The prover package is copied into `public/tlsnc-wasm/` at build time
(gitignored) and shipped as static files. The pages are cross-origin
isolated through the manifest (`cross_origin_embedder_policy`,
`cross_origin_opener_policy`), which the prover's WebAssembly threads need.

`npm test` runs the wallet against the public test mint
(`testnut.cashu.space`, which pays its own invoices): it mints, sends,
receives, pays, takes back and restores from the words. Set `TLSNC_OFFLINE=1`
to skip it.

## Limits

- Chrome or Chromium 116+ only. Firefox is untested; it does not support the
  manifest COOP/COEP keys that extension pages need here.
- GET requests only from the UI. Use the CLI or `@tlsnc/client` for other
  methods and bodies.
- Large cookie jars push a request into a more expensive tier, since the
  request size sets the tier. Tick only what the page needs, or add the one
  header it needs by hand.
- The wallet is meant for small amounts:
  - The words and proofs are stored unencrypted in the browser profile
    (`chrome.storage.local`).
  - It holds `sat` only and supports no locking conditions.
  - It cannot melt (pay Lightning invoices out). Export a token to another
    wallet instead.
- A presentation is checked against the keys the notary publishes now. To
  trust a specific key, pin it in Settings.
