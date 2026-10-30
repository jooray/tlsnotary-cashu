# Running a notary

This guide sets up `tlsnc-notary` on a Linux server behind nginx, at a name
such as `notary.example.org`. It was written on AlmaLinux 10 (SELinux
enforcing) and should work on any systemd distribution with nftables.
Commands run as root unless noted.

Read [DESIGN.md](../DESIGN.md) §6 first. The notary connects to hosts its
clients name (proxy mode and the browser bridge), so the three egress layers
below are what keep it away from localhost, your private network and your
other machines. Do not skip them.

## What you need

- A Linux server with systemd, nftables, nginx and about 4 GB of RAM for the
  notary (a tier-L session reserves 1.6 GB; see `memory_budget_mb` and the tiers in `config.example.toml`).
- A DNS name pointing at it and a TLS certificate for that name (certbot).
- A build machine with Rust ≥ 1.95. The scripts assume macOS on arm64 with
  rustup, `cargo-zigbuild` and zig for cross-compiling; on a Linux build
  machine, build natively with `cargo build --release` instead.
- For the web app and the extension: Node.js ≥ 22, and once
  `wasm/prover/build.sh` and `packages/verify/build-wasm.sh` (nightly Rust,
  `wasm-pack`, an LLVM clang that targets wasm32).

## 1. Name and certificate

Point an A record at the server (an AAAA record too only if the server has
global IPv6, see step 3). Get a certificate, for example with
`certbot certonly --nginx -d notary.example.org`. The nginx template expects
it at `/etc/letsencrypt/live/notary.example.org/`.

## 2. Build the server

Cross-compile from macOS (glibc 2.28 baseline, so it runs on most current
distributions):

```sh
rustup target add x86_64-unknown-linux-gnu
cargo zigbuild --release -p tlsnc-notary --target x86_64-unknown-linux-gnu.2.28
```

If Homebrew's `rustc` is older than 1.95 and comes first in `PATH`, put
rustup's toolchain first, e.g.
`PATH=~/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin:$PATH`.

Then build the web app, the extension zip and the CLI binaries for `/dl/`:

```sh
npm install
deploy/build-web.sh            # or --no-bin to skip the CLI binaries
```

## 3. Deploy

`deploy/deploy.sh` does steps 3a to 3e over SSH and is safe to rerun:

```sh
export TLSNC_HOST=root@server.example.org TLSNC_DOMAIN=notary.example.org
deploy/deploy.sh
```

What it does, in case you prefer to do it by hand:

**3a. User, binary, config.**

```sh
useradd --system --home-dir /var/lib/tlsnc --shell /sbin/nologin tlsnc
install -m 0755 tlsnc-notary /usr/local/bin/
install -d -m 0755 /etc/tlsnc
cp config.example.toml /etc/tlsnc/config.toml    # then edit it
```

In the config, review:

- `mints`: the Cashu mints you accept. The first one is where clients mint by
  default over Lightning, so put a reliable one first.
- the prices of each tier;
- `[egress] deny`: **the public addresses of this server and of your other
  machines**. Private and reserved ranges are always refused; your own public
  ones are not unless you list them here;
- `key_valid_from`: set it to the current Unix time.

**3b. Key.**

```sh
install -d -m 0700 -o tlsnc -g tlsnc /var/lib/tlsnc
runuser -u tlsnc -- tlsnc-notary --config /etc/tlsnc/config.toml keygen
```

The printed public key is what relying parties pin. The notary also serves it
at `/.well-known/tlsnc-notary.json`; publish it somewhere else as well, so
verifiers can check they got the right one.

**3c. Egress rules and service.** Add the same addresses as in the deny list
to `deploy/tlsnc-egress.nft` (the `never` set) and to `IPAddressDeny=` in
`deploy/tlsnc-notary.service`. If the server has global IPv6, keep the
`IPAddressDeny=::/0` line anyway unless you also extend the nftables rules to
IPv6.

```sh
install -m 0644 tlsnc-egress.nft /etc/tlsnc/egress.nft
install -m 0644 tlsnc-egress.service tlsnc-notary.socket tlsnc-notary.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tlsnc-egress.service tlsnc-notary.socket tlsnc-notary.service
```

The egress table (`inet tlsnc_egress`) is separate from firewalld's or
your own tables, and a firewall reload leaves it alone. Check it with
`nft list table inet tlsnc_egress`.

The socket is owned by group `nginx` (`SocketGroup=` in
`tlsnc-notary.socket`). On Debian and Ubuntu nginx runs as `www-data`, so
change it there.

**3d. SELinux** (only where it is enforcing). nginx (`httpd_t`) may neither
write a socket labelled `var_run_t` nor connect to a process in
`unconfined_service_t`, so it answers 502 with
`connect() … (13: Permission denied)` until both are allowed:

```sh
semanage fcontext -a -t httpd_var_run_t '/run/tlsnc(/.*)?'
checkmodule -M -m -o tlsnc-nginx.mod tlsnc-nginx.te
semodule_package -o tlsnc-nginx.pp -m tlsnc-nginx.mod && semodule -i tlsnc-nginx.pp
systemctl restart tlsnc-notary.socket tlsnc-notary.service
```

The module lets nginx connect to the Unix socket of any service running
unconfined, not only this one. A narrower rule needs an SELinux domain of
its own for the notary. A TCP listener would avoid the module but needs the
service to reach localhost, which is exactly what `IPAddressDeny=` forbids.

**3e. nginx and the web.** Copy `nginx-notary.conf` to
`/etc/nginx/conf.d/notary.conf`, replace `notary.example.org` and the
webroot, then:

```sh
install -d -m 0755 /var/www/notary
nginx -t && systemctl reload nginx
rsync -a --delete dist-web/ root@server.example.org:/var/www/notary/
```

`/app/` is the web app (it needs the COOP/COEP headers from the template),
`/dl/` the CLI binaries and the extension zip, and `/` redirects to the app.
The web app reloads itself when you deploy a new version.

## 4. Checks

```sh
curl -s https://notary.example.org/info | jq .notary_key
curl -si -X POST 'https://notary.example.org/v1/tickets?tier=S&egress=client' | grep -i x-cashu

# Egress policy, as the service sees it:
runuser -u tlsnc -- tlsnc-notary -c /etc/tlsnc/config.toml check-host localtest.me        # refused (::1)
runuser -u tlsnc -- tlsnc-notary -c /etc/tlsnc/config.toml check-host notary.example.org  # refused once your address is in deny
runuser -u tlsnc -- tlsnc-notary -c /etc/tlsnc/config.toml check-host example.com         # allowed

# Layer 3 really drops: this must fail, and the drop counter must move.
runuser -u tlsnc -- curl -m 5 http://127.0.0.1/ ; nft list chain inet tlsnc_egress notary
```

A paid end-to-end run from another machine:

```sh
export TLSNC_NOTARY=https://notary.example.org
tlsnc receive 500
tlsnc notarize https://httpbin.org/json
tlsnc present notarized --json slideshow.author
tlsnc verify notarized.presentation
```

Over the internet the MPC setup takes one to two minutes before the request
goes out.

## 5. Operations

- **The wallet is bearer money**: `/var/lib/tlsnc/wallet.sqlite` plus
  `wallet.seed`. Back up `/var/lib/tlsnc` (it also holds `notary.key`, which
  you cannot replace without every verifier re-pinning) and `/etc/tlsnc`.
  The seed alone restores the funds.
- **Sweep the earnings**:
  `runuser -u tlsnc -- tlsnc-notary -c /etc/tlsnc/config.toml wallet balance`,
  then `wallet send --mint … --amount …` prints a token. Sweep mints you trust
  less more often.
- **Stats**: `tlsnc-notary stats` shows tickets sold, attestations and sat received.
- **Mint rate limits**: some mints limit requests per IP address, and each
  ticket is one swap. If payments through one start failing, drop it from
  `mints`.
- **Key rotation**: move the current key to `[[previous_keys]]` with
  `valid_until` = now, create a new one (`keygen` with a new
  `signing_key_file`), set `key_valid_from` and restart. If a key leaked, set
  its `valid_until` to the time of the leak, not to now.
- **tlsn upgrades** are wire-incompatible: the server, the CLI, the WASM
  prover and the web app move to the new revision together (`TLSN_VERSION` in
  `crates/protocol` and `packages/client`).
- **A separate egress address** (recommended before you advertise
  notary-side egress widely): add an address to the server and enable the
  SNAT block at the end of `tlsnc-egress.nft`, so abuse reports land on that
  address and not on the one your other services use.
- **Logs**: `journalctl -u tlsnc-notary.service`. The nginx access log for the
  API omits query strings, and tickets never appear in URLs.
