#!/bin/sh
# Installs or updates a notary on a Linux server over SSH, following
# deploy/DEPLOY.md. Idempotent: an existing config, key and wallet are kept.
#
#   export TLSNC_HOST=root@server.example.org TLSNC_DOMAIN=notary.example.org
#   deploy/build-web.sh               # first: builds dist-web/ (app, binaries)
#   deploy/deploy.sh                  # server binary, units, nft, SELinux, nginx, web
#   deploy/deploy.sh --web-only       # just copy dist-web/
#
# Needs on the server: systemd, nftables, nginx with a certificate for
# $TLSNC_DOMAIN at /etc/letsencrypt/live/$TLSNC_DOMAIN/, rsync. Review
# /etc/tlsnc/config.toml (mints, prices, deny list) after the first run.
set -eu
cd "$(dirname "$0")/.."
HOST="${TLSNC_HOST:?set TLSNC_HOST, e.g. root@server.example.org}"
DOMAIN="${TLSNC_DOMAIN:?set TLSNC_DOMAIN, e.g. notary.example.org}"
WEBROOT=/var/www/notary
BIN=target/x86_64-unknown-linux-gnu/release/tlsnc-notary
STAGE=/root/tlsnc-deploy

[ -d dist-web/app ] || { echo "run deploy/build-web.sh first" >&2; exit 1; }

if [ "${1:-}" != "--web-only" ]; then
  [ -x "$BIN" ] || { echo "missing $BIN: see DEPLOY.md, step 2" >&2; exit 1; }
  ssh "$HOST" "install -d -m 0700 $STAGE"
  scp -q "$BIN" deploy/config.example.toml deploy/tlsnc-notary.socket \
    deploy/tlsnc-notary.service deploy/tlsnc-egress.service deploy/tlsnc-egress.nft \
    deploy/nginx-notary.conf deploy/tlsnc-nginx.te "$HOST:$STAGE/"
  ssh "$HOST" STAGE="$STAGE" WEBROOT="$WEBROOT" DOMAIN="$DOMAIN" sh -s <<'REMOTE'
set -eu
cd "$STAGE"
id tlsnc >/dev/null 2>&1 || useradd --system --home-dir /var/lib/tlsnc --shell /sbin/nologin tlsnc
install -m 0755 tlsnc-notary /usr/local/bin/tlsnc-notary
install -d -m 0755 /etc/tlsnc
if [ ! -f /etc/tlsnc/config.toml ]; then
  sed "s/^# key_valid_from = .*/key_valid_from = $(date +%s)/" config.example.toml > /etc/tlsnc/config.toml
  chmod 0644 /etc/tlsnc/config.toml
  echo "created /etc/tlsnc/config.toml: review mints, prices and the deny list"
fi
# Keep a locally edited egress.nft (your deny ranges); install it only once.
[ -f /etc/tlsnc/egress.nft ] || install -m 0644 tlsnc-egress.nft /etc/tlsnc/egress.nft
install -m 0644 tlsnc-egress.service tlsnc-notary.socket tlsnc-notary.service /etc/systemd/system/
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/tlsnc-notary.service /etc/systemd/system/tlsnc-notary.socket /etc/systemd/system/tlsnc-egress.service \
  || echo "WARNING: systemd-analyze verify reported problems (above)"

# The key lives in the service's StateDirectory, owned by tlsnc.
install -d -m 0700 -o tlsnc -g tlsnc /var/lib/tlsnc
if [ ! -f /var/lib/tlsnc/notary.key ]; then
  runuser -u tlsnc -- /usr/local/bin/tlsnc-notary --config /etc/tlsnc/config.toml keygen
fi

systemctl enable tlsnc-egress.service tlsnc-notary.socket tlsnc-notary.service
systemctl restart tlsnc-egress.service
systemctl restart tlsnc-notary.socket
systemctl restart tlsnc-notary.service
nft list table inet tlsnc_egress >/dev/null && echo "egress table loaded"

# SELinux (Fedora, RHEL, AlmaLinux...): nginx (httpd_t) may write to the
# socket and connect to the notary (unconfined_service_t).
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != Disabled ]; then
  if ! semodule -l | grep -qx tlsnc-nginx; then
    checkmodule -M -m -o tlsnc-nginx.mod tlsnc-nginx.te
    semodule_package -o tlsnc-nginx.pp -m tlsnc-nginx.mod
    semodule -i tlsnc-nginx.pp
  fi
  # grep reads all of it: with -q, semanage dies of SIGPIPE and prints a traceback.
  semanage fcontext -l -C | grep '^/run/tlsnc' >/dev/null || semanage fcontext -a -t httpd_var_run_t '/run/tlsnc(/.*)?'
  restorecon -R /run/tlsnc
fi

# nginx: the group of the socket (tlsnc-notary.socket) must be nginx's.
install -d -m 0755 "$WEBROOT"
sed -e "s/notary\.example\.org/$DOMAIN/g" -e "s#/var/www/notary#$WEBROOT#g" nginx-notary.conf \
  > /etc/nginx/conf.d/notary.conf
nginx -t
systemctl reload nginx
REMOTE
fi

rsync -a --delete --chmod=D0755,F0644 --exclude=/dl/ dist-web/ "$HOST:$WEBROOT/"
rsync -a --chmod=D0755,F0644 dist-web/dl/ "$HOST:$WEBROOT/dl/"

echo "--- checks"
curl -fsS "https://$DOMAIN/info" | head -c 400; echo
curl -s -o /dev/null -w "tickets: %{http_code} (expect 402)\n" -X POST "https://$DOMAIN/v1/tickets?tier=S&egress=client"
curl -sI "https://$DOMAIN/app/" | grep -i cross-origin
ssh "$HOST" DOMAIN="$DOMAIN" sh -s <<'REMOTE'
# localtest.me resolves to ::1 and must be refused. $DOMAIN must be refused
# too once this host's address is in the [egress] deny list.
for h in localtest.me "$DOMAIN" example.com; do
  printf '%s: ' "$h"; runuser -u tlsnc -- /usr/local/bin/tlsnc-notary --config /etc/tlsnc/config.toml check-host "$h" 2>&1 | tail -1
done
printf 'layer 3 (must fail): '; runuser -u tlsnc -- curl -s -m 5 -o /dev/null http://127.0.0.1:80/ && echo "NOT BLOCKED" || echo blocked
REMOTE
