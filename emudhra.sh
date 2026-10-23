#!/usr/bin/env bash
# eMudhra CA leak: check + fix host and docker.
# usage: ./emudhra.sh check|host|docker-check|docker-fix [compose-dir...]
# docker-check: OS CA bundle only; language bundles (certifi, node, go) need separate check
set -uo pipefail
CANARY=https://dv-g3b-emudhra.we-have-a-problem.com/

# prints SAFE if TLS fails (cert rejected), VULNERABLE if request succeeds
probe() { # args: command prefix (e.g. "docker exec <id>" or empty)
  local out
  if out=$($@ curl -sS -I -m 10 "$CANARY" 2>&1); then echo VULNERABLE
  elif grep -qiE 'certificate|SSL|issuer|revoked' <<<"$out"; then echo SAFE
  else echo "UNKNOWN($(head -c 80 <<<"$out"))"; fi
}

case "${1:-}" in
check)
  echo "host: $(probe)"
  ;;
host)
  if   command -v pacman >/dev/null; then sudo pacman -Syu --needed ca-certificates ca-certificates-mozilla
  elif command -v apt-get >/dev/null; then sudo apt-get update && sudo apt-get install -y --only-upgrade ca-certificates && sudo update-ca-certificates
  elif command -v brew >/dev/null;    then brew upgrade ca-certificates
  else echo "unknown pkg manager"; exit 1; fi
  "$0" check
  ;;
docker-check)
  # no exec needed: copy each container's CA bundle out, verify canary chain against it on host
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  h=${CANARY#https://}; h=${h%/}
  openssl s_client -connect "$h:443" -servername "$h" -showcerts </dev/null 2>/dev/null \
    | awk -v d="$tmp" '/BEGIN CERT/{n++; w=1} w{print > d "/c" n ".pem"} /END CERT/{w=0}'
  cat "$tmp"/c*.pem > "$tmp/chain.pem" 2>/dev/null || { echo "canary chain fetch failed"; exit 1; }
  docker ps -a --format '{{.ID}} {{.Names}} {{.Image}}' | while read -r id name img; do
    rm -f "$tmp/b.crt"; r=NO-BUNDLE
    for p in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/pki/tls/certs/ca-bundle.crt; do
      docker cp "$id:$p" "$tmp/b.crt" 2>/dev/null || continue
      if openssl verify -CAfile "$tmp/b.crt" -untrusted "$tmp/chain.pem" "$tmp/c1.pem" >/dev/null 2>&1
      then r=VULNERABLE; else r=SAFE; fi; break
    done
    printf '%-30s %-40s %s\n' "$name" "$img" "$r"
  done
  ;;
docker-fix)
  # containers are immutable: rebuild/pull + recreate. Pass compose dirs.
  shift
  [ $# -gt 0 ] || { echo "give compose project dirs"; exit 1; }
  for d in "$@"; do
    ( cd "$d" || exit
      docker compose build --pull --no-cache   # no-op for image-only services
      docker compose pull --ignore-buildable   # pull-only services
      docker compose up -d --force-recreate )
  done
  "$0" docker-check
  ;;
*) sed -n 2,3p "$0"; exit 1 ;;
esac
