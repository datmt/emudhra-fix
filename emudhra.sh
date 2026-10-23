#!/usr/bin/env bash
# eMudhra CA leak: check + fix host and docker.
# usage: ./emudhra.sh check|host|docker-check|docker-fix [compose-dir...]
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
  # curl missing in image => UNKNOWN; check those by hand / via language runtime
  docker ps --format '{{.ID}} {{.Names}} {{.Image}}' | while read -r id name img; do
    printf '%-30s %-40s %s\n' "$name" "$img" "$(probe docker exec "$id")"
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
