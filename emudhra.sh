#!/usr/bin/env bash
# eMudhra CA leak: check + fix host and docker.
# usage: ./emudhra.sh check|host|docker-check|docker-fix <compose-dir|file...>|java-truststore <container> [out]
# docker-check: OS bundle + cert dir, JDK cacerts, node built-in store. Not certifi or Go's embedded roots.
set -uo pipefail
CANARY=https://dv-g3b-emudhra.we-have-a-problem.com/

# Root the canary chains to (emSign ECC Root CA - G3). Distrusted by Debian ca-certificates
# 20250419+deb13u1, NSS 3.131.1, certifi 2026.10.19. Embedded so JDK/node stores can be
# searched for it, and so the check still works when the canary is down.
ROOT_FP=86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B
ROOT_PEM='-----BEGIN CERTIFICATE-----
MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG
EwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNo
bm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g
RzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJ
TjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9s
b2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0
WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xyS
fvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuB
zhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWB
CUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD
+JbNR6iC8hZVdyR+EhCVBCyj
-----END CERTIFICATE-----'
# 48 base64 chars of the root's public key, chosen to sit inside one line whether the PEM is
# wrapped at 64 (bundles), 72 (node's compiled-in store) or 76 columns
ROOT_KEY_B64=58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4P

OS_BUNDLES="/etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/pki/tls/certs/ca-bundle.crt"
# Go and OpenSSL's CApath also load every cert file in these dirs, not just the bundle
CERT_DIRS="/etc/ssl/certs /etc/pki/ca-trust/extracted/pem/directory-hash"
# copied out for the cert-dir search: the dirs above plus where their symlinks point
CERT_COPY="/etc/ssl/certs /etc/pki/ca-trust/extracted /usr/share/ca-certificates /usr/local/share/ca-certificates"
# Java ignores the OS store; its truststore is a separate binary file
JDK_CACERTS="/etc/pki/ca-trust/extracted/java/cacerts /etc/ssl/certs/java/cacerts /opt/java/openjdk/lib/security/cacerts /usr/lib/jvm/default-jvm/lib/security/cacerts"
NODE_BINS="/usr/local/bin/node /usr/bin/node"

# prints SAFE if TLS fails (cert rejected), VULNERABLE if request succeeds
probe() { # args: command prefix (e.g. "docker exec <id>" or empty)
  local out
  if out=$($@ curl -sS -I -m 10 "$CANARY" 2>&1); then echo VULNERABLE
  elif grep -qiE 'certificate|SSL|issuer|revoked' <<<"$out"; then echo SAFE
  else echo "UNKNOWN($(head -c 80 <<<"$out"))"; fi
}

wipe() { chmod -R u+w "$1" 2>/dev/null; rm -rf "$1"; }

hex() { od -An -v -tx1 "$1" | tr -d ' \n'; }

# container env var, empty if unset
cenv() { docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$1" | sed -n "s/^$2=//p"; }

# prints the trust stores in container $1 that trust the root, space separated; "none" if no store found
scan() {
  local id=$1 w=$tmp/w p d t l out found=0 hits=""
  wipe "$w"; mkdir -p "$w"
  # OS bundle: verify the canary chain like curl would (falls back to fingerprint if the canary is down).
  # -L: /etc/ssl/cert.pem and RHEL's ca-bundle.crt are symlinks
  for p in $OS_BUNDLES; do
    docker cp -L "$id:$p" "$w/b.crt" 2>/dev/null || continue
    found=1
    if [ -s "$tmp/chain.pem" ]; then
      # -no_check_time: the canary leaf expires May 2027; trust, not validity, is what's tested
      if out=$(openssl verify -no_check_time -CAfile "$w/b.crt" -untrusted "$tmp/chain.pem" "$tmp/c1.pem" 2>&1)
      then hits+=" os-bundle"
      elif ! grep -qE 'unable to get (local )?issuer certificate' <<<"$out"; then hits+=" os-bundle(verify-error)"; fi
    elif grep -qF "$ROOT_KEY_B64" "$w/b.crt"; then hits+=" os-bundle"; fi
    break
  done
  # cert dirs: copy them plus their link targets, repoint absolute links into the copy, then search
  for d in $CERT_COPY; do
    mkdir -p "$w/r${d%/*}"
    docker cp "$id:$d" - 2>/dev/null | tar -xf - -C "$w/r${d%/*}" 2>/dev/null
  done
  chmod -R u+w "$w/r" 2>/dev/null # RHEL ships these dirs read-only
  find "$w/r" -type l 2>/dev/null | while read -r l; do
    t=$(readlink "$l"); case $t in /*) ln -sfn "$w/r$t" "$l" ;; esac
  done
  for d in $CERT_DIRS; do
    [ -d "$w/r$d" ] || continue
    found=1
    grep -RqsF --exclude='ca-certificates.crt' --exclude-dir=java "$ROOT_KEY_B64" "$w/r$d" && { hits+=" os-certdir"; break; }
  done
  # JDK cacerts (JKS or PKCS12 both store certs as plain DER)
  t=$(cenv "$id" JAVA_HOME)
  for p in $JDK_CACERTS ${t:+$t/lib/security/cacerts}; do
    docker cp -L "$id:$p" "$w/cacerts" 2>/dev/null || continue
    found=1
    [[ $(hex "$w/cacerts") == *"$roothex"* ]] && { hits+=" jdk-cacerts"; break; }
  done
  # node's compiled-in roots; --use-openssl-ca replaces them with the OS store checked above
  if [[ $(cenv "$id" NODE_OPTIONS) != *--use-openssl-ca* ]]; then
    for p in $NODE_BINS; do
      docker cp -L "$id:$p" "$w/node" 2>/dev/null || continue
      found=1
      grep -qaF "$ROOT_KEY_B64" "$w/node" && hits+=" node-builtin"
      break
    done
  fi
  wipe "$w"
  [ $found = 1 ] || hits=" none"
  echo "${hits# }"
}

main() { case "${1:-}" in
check)
  echo "host: $(probe)"
  ;;
host)
  if   command -v pacman >/dev/null; then # CA data only: -Sy without -u skips the full upgrade (partial upgrade; review the dep list pacman shows)
  sudo pacman -Sy ca-certificates ca-certificates-mozilla
  elif command -v apt-get >/dev/null; then sudo apt-get update && sudo apt-get install -y --only-upgrade ca-certificates && sudo update-ca-certificates
  elif command -v brew >/dev/null;    then brew upgrade ca-certificates
  else echo "unknown pkg manager"; exit 1; fi
  main check
  ;;
docker-check)
  # no exec needed: copy each container's trust stores out and check them on the host
  tmp=$(mktemp -d); trap 'wipe "$tmp"' EXIT
  h=${CANARY#https://}; h=${h%/}
  openssl s_client -connect "$h:443" -servername "$h" -showcerts </dev/null 2>/dev/null \
    | awk -v d="$tmp" '/BEGIN CERT/{n++; w=1} w{print > d "/c" n ".pem"} /END CERT/{w=0}'
  cat "$tmp"/c*.pem > "$tmp/chain.pem" 2>/dev/null \
    || { rm -f "$tmp/chain.pem"; echo "canary chain fetch failed; checking OS bundles by root fingerprint only" >&2; }
  printf '%s\n' "$ROOT_PEM" > "$tmp/root.pem"
  [ "$(openssl x509 -in "$tmp/root.pem" -noout -fingerprint -sha256)" = "sha256 Fingerprint=$ROOT_FP" ] \
    || { echo "embedded root corrupted"; exit 1; }
  openssl x509 -in "$tmp/root.pem" -outform der -out "$tmp/root.der"
  roothex=$(hex "$tmp/root.der")
  printf '%-30s %-40s %-10s %-11s %s\n' NAME IMAGE STATE RESULT "TRUSTED BY"
  docker ps -a --format '{{.ID}} {{.Names}} {{.Image}} {{.State}}' | while read -r id name img state; do
    s=$(scan "$id")
    case $s in "") r=SAFE ;; none) r=NO-CA-STORE; s="" ;; *) r=VULNERABLE ;; esac
    printf '%-30s %-40s %-10s %-11s %s\n' "$name" "$img" "$state" "$r" "$s"
  done | tee "$tmp/out"
  if grep -q ' VULNERABLE ' "$tmp/out"; then
    echo
    echo "os-*: rebuild/pull, or mount the host's patched store (README: 'Mitigate without new images')."
    echo "jdk-cacerts: ./emudhra.sh java-truststore <container>. node-builtin: NODE_OPTIONS=--use-openssl-ca."
    exit 2
  fi
  ;;
docker-fix)
  # containers are immutable: rebuild/pull + recreate. Pass compose dirs or compose files.
  shift
  [ $# -gt 0 ] || { echo "give compose project dirs or files"; exit 1; }
  for t in "$@"; do
    f=(); d=$t
    [ -f "$t" ] && { d=$(dirname "$t"); f=(-f "$(cd "$d" && pwd)/$(basename "$t")"); }
    ( cd "$d" || exit
      docker compose ${f[@]+"${f[@]}"} build --pull --no-cache   # no-op for image-only services
      docker compose ${f[@]+"${f[@]}"} pull --ignore-buildable   # pull-only services
      docker compose ${f[@]+"${f[@]}"} up -d --force-recreate )
  done
  # still VULNERABLE after this = upstream hasn't shipped a fixed image for that tag (old/pinned tags never will)
  main docker-check
  ;;
java-truststore)
  # Java ignores the OS store. Writes a copy of the container's JDK truststore without the root,
  # to bind-mount back over the original (read-only). keytool comes from the host or the container's image.
  c=${2:?usage: emudhra.sh java-truststore <container> [out-file]}; out=${3:-./cacerts}
  src=""
  for p in $JDK_CACERTS $(t=$(cenv "$c" JAVA_HOME); [ -n "$t" ] && echo "$t/lib/security/cacerts"); do
    docker cp -L "$c:$p" "$out" 2>/dev/null && { src=$p; break; }
  done
  [ -n "$src" ] || { echo "no JDK cacerts found in $c"; exit 1; }
  chmod 644 "$out"
  od=$(cd "$(dirname "$out")" && pwd); of=$(basename "$out")
  if command -v keytool >/dev/null; then kt() { keytool "$@" -keystore "$od/$of" -storepass changeit; }
  else
    img=$(docker inspect -f '{{.Config.Image}}' "$c")
    kt() { docker run --rm --user "$(id -u):$(id -g)" --entrypoint keytool -v "$od:/w" "$img" "$@" -keystore "/w/$of" -storepass changeit; }
  fi
  a=$(kt -list | awk -v fp="$ROOT_FP" '/trustedCertEntry/{a=$0; sub(/, .*/, "", a)} index($0, fp){print a}')
  [ -n "$a" ] || { echo "$src in $c does not contain the root; nothing to do"; rm -f "$out"; exit 0; }
  kt -delete -alias "$a" || exit 1
  echo "removed '$a'. Add to the service's volumes, then recreate:"
  echo "      - $od/$of:$src:ro"
  ;;
*) echo "usage: emudhra.sh check|host|docker-check|docker-fix <compose-dir|file...>|java-truststore <container> [out]"; exit 1 ;;
esac
}
main "$@"
