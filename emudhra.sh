#!/usr/bin/env bash
# eMudhra CA leak: check + fix host and docker.
# usage: ./emudhra.sh check|host|docker-check [-q]|docker-fix <compose-dir|file...>|java-truststore <container> [out]
# docker-check: OS bundle + cert dir, JDK cacerts, node built-in store. Not certifi or Go's embedded roots.
# Output shows every file checked, where it comes from (image or host mount), the test and its raw result.
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
CERT_COPY="/etc/ssl/certs /etc/pki/tls /etc/pki/ca-trust/extracted /usr/share/ca-certificates /usr/local/share/ca-certificates"
# Java ignores the OS store; its truststore is a separate binary file
JDK_CACERTS="/etc/pki/ca-trust/extracted/java/cacerts /etc/ssl/certs/java/cacerts /opt/java/openjdk/lib/security/cacerts /usr/lib/jvm/default-jvm/lib/security/cacerts"
NODE_BINS="/usr/local/bin/node /usr/bin/node"

QUIET=0
say() { [ "$QUIET" = 1 ] || printf '%s\n' "$*"; }
run() { echo "+ $*"; "$@"; }

wipe() { chmod -R u+w "$1" 2>/dev/null; rm -rf "$1"; }

hex() { od -An -v -tx1 "$1" | tr -d ' \n'; }

# subject/issuer CN of a PEM file
cn() { openssl x509 -in "$1" -noout -"$2" 2>/dev/null | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p'; }

# true if file $1 trusts the root. OpenSSL "TRUSTED CERTIFICATE" bundles (RHEL ca-bundle.trust.crt)
# can list it with serverAuth rejected, which is an explicit distrust, not trust
trusts_root() {
  grep -qF "$ROOT_KEY_B64" "$1" || return 1
  grep -q 'BEGIN TRUSTED CERTIFICATE' "$1" || return 0
  ! awk -v k="$ROOT_KEY_B64" '/BEGIN TRUSTED CERT/{c=""} {c=c $0 "\n"} /END TRUSTED CERT/{if (index(c, k)) printf "%s", c}' "$1" \
    | openssl x509 -trustout -noout -text 2>/dev/null | grep -A1 'Rejected Uses' | grep -q 'TLS Web Server Authentication'
}

# container env var, empty if unset
cenv() { docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$1" | sed -n "s/^$2=//p"; }

# installed CA package version on this host
pkgver() {
  dpkg-query -W -f='ca-certificates ${Version}' ca-certificates 2>/dev/null ||
  pacman -Q ca-certificates-mozilla 2>/dev/null || rpm -q ca-certificates 2>/dev/null ||
  apk info -v ca-certificates 2>/dev/null | head -1 || brew list --versions ca-certificates 2>/dev/null ||
  echo "unknown (no dpkg/pacman/rpm/apk/brew record)"
}

# copy file $2 out of container $1 to $3, following symlinks one hop at a time so the chain
# can be shown. Sets VIA ("a -> b") and FINAL (resolved path). Fails if the path doesn't exist.
fetch() {
  local id=$1 p=$2 out=$3 t i=0
  VIA=$p; FINAL=$p; rm -rf "$out"
  while docker cp "$id:$p" "$out" 2>/dev/null; do
    [ -L "$out" ] || { FINAL=$p; return 0; }
    t=$(readlink "$out"); rm -f "$out"
    case $t in /*) p=$t ;; *) p=${p%/*}/$t ;; esac
    VIA+=" -> $t"; i=$((i+1)); [ $i -lt 8 ] || return 1
  done
  return 1
}

# where container path $1 really comes from: the image, or a mount (shows host source)
src_of() {
  local p=$1 dst src rw best="" bl=0
  while IFS='|' read -r dst src rw; do
    [ -n "$dst" ] || continue
    case $p in "$dst"|"$dst"/*)
      [ ${#dst} -gt $bl ] || continue
      bl=${#dst}; best="HOST MOUNT $src${p#"$dst"} ($([ "$rw" = true ] && echo rw || echo ro))" ;;
    esac
  done <<<"$MOUNTS"
  echo "${best:-image layer}"
}

# prints SAFE if TLS fails (cert rejected), VULNERABLE if request succeeds; raw curl output in OUT
probe() { # args: command prefix (e.g. "docker exec <id>" or empty)
  if OUT=$($@ curl -v -sS -I -m 10 "$CANARY" 2>&1); then echo VULNERABLE
  elif grep -qiE 'certificate|SSL|issuer|revoked' <<<"$OUT"; then echo SAFE
  else echo "UNKNOWN($(grep -v '^[*<>{}]' <<<"$OUT" | head -c 80))"; fi
}

# checks every trust store in container $1 and explains each step; sets HITS (stores trusting
# the root, space separated), NSTORES (stores found)
scan() {
  local id=$1 name=$2 img=$3 state=$4 w=$tmp/w p d t f n h k m out rc
  HITS=""; NSTORES=0
  wipe "$w"; mkdir -p "$w"
  MOUNTS=$(docker inspect -f '{{range .Mounts}}{{.Destination}}|{{.Source}}|{{.RW}}{{"\n"}}{{end}}' "$id")
  t=$(docker inspect -f '{{.Image}}' "$id")
  say ""
  say "━━ $name"
  t=${t#sha256:}
  say "   image    : $img  (id ${t:0:12}, built $(docker image inspect -f '{{.Created}}' "$t" 2>/dev/null | cut -c1-10))"
  say "   state    : $state"
  fetch "$id" /etc/os-release "$w/os" && say "   os       : $(sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$w/os")"

  say "   [os-bundle]    used by curl, wget, PHP, Ruby, Python ssl, OpenSSL CAfile"
  for p in $OS_BUNDLES; do fetch "$id" "$p" "$w/b.crt" && break; done
  if [ -f "$w/b.crt" ]; then
    NSTORES=$((NSTORES+1))
    say "      file    : $VIA"
    say "      source  : $(src_of "$FINAL")"
    say "      content : $(grep -c 'BEGIN CERTIFICATE' "$w/b.crt") certificates"
    if [ -s "$tmp/chain.pem" ]; then
      # -no_check_time: the canary leaf expires May 2027; trust, not validity, is what's tested
      say "      test    : openssl verify -no_check_time -CAfile <this file> -untrusted <canary chain> <canary leaf>"
      out=$(openssl verify -no_check_time -show_chain -CAfile "$w/b.crt" -untrusted "$tmp/chain.pem" "$tmp/c1.pem" 2>&1); rc=$?
      if [ $rc = 0 ]; then
        say "      openssl : OK, chain ends at trusted '$(grep '^depth=' <<<"$out" | tail -1 | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')'"
        say "      => TRUSTS ROOT"; HITS+=" os-bundle"
      else
        say "      openssl : $(grep -m1 '^error [0-9]' <<<"$out")"
        if grep -qE 'unable to get (local )?issuer certificate' <<<"$out"; then say "      => clean (chain does not reach a trusted root)"
        else say "      => UNEXPECTED verify error, counted as vulnerable"; HITS+=" os-bundle(verify-error)"; fi
      fi
    else
      say "      test    : search for the root's public key (canary unreachable, chain test skipped)"
      if grep -qF "$ROOT_KEY_B64" "$w/b.crt"; then say "      => TRUSTS ROOT"; HITS+=" os-bundle"; else say "      => clean"; fi
    fi
  else say "      not present (looked for $OS_BUNDLES)"; fi

  say "   [os-certdir]   used by Go (loads every file in the dir), OpenSSL CApath"
  # copy the dirs plus their link targets, repoint absolute links into the copy, then search
  for d in $CERT_COPY; do
    mkdir -p "$w/r${d%/*}"
    docker cp "$id:$d" - 2>/dev/null | tar -xf - -C "$w/r${d%/*}" 2>/dev/null
  done
  chmod -R u+w "$w/r" 2>/dev/null # RHEL ships these dirs read-only
  find "$w/r" -type l 2>/dev/null | while read -r f; do
    t=$(readlink "$f"); case $t in /*) ln -sfn "$w/r$t" "$f" ;; esac
  done
  m=0
  for d in $CERT_DIRS; do
    [ -e "$w/r$d" ] || continue
    NSTORES=$((NSTORES+1)); m=1
    n=$(find -L "$w/r$d/" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')
    t=$(find "$w/r$d/" -maxdepth 1 -type l ! -exec test -e {} \; -print 2>/dev/null | wc -l | tr -d ' ')
    say "      dir     : $d$([ -L "$w/r$d" ] && echo " -> $(readlink "$w/r$d" | sed "s|^$w/r||")")"
    say "      source  : $(src_of "$d")"
    say "      content : $n readable files$([ "$t" != 0 ] && echo ", $t dangling links (target not in container)")"
    say "      test    : search each file for the root's public key (bundle file and java/ excluded, covered elsewhere)"
    k=0
    while read -r f; do
      [ -n "$f" ] || continue
      t=$(readlink -f "$f" | sed "s|^$w/r||")
      n="${f#"$w/r$d/"}$([ "$t" != "$d/${f#"$w/r$d/"}" ] && echo " -> $t") [$(src_of "$t")]"
      if trusts_root "$f"; then say "      match   : $n"; k=1
      else say "      listed  : $n, but with TLS server auth REJECTED (explicit distrust)"; fi
    done <<<"$(grep -RlsF --exclude='ca-certificates.crt' --exclude-dir=java "$ROOT_KEY_B64" "$w/r$d/")"
    if [ $k = 1 ]; then say "      => TRUSTS ROOT"; HITS+=" os-certdir"; break
    else say "      => clean (no file trusts the root)"; fi
  done
  [ $m = 1 ] || say "      not present (looked for $CERT_DIRS)"

  say "   [jdk-cacerts]  used by Java (ignores the OS store)"
  k=$(cenv "$id" JAVA_HOME); m=0
  for p in $JDK_CACERTS ${k:+$k/lib/security/cacerts}; do
    fetch "$id" "$p" "$w/cacerts" || continue
    NSTORES=$((NSTORES+1)); m=1
    h=$(hex "$w/cacerts")
    case $h in feedfeed*) t=JKS ;; cececece*) t=JCEKS ;; 30*) t=PKCS12 ;; *) t="unknown format" ;; esac
    say "      file    : $VIA  ($t, $(wc -c <"$w/cacerts" | tr -d ' ') bytes)"
    say "      source  : $(src_of "$FINAL")"
    say "      test    : search for the root certificate's DER bytes"
    if [[ $h == *"$roothex"* ]]; then
      t=${h%%"$roothex"*}
      say "      match   : at byte offset $(( ${#t} / 2 ))"; say "      => TRUSTS ROOT"; HITS+=" jdk-cacerts"; break
    else say "      => clean"; fi
  done
  [ $m = 1 ] || say "      not present (looked for $JDK_CACERTS${k:+ \$JAVA_HOME/lib/security/cacerts})"

  say "   [node-builtin] used by Node.js (roots compiled into the binary)"
  k=$(cenv "$id" NODE_OPTIONS); m=0
  for p in $NODE_BINS; do
    fetch "$id" "$p" "$w/node" || continue
    NSTORES=$((NSTORES+1)); m=1
    say "      binary  : $VIA  ($(( $(wc -c <"$w/node") / 1048576 )) MB)"
    say "      env     : NODE_OPTIONS=${k:-<unset>}"
    if [[ $k == *--use-openssl-ca* ]]; then
      say "      => not used: --use-openssl-ca makes node load the OS store (checked above)"
    else
      say "      test    : search the binary for the root's public key"
      t=$(grep -aobF "$ROOT_KEY_B64" "$w/node" | head -1 | cut -d: -f1)
      if [ -n "$t" ]; then say "      match   : at byte offset $t"; say "      => TRUSTS ROOT"; HITS+=" node-builtin"
      else say "      => clean"; fi
    fi
    break
  done
  [ $m = 1 ] || say "      not present (looked for $NODE_BINS)"
  wipe "$w"
  HITS=${HITS# }
  if [ -n "$HITS" ]; then say "   RESULT   : VULNERABLE, trusted by: $HITS"
  elif [ $NSTORES = 0 ]; then say "   RESULT   : NO-CA-STORE, no trust store at any known path; TLS clients here fail or bring their own (not checked)"
  else say "   RESULT   : SAFE, $NSTORES store(s) checked, none trust the root"; fi
}

main() { case "${1:-}" in
check)
  r=$(probe; printf '\n%s' "$OUT")
  OUT=${r#*$'\n'}; r=${r%%$'\n'*}
  echo "host     : $(hostname)"
  echo "package  : $(pkgver)"
  echo "curl     : $(curl --version | head -1 | cut -d' ' -f1-2,5)"
  echo "CA used  : $(grep -E '^\* +CA(file|path):' <<<"$OUT" | sed 's/^\* *//' | tr '\n' ' ')"
  echo "request  : curl -I $CANARY"
  echo "response : $(grep -m1 -E 'SSL certificate problem|^curl: |^< HTTP/' <<<"$OUT" | sed 's/^[<*] //')"
  echo "result   : $r"
  ;;
host)
  echo "before   : $(pkgver)"
  if   command -v pacman >/dev/null; then # CA data only: -Sy without -u skips the full upgrade (partial upgrade; review the dep list pacman shows)
  run sudo pacman -Sy ca-certificates ca-certificates-mozilla
  elif command -v apt-get >/dev/null; then run sudo apt-get update && run sudo apt-get install -y --only-upgrade ca-certificates && run sudo update-ca-certificates
  elif command -v brew >/dev/null;    then run brew upgrade ca-certificates
  else echo "unknown pkg manager"; exit 1; fi
  echo "after    : $(pkgver)"
  main check
  ;;
docker-check)
  # no exec needed: copy each container's trust stores out and check them on the host
  [ "${2:-}" = -q ] && QUIET=1
  tmp=$(mktemp -d); trap 'wipe "$tmp"' EXIT
  printf '%s\n' "$ROOT_PEM" > "$tmp/root.pem"
  [ "$(openssl x509 -in "$tmp/root.pem" -noout -fingerprint -sha256)" = "sha256 Fingerprint=$ROOT_FP" ] \
    || { echo "embedded root corrupted"; exit 1; }
  openssl x509 -in "$tmp/root.pem" -outform der -out "$tmp/root.der"
  roothex=$(hex "$tmp/root.der")
  h=${CANARY#https://}; h=${h%/}
  openssl s_client -connect "$h:443" -servername "$h" -showcerts </dev/null 2>/dev/null \
    | awk -v d="$tmp" '/BEGIN CERT/{n++; w=1} w{print > d "/c" n ".pem"} /END CERT/{w=0}'
  cat "$tmp"/c*.pem > "$tmp/chain.pem" 2>/dev/null || rm -f "$tmp/chain.pem"

  say "eMudhra CA check, $(date -u '+%Y-%m-%d %H:%M UTC') on $(hostname)"
  say "looking for : emSign ECC Root CA - G3 (eMudhra Technologies), sha256 $ROOT_FP"
  say "              (embedded in this script, fingerprint verified at start)"
  if [ -s "$tmp/chain.pem" ]; then
    say "canary      : $h:443, served $(ls "$tmp"/c[0-9]*.pem | wc -l | tr -d ' ') certs:"
    for f in "$tmp"/c[0-9]*.pem; do say "                $(cn "$f" subject)   <- issued by $(cn "$f" issuer)"; done
  else
    say "canary      : $h:443 UNREACHABLE; OS bundles are checked by searching for the root instead"
  fi
  say "method      : each container's trust stores are copied out with 'docker cp' (no exec, works on"
  say "              stopped containers) and checked here. Nothing is changed. A store marked"
  say "              HOST MOUNT is this host's file, so its result depends on this host being patched."
  say "tools       : $(openssl version | cut -d' ' -f1-2), Docker $(docker version -f '{{.Server.Version}}' 2>/dev/null)"
  say "this host   : $(pkgver)"
  for p in $OS_BUNDLES; do
    [ -f "$p" ] || continue
    if grep -qF "$ROOT_KEY_B64" "$p"; then say "              $p TRUSTS the root"; else say "              $p does not trust the root"; fi
    break
  done

  docker ps -a --format '{{.ID}} {{.Names}} {{.Image}} {{.State}}' > "$tmp/ps"
  while read -r -u 3 id name img state; do
    scan "$id" "$name" "$img" "$state"
    case $HITS in "") [ $NSTORES = 0 ] && r=NO-CA-STORE || r=SAFE ;; *) r=VULNERABLE ;; esac
    printf '%-30s %-40s %-10s %-11s %s\n' "$name" "$img" "$state" "$r" "$HITS" >> "$tmp/out"
  done 3< "$tmp/ps"

  say ""
  say "━━ summary"
  printf '%-30s %-40s %-10s %-11s %s\n' NAME IMAGE STATE RESULT "TRUSTED BY"
  cat "$tmp/out" 2>/dev/null
  say ""
  say "not checked : Python certifi bundles, Go binaries with embedded roots, Rust webpki-roots, app-specific"
  say "              truststores. A store that trusts the root only matters if something in that container"
  say "              makes outbound TLS with it."
  if grep -q ' VULNERABLE ' "$tmp/out" 2>/dev/null; then
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
    echo "== $t"
    ( cd "$d" || exit
      run docker compose ${f[@]+"${f[@]}"} build --pull --no-cache   # no-op for image-only services
      run docker compose ${f[@]+"${f[@]}"} pull --ignore-buildable   # pull-only services
      run docker compose ${f[@]+"${f[@]}"} up -d --force-recreate )
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
    echo "looking  : $c:$p"
    docker cp -L "$c:$p" "$out" 2>/dev/null && { src=$p; break; }
  done
  [ -n "$src" ] || { echo "no JDK cacerts found in $c"; exit 1; }
  chmod 644 "$out"
  echo "copied   : $c:$src -> $out"
  od=$(cd "$(dirname "$out")" && pwd); of=$(basename "$out")
  if command -v keytool >/dev/null; then
    echo "keytool  : host ($(command -v keytool))"
    kt() { keytool "$@" -keystore "$od/$of" -storepass changeit; }
  else
    img=$(docker inspect -f '{{.Config.Image}}' "$c")
    echo "keytool  : from image $img (no keytool on host)"
    kt() { docker run --rm --user "$(id -u):$(id -g)" --entrypoint keytool -v "$od:/w" "$img" "$@" -keystore "/w/$of" -storepass changeit; }
  fi
  echo "searching: alias with SHA-256 $ROOT_FP"
  a=$(kt -list | awk -v fp="$ROOT_FP" '/trustedCertEntry/{a=$0; sub(/, .*/, "", a)} index($0, fp){print a}')
  [ -n "$a" ] || { echo "result   : $src in $c does not contain the root; nothing to do"; rm -f "$out"; exit 0; }
  echo "found    : alias '$a'"
  kt -delete -alias "$a" || exit 1
  echo "removed  : '$a' ($(kt -list | grep -c trustedCertEntry) entries left)"
  echo "Add to the service's volumes, then recreate:"
  echo "      - $od/$of:$src:ro"
  ;;
*) echo "usage: emudhra.sh check|host|docker-check [-q]|docker-fix <compose-dir|file...>|java-truststore <container> [out]"; exit 1 ;;
esac
}
main "$@"
