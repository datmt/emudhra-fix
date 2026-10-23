# emudhra-fix

Check and fix hosts and Docker containers that still trust the leaked eMudhra intermediate CA keys.

> Based on the [oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/10/20/1) and Debian's `ca-certificates 20250419+deb13u1` (blocklists emSign ECC Root CA - G3). The canary domain and other version numbers come from third-party reporting; confirm them against vendor or CA-store announcements before relying on them.

## Background

Some eMudhra intermediate CA private keys were reported leaked, some trivially weak. With them an attacker can forge TLS certificates for any domain and run a man-in-the-middle attack. Browsers ship updated blocklists, but servers and containers do not protect themselves: default TLS clients (curl, Python `requests`, Node, Go) don't check OCSP/CRL and don't enforce Certificate Transparency. Their only defense is an updated CA bundle.

Updating the host does **not** fix running containers. Each image carries its own CA store.

## Usage

One-liner, no clone needed (read the script first: `host` runs `sudo`, `docker-fix` recreates containers):

```bash
curl -fsSL https://raw.githubusercontent.com/datmt/emudhra-fix/main/emudhra.sh | bash -s -- check
curl -fsSL https://raw.githubusercontent.com/datmt/emudhra-fix/main/emudhra.sh | bash -s -- docker-check
curl -fsSL https://raw.githubusercontent.com/datmt/emudhra-fix/main/emudhra.sh | bash -s -- docker-check -q
curl -fsSL https://raw.githubusercontent.com/datmt/emudhra-fix/main/emudhra.sh | bash -s -- host
```

Or from a clone:

```bash
./emudhra.sh check                       # canary test on this host
./emudhra.sh host                        # upgrade ca-certificates (apt/pacman/brew only), re-check
./emudhra.sh docker-check                # check every container's trust stores (running or stopped), with full evidence; exit 2 if any vulnerable
./emudhra.sh docker-check -q             # summary table only (cron)
./emudhra.sh docker-fix ~/proj/a ~/proj/b/stack.yaml  # rebuild --pull --no-cache, pull, recreate compose projects (dirs or files), re-check
./emudhra.sh java-truststore <container> [out]  # write the container's JDK cacerts without the root, to bind-mount back
```

`check`, `docker-check` and `java-truststore` change nothing. `host` upgrades the CA package; `docker-fix` rebuilds, pulls and recreates the compose projects you name.

### Requirements

- bash (3.2+, so macOS works), `openssl` 1.1+, `tar`, `od`, `grep`; `curl` for `check`.
- Docker CLI with access to the daemon (`docker` group or root) for the `docker-*` commands.
- `keytool` for `java-truststore`: from the host if installed, otherwise from the container's own image.

`docker-check` works on any Docker host, patched or not: the root is embedded in the script and the canary chain is fetched without verifying it, so the host's own CA store plays no part in the result. Only the [mount mitigation](#mitigate-without-new-images) depends on the host.

`host` handles apt, pacman and brew. Elsewhere, upgrade by hand and re-run `check`:

```bash
sudo dnf upgrade ca-certificates          # RHEL/Fedora
sudo apk add --upgrade ca-certificates    # Alpine
sudo zypper update ca-certificates        # SUSE
```

The upgrade only helps once your distro has shipped the distrust; `check` tells you whether it has.

### Exit codes

`docker-check`: `0` nothing vulnerable, `2` at least one container trusts the root, `1` error. `docker-fix` returns `docker-check`'s code after recreating.

### Canary

```bash
curl -I https://dv-g3b-emudhra.we-have-a-problem.com/
```

- `HTTP/1.1 200 OK` — **vulnerable**, the leaked key is still trusted.
- TLS error (`unable to get local issuer certificate`, `certificate revoked`) — **safe**.

`docker-check` needs no `curl` or `docker exec`. It `docker cp`s each container's trust stores to the host and checks every one, because a client only uses one of them and a patched bundle alone doesn't help the others:

| Store | Used by | Check |
|-------|---------|-------|
| `os-bundle` (`/etc/ssl/certs/ca-certificates.crt`, `/etc/ssl/cert.pem`, `/etc/pki/tls/certs/ca-bundle.crt`) | curl, OpenSSL CAfile, PHP, Ruby | `openssl verify` of the canary chain against it |
| `os-certdir` (`/etc/ssl/certs/*`, RHEL `directory-hash`) | **Go** (loads every file in the dir, not just the bundle), OpenSSL CApath | search for the root |
| `jdk-cacerts` | Java (ignores the OS store) | search for the root's DER |
| `node-builtin` | Node (compiled-in roots), unless `NODE_OPTIONS=--use-openssl-ca` | search the `node` binary for the root |

The root the canary chains to, emSign ECC Root CA - G3 (SHA-256 `86:A1:EC:BA:…:6B:BE:6B`), is embedded in the script, so the root searches work without the canary. If the canary is unreachable the OS bundle is checked by fingerprint too. `verify` runs with `-no_check_time`, so the result doesn't flip to SAFE when the canary's leaf expires.

For every container the report shows each store it looked at: the file path and symlink chain, whether the file comes from the **image layer** or a **HOST MOUNT** (so a SAFE that depends on the host being patched is visible), certificate/file counts, the exact test, the raw `openssl` result or match location, and the verdict. Stores not present list the paths that were tried. RHEL's OpenSSL trust bundle can list the root with TLS server auth rejected; that's reported as explicit distrust, not a match. The header shows the root being searched for, the canary chain as served, tool versions, and this host's CA package. Example:

```
━━ keycloak
   image    : quay.io/keycloak/keycloak:26.6.0  (id 102b1fee6152, built 2026-04-08)
   [os-bundle]    used by curl, wget, PHP, Ruby, Python ssl, OpenSSL CAfile
      file    : /etc/ssl/cert.pem -> /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
      source  : HOST MOUNT /srv/keycloak/ca-trust/extracted/pem/tls-ca-bundle.pem (ro)
      content : 145 certificates
      test    : openssl verify -no_check_time -CAfile <this file> -untrusted <canary chain> <canary leaf>
      openssl : error 20 at 2 depth lookup: unable to get local issuer certificate
      => clean (chain does not reach a trusted root)
   ...
   RESULT   : SAFE, 4 store(s) checked, none trust the root
```

On a terminal the report is coloured: red for anything that trusts the root, green for clean stores and SAFE, yellow for host mounts and `NO-CA-STORE`. Piped or redirected output (cron, logs) stays plain; `NO_COLOR=1` turns colour off.

Verdict per container: `SAFE`, `VULNERABLE` plus the stores that trust the root, or `NO-CA-STORE` (none found at known paths, e.g. distroless/scratch/Debian-slim without ca-certificates: TLS clients there either fail or bring their own store).

Limits: no Python `certifi` (path varies per install) and no Go binaries with embedded roots. If the upstream fix is a revocation/distrust of the intermediate rather than a root removal, a stale-looking bundle can't be told apart from a patched one by this test; treat the host `check` (real `curl`) as the reference.

## Can Docker be automated?

Partly. Containers can't be patched in place, so the fix is rebuild or pull, then recreate.

| Case | Automated? |
|------|-----------|
| Compose projects (build or pull) | Yes, `docker-fix` |
| Plain `docker run` containers | No, recreate by hand |
| Python (`certifi`), Node, Go bundles | No, change the Dockerfile (see `Dockerfile.snippets`) |
| Upstream images | Only after maintainers ship the new CA package. Old or pinned tags (`grafana:10.4.3`, `mongo:5.0`, ...) are never rebuilt, so `pull` changes nothing; see below |
| Java truststore | Half: `java-truststore` writes the cleaned file, you add the mount |
| RHEL/UBI images | No, see [RHEL/UBI images](#rhelubi-images) |

For ongoing updates, run `docker-fix` from a weekly cron or systemd timer, or use Renovate/Dependabot to bump base images.

## Mitigate without new images

When the host is patched but an image isn't, give the container the host's store instead of rebuilding. Two preconditions:

1. **The host is patched.** `./emudhra.sh check` says SAFE. Otherwise the mount hands every container the host's vulnerable store, and they'll report VULNERABLE with `source: HOST MOUNT`.
2. **The host has the Debian/Ubuntu layout**: `/etc/ssl/certs/ca-certificates.crt` plus per-cert links into `/usr/share/ca-certificates`. Alpine hosts match too. On a RHEL/Fedora host `/etc/ssl/certs` holds only `ca-bundle.crt` links, so Debian/Alpine containers would lose `ca-certificates.crt` and **all TLS breaks**. Arch links into `/etc/ca-certificates/extracted`, which would need mounting as well. Docker Desktop on macOS: not applicable, the paths are the Linux VM's.

Add to each service, then `docker compose up -d`:

```yaml
    volumes:
      - /etc/ssl/certs:/etc/ssl/certs:ro
      - /usr/share/ca-certificates:/usr/share/ca-certificates:ro   # Debian/Ubuntu host: the cert dir symlinks into here
```

- Mount the **directories**, not just `ca-certificates.crt`. Go reads every file in `/etc/ssl/certs`, so a fixed bundle next to a stale `emSign_ECC_Root_CA_-_G3.pem` is still vulnerable. A single-file bind mount also pins the file's inode, so it goes stale after the next host `update-ca-certificates`; a directory mount doesn't.
- Covers Debian/Ubuntu/Alpine-based images (same paths). Not RHEL/UBI images, whose store is under `/etc/pki`.
- It hides whatever the image had in `/etc/ssl/certs`. Check for private CAs first, and note Debian/Ubuntu Java images keep their truststore at `/etc/ssl/certs/java/cacerts`, which this mount removes (use `java-truststore` and mount that file somewhere Java looks, or skip the dir mount for that service).
- Java: `./emudhra.sh java-truststore <container> ./truststore/cacerts`, then mount the printed path read-only.
- Node: add `NODE_OPTIONS=--use-openssl-ca` so Node uses the mounted OS store instead of its compiled-in roots (Node 18 is EOL and won't get new roots).

Re-run `docker-check` afterwards; it reads stores through the mounts and marks them `HOST MOUNT`.

### RHEL/UBI images

These keep everything under `/etc/pki/ca-trust/extracted` (PEM bundles, `directory-hash`, the OpenSSL trust bundle, Java `cacerts`), all generated by `update-ca-trust`. Regenerate the whole tree with the root blocklisted and mount it over the original. Minimal images (e.g. Keycloak's) lack `p11-kit`, so run the tool in full UBI:

```bash
mkdir -p ca-trust/blocklist ca-trust/extracted
# the root, taken from the script (fingerprint 86:A1:EC:BA:...:6B:BE:6B)
sed -n "/^ROOT_PEM='/,/END CERTIFICATE/{s/^ROOT_PEM='//;s/'\$//;p;}" emudhra.sh > ca-trust/blocklist/emSign_ECC_Root_CA_-_G3.pem
openssl x509 -in ca-trust/blocklist/emSign_ECC_Root_CA_-_G3.pem -noout -fingerprint -sha256
docker run --rm --user 0 --entrypoint sh \
  -v ./ca-trust/blocklist:/etc/pki/ca-trust/source/blocklist:ro -v ./ca-trust/extracted:/out \
  registry.access.redhat.com/ubi9/ubi-minimal:latest \
  -c 'update-ca-trust extract && cp -a /etc/pki/ca-trust/extracted/. /out/ && chown -R 1000:1000 /out'
```

```yaml
    volumes:
      - ./ca-trust/extracted:/etc/pki/ca-trust/extracted:ro
```

This also covers Java, so `java-truststore` isn't needed. The root stays listed in `openssl/ca-bundle.trust.crt` with all uses rejected (explicit distrust; `docker-check` reports it as such). Set `chown` to the container's user. It's a snapshot: re-run after upgrading the image so newer roots come along.

## Dockerfile fixes

See [`Dockerfile.snippets`](Dockerfile.snippets): `ca-certificates` upgrade for Debian/Ubuntu and Alpine, `certifi>=2026.10.19` for Python, `--use-openssl-ca` for Node, JDK truststore cleanup for Java, current toolchain for Go.

## Files

- `emudhra.sh` — check/fix script
- `Dockerfile.snippets` — per-base-image fixes
