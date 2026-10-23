# emudhra-fix

Check and fix hosts and Docker containers that still trust the leaked eMudhra intermediate CA keys.

> **Unverified.** The advisory this is based on was not independently verified. Confirm the canary domain and version numbers against vendor or CA-store announcements before relying on them.

## Background

Some eMudhra intermediate CA private keys were reported leaked, some trivially weak. With them an attacker can forge TLS certificates for any domain and run a man-in-the-middle attack. Browsers ship updated blocklists, but servers and containers do not protect themselves: default TLS clients (curl, Python `requests`, Node, Go) don't check OCSP/CRL and don't enforce Certificate Transparency. Their only defense is an updated CA bundle.

Updating the host does **not** fix running containers. Each image carries its own CA store.

## Usage

One-liner, no clone needed (read the script first, it runs `sudo` for `host` and `docker-fix`):

```bash
curl -fsSL https://raw.githubusercontent.com/datmt/emudhra-fix/main/emudhra.sh | bash -s -- check
curl -fsSL https://raw.githubusercontent.com/datmt/emudhra-fix/main/emudhra.sh | bash -s -- docker-check
curl -fsSL https://raw.githubusercontent.com/datmt/emudhra-fix/main/emudhra.sh | bash -s -- host
```

Or from a clone:

```bash
./emudhra.sh check                       # canary test on this host
./emudhra.sh host                        # upgrade ca-certificates (pacman/apt/brew), re-check
./emudhra.sh docker-check                # check every container's trust stores (running or stopped); exit 2 if any vulnerable
./emudhra.sh docker-fix ~/proj/a ~/proj/b/stack.yaml  # rebuild --pull --no-cache, pull, recreate compose projects (dirs or files), re-check
./emudhra.sh java-truststore <container> [out]  # write the container's JDK cacerts without the root, to bind-mount back
```

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

Output per container: `SAFE`, `VULNERABLE` plus the stores that trust the root, or `NO-CA-STORE` (none found at known paths, e.g. distroless/scratch/Debian-slim without ca-certificates: TLS clients there either fail or bring their own store).

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

For ongoing updates, run `docker-fix` from a weekly cron or systemd timer, or use Renovate/Dependabot to bump base images.

## Mitigate without new images

When the host is patched (`./emudhra.sh check` says SAFE) but an image isn't, give the container the host's store instead of rebuilding. Add to each service, then `docker compose up -d`:

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

Re-run `docker-check` afterwards; it reads stores through the mounts.

## Dockerfile fixes

See [`Dockerfile.snippets`](Dockerfile.snippets): `ca-certificates` upgrade for Debian/Ubuntu and Alpine, `certifi>=2026.10.19` for Python, `--use-openssl-ca` for Node, JDK truststore cleanup for Java, current toolchain for Go.

## Files

- `emudhra.sh` — check/fix script
- `Dockerfile.snippets` — per-base-image fixes
