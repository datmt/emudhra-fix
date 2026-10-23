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
./emudhra.sh docker-check                # canary test inside every running container
./emudhra.sh docker-fix ~/proj/a ~/proj/b  # rebuild --pull --no-cache, pull, recreate compose projects, re-check
```

### Canary

```bash
curl -I https://dv-g3b-emudhra.we-have-a-problem.com/
```

- `HTTP/1.1 200 OK` — **vulnerable**, the leaked key is still trusted.
- TLS error (`unable to get local issuer certificate`, `certificate revoked`) — **safe**.

`docker-check` needs no `curl` in the image. It fetches the canary's cert chain on the host, `docker cp`s each container's CA bundle (running or stopped), and runs `openssl verify` against it. Output is `SAFE`, `VULNERABLE` (bundle trusts the canary chain) or `NO-BUNDLE` (no bundle at a known path, e.g. distroless/scratch/Debian-slim without ca-certificates).

Limits: checks the OS bundle only, not `certifi`, Node's built-in store or Go's embedded roots. If the upstream fix is a revocation/distrust of the intermediate rather than a root removal, a stale-looking bundle can't be told apart from a patched one by this test; treat the host `check` (real `curl`) as the reference.

## Can Docker be automated?

Partly. Containers can't be patched in place, so the fix is rebuild or pull, then recreate.

| Case | Automated? |
|------|-----------|
| Compose projects (build or pull) | Yes, `docker-fix` |
| Plain `docker run` containers | No, recreate by hand |
| Python (`certifi`), Node, Go bundles | No, change the Dockerfile (see `Dockerfile.snippets`) |
| Upstream images | Only after maintainers ship the new CA package |

For ongoing updates, run `docker-fix` from a weekly cron or systemd timer, or use Renovate/Dependabot to bump base images.

## Dockerfile fixes

See [`Dockerfile.snippets`](Dockerfile.snippets): `ca-certificates` upgrade for Debian/Ubuntu and Alpine, `certifi>=2026.10.19` for Python, `--use-openssl-ca` for Node, current toolchain for Go.

## Files

- `emudhra.sh` — check/fix script
- `Dockerfile.snippets` — per-base-image fixes
