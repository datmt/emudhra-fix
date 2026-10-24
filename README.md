# emudhra-fix

> Also in this repo: [`brotli-cve-check.sh`](#brotli-cve-check-ghsa-9v8h-qqgm-4m35--cve-2026-111497), a scanner for the Brotli decoder CVE-2026-111497 on hosts, containers, images and Kubernetes.

Check and fix hosts, Docker containers and Kubernetes pods that still trust the leaked eMudhra intermediate CA keys.

> Based on the [oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/10/20/1) and Debian's `ca-certificates 20250419+deb13u1` (blocklists emSign ECC Root CA - G3). The canary domain and other version numbers come from third-party reporting; confirm them against vendor or CA-store announcements before relying on them.

> **Disclaimer:** Provided as is, without warranty. Not affiliated with eMudhra or any vendor. `check`, `docker-check`, `image-check`, `k8s-check` and `java-truststore` only read; `host` upgrades packages and `docker-fix` rebuilds and recreates containers. Read the script and try it on a non-production machine first, and take your own backups. You are responsible for what you run.

![docker-check flags running containers that still trust the root](docs/docker-check.png)

After the fix, Java rejects a certificate chained to the root (canary domain):

![JShell: PKIX path building failed after cleaning the truststore](docs/java-rejected.png)

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
curl -fsSL https://raw.githubusercontent.com/datmt/emudhra-fix/main/emudhra.sh | bash -s -- k8s-check -q
```

Or from a clone:

```bash
./emudhra.sh check                       # canary test on this host
./emudhra.sh host                        # upgrade ca-certificates (apt/pacman/brew only), re-check
./emudhra.sh docker-check                # check every container's trust stores (running or stopped), with full evidence; exit 2 if any vulnerable
./emudhra.sh docker-check -q             # summary table only (cron)
./emudhra.sh docker-fix ~/proj/a ~/proj/b/stack.yaml  # rebuild --pull --no-cache, pull, recreate compose projects (dirs or files), re-check
./emudhra.sh java-truststore <container> [out]  # write the container's JDK cacerts without the root, to bind-mount back
./emudhra.sh image-check [-q] <image...>  # same checks on images (pulled if not local, never run)
./emudhra.sh k8s-check [-q]              # every running pod's image, plus pods whose spec overrides trust
```

`check`, `docker-check`, `image-check`, `k8s-check` and `java-truststore` change nothing on the host or cluster (`image-check`/`k8s-check` pull images and remove them again). `host` upgrades the CA package; `docker-fix` rebuilds, pulls and recreates the compose projects you name.

### Requirements

- bash (3.2+, so macOS works), `openssl` 1.1+, `tar`, `od`, `grep`; `curl` for `check`.
- Docker CLI with access to the daemon (`docker` group or root) for the `docker-*` commands.
- `kubectl` with read access to pods in all namespaces for `k8s-check` (`KUBECTL="k3s kubectl"` to use another command), plus Docker to pull and check the images.
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

`docker-check`: `0` nothing vulnerable, `2` at least one container trusts the root, `1` error. `docker-fix` returns `docker-check`'s code after recreating. `image-check` and `k8s-check`: `0`, `2` likewise, `1` if any image couldn't be pulled or checked.

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

## Kubernetes

`docker-check` can't see pods on containerd (k3s, most managed clusters). `k8s-check` checks their images instead: unless a pod's spec changes its trust store, a pod trusts exactly what its image ships.

- Lists every container in `kubectl get pods -A` and checks each distinct image once, pulled by the digest the node is running (from the pod status), so a moved tag doesn't change the answer.
- The image goes through `docker create` (never started) and the same store checks as `docker-check`. Images it pulled are removed afterwards; `KEEP_IMAGES=1` keeps them.
- Marks `OVERRIDE` on containers that mount over a CA path (`ssl`, `pki`, `cert`, `ca-trust`, `truststore`) or set `SSL_CERT_FILE`, `SSL_CERT_DIR`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `USE_SYSTEM_CA_CERTS`, a CA flag in `NODE_OPTIONS`, or a `trustStore` in `JAVA_OPTS`/`JAVA_TOOL_OPTIONS`/`JDK_JAVA_OPTIONS`. For those the image result alone isn't the answer; check what's mounted. Env values aren't printed.
- Private registries: `docker login` first, or map the registry to a mirror or port-forward:

```bash
kubectl -n <ns> port-forward svc/<registry> 15000:5000 &
docker login localhost:15000
REWRITE="cr.example.com=localhost:15000" ./emudhra.sh k8s-check
```

`image-check <image...>` is the same check for any image list, e.g. before deploying.

Not covered: CA paths set through `envFrom` or container args, and pods without a status yet.

### Fixing pods

Rebuild images you own ([`Dockerfile.snippets`](Dockerfile.snippets)); for Java also clean the JDK `cacerts`. For third-party images, mount a clean bundle from a ConfigMap, created from a patched host (`./emudhra.sh check` says SAFE):

```bash
kubectl -n <ns> create configmap ca-bundle --from-file=ca-certificates.crt=/etc/ssl/certs/ca-certificates.crt
```

```yaml
      volumes:
        - name: ca-bundle
          configMap: {name: ca-bundle}
      containers:
        - name: app
          env:
            - {name: SSL_CERT_FILE, value: /etc/ssl/certs/ca-certificates.crt}   # Go, OpenSSL, Python ssl
          volumeMounts:
            - {name: ca-bundle, mountPath: /etc/ssl/certs, readOnly: true}
```

The directory mount holds only the clean bundle, so Go can't pick up stale per-cert files. As with the Docker mount it hides the image's own `/etc/ssl/certs` (private CAs, Debian Java's `java/cacerts`), and it's a snapshot: recreate it after host CA updates, or sync it with [trust-manager](https://cert-manager.io/docs/trust/trust-manager/). Node also needs `NODE_OPTIONS=--use-openssl-ca`; Java needs a cleaned `cacerts` (`java-truststore` on a Docker host) mounted over the JDK's. Only pods that make outbound TLS need this; cluster-internal TLS with the cluster CA is unaffected.

`k8s-check` reads the image, not the mounted ConfigMap, so after this it still shows the image result with `OVERRIDE`. Confirm with a real request from the pod: `kubectl exec <pod> -- curl -sSI https://dv-g3b-emudhra.we-have-a-problem.com/` should fail with a certificate error.

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

See [`Dockerfile.snippets`](Dockerfile.snippets): `ca-certificates` upgrade for Debian/Ubuntu and Alpine, `certifi>=2026.10.19` for Python, `--use-openssl-ca` for Node, JDK truststore cleanup for Java (`keytool -delete` loop, matches aliases `emsign`/`aaa_certificate_services`; for distroless, clean a copy in a JDK build stage and `COPY` it over `/etc/ssl/certs/java/cacerts`), current toolchain for Go.

## Brotli CVE check (GHSA-9v8h-qqgm-4m35 / CVE-2026-111497)

[`brotli-cve-check.sh`](brotli-cve-check.sh) looks for the Brotli decoder out-of-bounds write ("Node2Shell") on hosts, in running containers, local images and Kubernetes pods. It only reads: each target is probed with a short `sh` script (run locally, over `ssh`, via `docker exec`, or in a throwaway `docker run --network none --cap-drop ALL` for images).

| Finds | Status |
|---|---|
| PyPI `brotli` >= 1.0.3, < 1.2.1 / `brotlicffi` >= 1.0.3, < 1.2.1.0 (any venv, found by `*.dist-info`) | `VULNERABLE` |
| Node.js 22 / 24 / 26 below 22.23.4 / 24.22.1 / 26.12.1 (bundled decoder) | `VULNERABLE` |
| Java jars named `*brotli*`, npm `iltorb` / `brotli-wasm`, native `libbrotlidec.so*` | `REVIEW` (check the vendor or distro advisory; backports keep old version numbers) |

One-liners, no clone needed (read the script first; only `--fix` changes anything):

```bash
B=https://raw.githubusercontent.com/datmt/emudhra-fix/main/brotli-cve-check.sh
curl -fsSL $B | bash -s -- host                     # this machine
curl -fsSL $B | bash -s -- ssh:user@server          # another machine over ssh
curl -fsSL $B | bash -s -- -q all                   # containers + images, VULNERABLE rows only
curl -fsSL $B | bash -s -- k8s                      # pods in the current kubectl context
curl -fsSL $B | bash -s -- --fix host               # also upgrade vulnerable pip venvs (asks y/N)
curl -fsSL $B | SCAN_ROOT=/data bash -s -- host     # env vars go on bash, not curl
```

Or from a clone:

```bash
./brotli-cve-check.sh host                                                      # this machine (run as root to see everything)
./brotli-cve-check.sh ssh:user@server                                           # another machine over ssh, nothing installed there
./brotli-cve-check.sh --fix host                                                # also upgrade vulnerable pip venvs here (asks y/N; -y skips)
SCAN_ROOT=/data ./brotli-cve-check.sh host                                      # limit the file search to one directory
./brotli-cve-check.sh containers                                                # every running container
./brotli-cve-check.sh images                                                    # every local image
./brotli-cve-check.sh all                                                       # containers and images
./brotli-cve-check.sh k8s                                                       # every image used by pods in the current kubectl context
KCTX=prod K8S_NS=apps ./brotli-cve-check.sh k8s                                 # other context / one namespace
KUBECTL='docker exec k3d-mycluster-server-0 kubectl' ./brotli-cve-check.sh k8s  # k3d/k3s: kubectl only inside the node container
./brotli-cve-check.sh -q all                                                    # summary table with only the VULNERABLE rows (cron)
./brotli-cve-check.sh my-api python:3.12                                        # specific containers or images
```

Each target gets a block with every finding, then a summary table sorted worst first. Colour shows on a terminal; `NO_COLOR=1` turns it off. Exit code is 2 if anything is `VULNERABLE`, 0 otherwise.

`host` and `ssh:` run the same probe on a plain machine (Linux, macOS, BSD; needs only `sh` and `find`). Besides every Python venv, Node and jar on disk (skipping `/proc`, `/sys`, `/dev`, `/run`, `/mnt`, `/media` and container storage: `/var/lib/docker`, `containerd`, `containers`, `kubelet`, `rancher`; use `containers` / `images` for those), they check `curl -V` for the libbrotli it links and the installed `libbrotli*` package (dpkg, rpm, apk, pacman, brew). Distros often backport the fix without changing the version, so curl, packages and native libraries are `REVIEW` (vulnerable only if your distro hasn't patched; check its security tracker), while Python and Node versions are decisive. Over `ssh:` the probe is piped to `sh -s`; use your usual ssh keys or agent.

`k8s` lists pod and init-container images with `kubectl`, pulls each unique image locally if it isn't already there (`docker login` first for a private registry; images that can't be pulled show `PULL-FAILED`, not checked), scans it, then prints a per-pod table. It checks what the image contains, not what a pod mounts or installs at start-up, and scans the local platform's variant of a multi-arch image.

**Fixes.** Whenever something is `VULNERABLE` the script ends with a "how to fix" block: the exact `<venv>/bin/python -m pip install -U 'brotli>=1.2.1'` per venv, `conda install -p <env>` for conda envs (not pip), `uv cache clean` for uv caches, rebuild instructions for containers and images, and the Node versions to move to. `--fix` applies only the host venv upgrades (`pip`, or `uv pip` for uv-created venvs that have no pip; a failure shows pip's last error line), after listing them and asking `[y/N]` (`-y` skips the question). It never touches conda envs, caches, Node, OS packages, containers or `ssh:` targets. Restart the services using an upgraded venv, then re-run the check.

Limits: it doesn't open jars nested inside fat jars, and doesn't see statically linked binaries. Container and image scans stay inside the container's own filesystem (not mounted volumes), and a host scan skips network mounts under `/mnt` and `/media`, so a clean result isn't proof. The Node fix versions come from the [Node.js October 2026 security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases); confirm them there. A stopped container can't be exec'd; scan its image instead.

## Files

- `emudhra.sh` — check/fix script (host, Docker, images, Kubernetes)
- `Dockerfile.snippets` — per-base-image fixes
- `brotli-cve-check.sh` — Brotli CVE-2026-111497 scanner for containers and images (Python, Node, Java)
