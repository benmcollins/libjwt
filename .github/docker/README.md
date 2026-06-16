# LibJWT CI base image

`ghcr.io/benmcollins/libjwt/gnutls-leancrypto-mbedtls`

A `debian:forky` image with every LibJWT crypto/JSON backend usable in one
place, built so the **GnuTLS ML-DSA success path actually works** and the
**latest MbedTLS 3.6.x LTS** is present - neither of which forky's stock apt
packages provide.

| Component | Source | Notes |
|-----------|--------|-------|
| OpenSSL | forky apt (`libssl-dev`) | 3.6.x >= 3.5, so the OpenSSL ML-DSA path works |
| GnuTLS | **from source** `--with-leancrypto` | ML-DSA (FIPS 204 / RFC 9964, `kty="AKP"`) success path; stock GnuTLS returns `-106` |
| leancrypto | **from source** | the PQC provider GnuTLS statically links against |
| MbedTLS | **from source**, 3.6.x LTS | **not** 4.x (PSA rewrite drops the legacy `mbedtls_pk_*` API libjwt uses) |
| jansson + json-c | forky apt | both JSON backends installed, either selectable |
| libcurl, check, bats, jq, lcov, valgrind | forky apt | build + test + coverage + memcheck tooling |

Only the three components that genuinely need a custom/newer build are compiled
from source (into `/usr/local`); every build-dependency comes from native
Debian apt. `libgnutls28-dev` / `libmbedtls-dev` are deliberately **not**
installed so their apt `.pc` files cannot shadow the from-source ones.

## Pinned versions

Set via `ARG` in the [`Dockerfile`](./Dockerfile) - bump these for a respin:

```dockerfile
ARG LEANCRYPTO_VERSION=v1.7.2
ARG GNUTLS_VERSION=3.8.13     # >= 3.8.10 enables ML-DSA
ARG GNUTLS_SERIES=v3.8        # keep in sync with GNUTLS_VERSION's major.minor
ARG MBEDTLS_VERSION=3.6.6     # 3.6.x LTS only
```

The final layer of the Dockerfile asserts these guarantees (pkg-config floors,
`/usr/local` precedence, and a live `certtool` ML-DSA key-gen proving the
leancrypto provider is wired in), so a bad respin fails the build instead of
publishing a silently broken image.

## Respinning the image

Automatically, via the [`ci-image.yml`](../workflows/ci-image.yml) workflow:

- It runs on **`workflow_dispatch`** (Actions -> *Build CI Base Image* -> *Run
  workflow*) and on pushes to `master` that touch the `Dockerfile` or that
  workflow.
- It pushes `:latest`, `:forky`, and `:<sha>` tags to GHCR using the built-in
  `GITHUB_TOKEN` (no secrets to manage).

Locally:

```bash
docker build -f .github/docker/Dockerfile \
  -t ghcr.io/benmcollins/libjwt/gnutls-leancrypto-mbedtls:latest .
```

## Using it

The image bakes in the full toolchain, so a consuming CI job just builds:

```bash
cmake -B build -DWITH_OPENSSL=ON -DWITH_GNUTLS=ON -DWITH_MBEDTLS=ON \
      -DWITH_ML_DSA=ON -DWITH_LIBCURL=YES
cmake --build build -- all
ctest --test-dir build --output-on-failure
```

> The package must be **public** (Packages -> settings -> *Change visibility*)
> for `container:` jobs to pull it without a `credentials:` block.
