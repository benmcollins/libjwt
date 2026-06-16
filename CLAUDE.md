# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LibJWT is a C library implementing RFC 7515-7519 for JSON Web Tokens (JWT), JSON Web Keys (JWK), and JWK Sets (JWKS). It supports multiple cryptographic backends (OpenSSL, GnuTLS, MBedTLS) and JSON backends (Jansson, json-c).

## Issue Workflow

Follow this pipeline for every piece of work:

1. **Issue** — Work must map to a GitHub issue. If none exists, create one first describing the task.
2. **Branch** — `git checkout -b <issue#>-<short-summary>` (e.g. `157-crit-header`). Never work on `master`.
3. **Plan** — Plan the implementation, then post the plan as a comment on the issue.
4. **Implement** — Do the work, including tests for all new code (see Testing) and coverage (no new uncovered lines). Verify under both JSON backends when JSON handling is touched.
5. **PR** — Open a PR (`closes #<issue>`), then watch CI to completion (`gh pr checks <#> --watch` or the GitHub check-runs API) and fix any failures.

Commit messages: `git commit -s` (Signed-off-by). Don't commit/push unless asked.

## Build Commands

```bash
# Standard build
mkdir build && cd build
cmake ..
make

# Build with options
cmake -DWITH_GNUTLS=ON -DWITH_MBEDTLS=ON -DWITH_LIBCURL=ON -DWITH_JSON_C=ON ..

# Switching backends in an existing build/ resets unspecified flags (e.g.
# ENABLE_COVERAGE -> OFF). Re-pass all flags and `make clean` after switching,
# since stale .gcno/.gcda from the prior backend linger.

# Only `/build/**` is gitignored. Name throwaway build trees `build/...` or
# remove them before `git add -A` — a stray `build-foo/` will otherwise be
# staged and committed.

# Run all tests
make check

# Run a single test (from build directory)
ctest -R jwt_builder -V

# Run tests with valgrind memory checking
ctest -T memcheck

# Code coverage (must configure with ENABLE_COVERAGE)
cmake -DENABLE_COVERAGE=YES ..
make check-code-coverage

All new code MUST be covered by tests cases. Do not commit ANY code
changes without running coverage first, and ensure there are no new
missing lines covered.

# NOTE: `make check-code-coverage` always exits non-zero — its final genhtml
# step fails ("no valid records"). The lcov capture still succeeds; read
# per-line coverage from build/check-code-coverage.capture (lcov DA: records).
# In that file, jwt-common.c appears ~4x (builder/checker x lib/test-harness);
# the real library coverage is the jwt.dir record, not the per-filename union.
#
# Code that is #ifdef'd out (e.g. an off-by-default feature) is invisible to
# gcov, so it never counts as uncovered. Enabling such a feature in a
# coverage/Codecov job makes its lines visible — only do that if a test
# actually exercises them, or codecov/patch will drop. Genuinely unreachable
# defensive branches use // LCOV_EXCL_LINE or // LCOV_EXCL_START/STOP.

# Build documentation (requires Doxygen >= 1.9.8)
# Docs are built automatically if Doxygen is found
```

**Doc encoding.** Doxygen processes `include/jwt.h` (public-header doc comments)
and `doxygen/mainpage.dox`. `DOXYGEN_INPUT_ENCODING` in
`cmake/LibJWTDoxyfile.cmake` is **UTF-8** to match the UTF-8 sources, so
non-ASCII (em-dashes, curly quotes, symbols) renders correctly in the generated
HTML. It was previously `ISO-8859-1`, which decoded the UTF-8 bytes as Latin-1
and produced mojibake (a UTF-8 em-dash showed up as an `a`-prefixed
box-character blob); do not revert it.

## Key CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `WITH_JSON_C` | OFF | Use json-c instead of Jansson |
| `WITH_OPENSSL` | ON | Enable OpenSSL backend |
| `WITH_GNUTLS` | auto-detect | Enable GnuTLS backend |
| `WITH_MBEDTLS` | OFF | Enable MBedTLS backend |
| `WITH_LIBCURL` | OFF | Enable libcurl for remote JWKS |
| `WITH_TESTS` | ON | Build test suite |
| `WITH_KCAPI_MD` | OFF | Linux Kernel Crypto API for HMAC |
| `ENABLE_COVERAGE` | OFF | LCOV code coverage |
| `EXCLUDE_DEPRECATED` | OFF | Exclude deprecated API |
| `WITH_ML_DSA` | OFF | Experimental ML-DSA (FIPS 204/RFC 9964); needs OpenSSL >= 3.5 or GnuTLS >= 3.8.10 |

## Architecture

### Abstraction Layers

The library has two key abstraction interfaces that allow swapping implementations:

1. **Crypto backend abstraction** (`jwt-crypto-ops.c`, `jwt-private.h:jwt_crypto_ops`): Each crypto provider (OpenSSL, GnuTLS, MBedTLS) implements the `jwt_crypto_ops` struct with function pointers for sign/verify, JWK parsing (`process_*`), and native-key→JWK conversion (`key2jwk_params`, assembled by the common `jwk-export.c`). All three backends are optional and interchangeable; the build requires at least one but works with any combination (default `WITH_OPENSSL=ON`). A GnuTLS-only build (no OpenSSL) requires GnuTLS >= 3.8.4, since older GnuTLS has no native JWK/JWE path and falls back to OpenSSL. The MbedTLS backend targets the MbedTLS **3.6.x LTS** API (`mbedcrypto>=3.6.0`); MbedTLS **4.x will not build** — its PSA rewrite drops the legacy `mbedtls_pk_*` API the backend uses — so pin 3.6.x (the CI image builds it from source for this reason). The active provider is selected at runtime via `jwt_set_crypto_ops()`; the default is the first compiled backend (OpenSSL > GnuTLS > MBedTLS).

2. **JSON backend abstraction** (`jwt-json-ops.h`): Jansson and json-c each implement the same JSON operations interface. Selected at compile time via `WITH_JSON_C`.

   - **json-c asserts (aborts)** where Jansson returns gracefully: e.g. `json_object_array_length()`/`_get_idx()` abort on a non-array (Jansson returns 0/NULL). Type-check in the json-c wrapper. Test any JSON handling under BOTH backends.
   - `jwt_json_obj_set`/`jwt_json_arr_append` STEAL the value reference in both backends — never free what you set/append.

### Experimental & version-gated features (ML-DSA)

ML-DSA (FIPS 204 / RFC 9964 post-quantum signatures `ML-DSA-44/65/87`, JWK
`kty="AKP"`) is the template for an optional, off-by-default, version-gated
feature:

- Gated behind `WITH_ML_DSA` (default OFF). CMake sets `LIBJWT_HAVE_ML_DSA` only
  when a *capable* backend is present (OpenSSL >= 3.5 **or** GnuTLS >= 3.8.10).
  That macro is emitted into the public `jwt_export.h` via `#cmakedefine` in
  `include/jwt_export.h.in`, so the same macro gates library and downstream code.
- The `jwt_alg_t` / `jwk_key_type_t` enum values exist **unconditionally** (ABI
  stability); only recognition (`jwt_str_alg`), dispatch, the `jwt_alg_required_kty`
  anti-confusion gate, and backend code are gated. The CLI tools' `-l` loops skip
  algs whose `jwt_alg_str()` returns NULL so a compiled-out alg isn't listed.
- Each backend's ML-DSA code carries its OWN version guard in addition to the
  macro — `#if defined(LIBJWT_HAVE_ML_DSA) && OPENSSL_VERSION_NUMBER >= 0x30500000L`
  (OpenSSL) / `&& GNUTLS_VERSION_NUMBER >= 0x03080a` (GnuTLS) — so a multi-backend
  build with one capable and one too-old backend still compiles.
- AKP keys: `pub` = encoded public key, `priv` = the **32-byte FIPS-204 seed**
  (not the expanded key), `alg` REQUIRED, no `crv`. The variant is pinned to the
  key at sign time to prevent algorithm confusion. A private key with no seed
  (expanded-only) cannot be a private AKP JWK; both backends downgrade it to a
  public export rather than emit a broken key.
- **GnuTLS** needs a build with a PQC provider (`--with-leancrypto`); a stock
  GnuTLS returns `-106` at runtime. There is no raw ML-DSA import, so
  `gnutls/jwk-parse.c` hand-builds SubjectPublicKeyInfo / seed-PKCS#8 DER and
  imports that; `gnutls_x509_privkey_export2_pkcs8(..., GNUTLS_PKCS_MLDSA_SEED,
  ...)` SEGFAULTS on a seedless key, so export probes for the seed via a plain
  PKCS#8 export first.

**Dynamic (runtime) version gating.** When the defect is in the *shared* crypto
library rather than libjwt, gate on the RUNTIME version so a library upgrade
fixes it without rebuilding libjwt. Use a hybrid: a build-time
`#if GNUTLS_VERSION_NUMBER < 0xMMmmpp` (keeps the code absent — and
coverage-invisible — when built against a fixed version) wrapping a runtime
`gnutls_check_version("M.m.p")` check that decides per call. `gnutls/jwk-parse.c`
(`gnutls_process_eddsa`) rejects two **GnuTLS < 3.8.13** OKP defects this way:
(1) `gnutls_privkey_import_ecc_raw()` **SEGFAULTS** deriving the public key for a
*seed-only* OKP private JWK — `d` present, **no `x`** — for any curve
(Ed25519/Ed448/X25519/X448); (2) X25519/X448 **ECDH-ES** derive yields nothing.
Keys that carry `x`, all public keys, and the PEM/DER path (whose JWK export
always includes `x`) are unaffected, as are OpenSSL and MbedTLS. A library must
*error*, not crash, on a key it can't handle.

### Source Organization

- `libjwt/` — Core library source
  - `jwt.c` — Main JWT creation, parsing, and lifecycle
  - `jwt-common.c` — Shared builder/checker logic (compiled twice with `-DJWT_BUILDER` and `-DJWT_CHECKER` preprocessor flags via custom CMake commands)
  - `jwt-setget.c` — Claims get/set operations using `jwt_value_t`
  - `jwt-verify.c` — JWT signature verification
  - `jwt-encode.c` — JWT encoding/signing
  - `jwks.c` — JWK/JWKS parsing and management
  - `jwt-private.h` — Internal structures (`jwt`, `jwk_set`, `jwk_item`, `jwt_crypto_ops`)
  - `openssl/`, `gnutls/`, `mbedtls/` — Crypto backend implementations
  - `jansson/`, `json-c/` — JSON backend implementations
- `include/jwt.h` — Complete public API (the only public header)
- `tools/` — CLI utilities: `jwt-generate`, `jwt-verify`, `jwk2key`, `key2jwk`
- `tests/` — Check framework unit tests and BATS integration tests

### Key Patterns

- **Memory management**: Custom allocators (`jwt_malloc`, `__jwt_freemem`) with GCC `__attribute__((cleanup()))` auto-cleanup via `jwt_auto_t`, `jwt_builder_auto_t`, `jwt_checker_auto_t`, `jwt_json_auto_t` typedefs.
- **Error handling**: Objects carry `error` flag and `error_msg[256]` buffer. Use `jwt_write_error()` macro for consistent error reporting.
- **Builder/Checker pattern**: `jwt_builder_t` creates tokens, `jwt_checker_t` verifies them. Both share `jwt_common` struct internals. Support callback-based claim generation/verification.
- **Linked list**: Internal `ll.h` provides a doubly-linked list for JWK sets.

## Testing

Tests use the [Check](https://libcheck.github.io/check/) C unit testing framework. Each test file defines a `libjwt_suite()` function and uses the `JWT_TEST_MAIN()` macro.

- Tests iterate over all compiled crypto providers using the `jwt_test_ops[]` array and `SET_OPS()` macro via Check's loop tests (`_i` index variable).
- Test keys are in `tests/keys/` — referenced via the `KEYDIR` compile-time macro.
- A constant timestamp `TS_CONST` (1475980545L) is used for reproducible time-based tests.
- BATS tests in `tests/jwt-cli.bats` cover the CLI tools.
- For features that depend on the runtime (not just compile-time) capability of a
  backend, probe at runtime and skip incapable backends rather than hardcoding
  which provider supports what — e.g. `mldsa_supported()` in `jwt_mldsa.c` loads a
  known AKP key under the active ops, so the success tests run on OpenSSL and a
  PQC-enabled GnuTLS and skip a GnuTLS without leancrypto (and MbedTLS).
  `gnutls_okp_jwk_broken()` in `jwt_tests.h` is a second example — it mirrors the
  library's hybrid build/runtime gate (`gnutls_check_version("3.8.13")`) to skip
  the OKP keys an old GnuTLS can't load, so the suite passes on GnuTLS 3.8.9 and
  3.8.13 alike.

## Continuous Integration

`.github/workflows/build-and-test.yml`. Codecov is **informational only** (never
fails CI), and the in-CI coverage step runs `check-code-coverage` under `|| true`
and just uploads the `.info` — it does **not** fail on a coverage regression. The
"no new uncovered lines in `libjwt/`+`tools/`" rule is a developer discipline you
enforce locally before committing (see Build Commands / Issue Workflow), not an
automatic CI gate. Still, do NOT add compiled-but-unexercised code to a coverage
job (see the gcov/`#ifdef` note under Build Commands) — it lowers `codecov/patch`.

- **CI base image** — `build-linux-combos` runs inside a custom image,
  `ghcr.io/benmcollins/libjwt/gnutls-leancrypto-mbedtls`, built from
  `.github/docker/Dockerfile` and pushed by `.github/workflows/ci-image.yml`
  (GHCR via the built-in `GITHUB_TOKEN`; the package must be **public** so
  `container:` jobs and fork PRs can pull it). It is `debian:forky` with GnuTLS
  built `--with-leancrypto` (so the ML-DSA **and** Ed448/X25519/X448 success
  paths are real — forky's apt GnuTLS lacks both) and the latest MbedTLS 3.6.x
  LTS, both from source; everything else (and every build-dep) is native Debian
  apt. See `.github/docker/README.md`. Respin by bumping the Dockerfile `ARG`
  pins and re-running the workflow. A CI change that *references* the image must
  land only after the image is pushed and made public.
- `build-linux-combos` runs the seven backend combinations in that image. The
  renamed **`all`** row (all three backends + `WITH_ML_DSA=ON`) is the **only**
  row that collects coverage → Codecov **and** runs `ctest -T memcheck`; on the
  leancrypto image its ML-DSA/Ed448/X-curve lines are exercised, not just
  compiled. The other rows just build + `ctest`.
- `build-linux` is a vendor-compatibility matrix: Ubuntu 22.04/24.04/26.04 and
  Debian stable/oldstable, each built with **both** JSON backends (jansson +
  json-c) — OpenSSL only. GnuTLS is OFF on every row: the GnuTLS these distros
  ship is either below the `gnutls>=3.8.8` CMake floor or `<= 3.8.12` (which hits
  the GnuTLS < 3.8.13 OKP defects — see the version-gated note), so none can fully
  exercise it. json-c is excluded on Ubuntu 22.04 (jammy ships json-c
  0.15 < the 0.16 floor). Debian has no hosted runner, so stable/oldstable run as
  `container:`; `ubuntu-26.04` is a preview runner (`continue-on-error`).
- `build-linux-mbedtls` and `build-linux-json-c` were **removed** — folded into
  the `all` row and the compat matrix respectively.
- For same-repo PRs the workflow runs from the PR branch's copy of the YAML; for
  forks it uses the base branch's. `paths-ignore` skips runs whose changes are
  entirely docs/`.github`/images — so a `.github`-only push won't trigger it (use
  `workflow_dispatch`).

## Compiler Flags

The project compiles with `-Wall -Werror -Wextra -Wunused`. All warnings are errors.
