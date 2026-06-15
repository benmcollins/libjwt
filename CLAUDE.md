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

# Build documentation (requires Doxygen >= 1.9.8)
# Docs are built automatically if Doxygen is found
```

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

## Architecture

### Abstraction Layers

The library has two key abstraction interfaces that allow swapping implementations:

1. **Crypto backend abstraction** (`jwt-crypto-ops.c`, `jwt-private.h:jwt_crypto_ops`): Each crypto provider (OpenSSL, GnuTLS, MBedTLS) implements the `jwt_crypto_ops` struct with function pointers for sign/verify, JWK parsing (`process_*`), and native-key→JWK conversion (`key2jwk_params`, assembled by the common `jwk-export.c`). All three backends are optional and interchangeable; the build requires at least one but works with any combination (default `WITH_OPENSSL=ON`). A GnuTLS-only build (no OpenSSL) requires GnuTLS >= 3.8.4, since older GnuTLS has no native JWK/JWE path and falls back to OpenSSL. The active provider is selected at runtime via `jwt_set_crypto_ops()`; the default is the first compiled backend (OpenSSL > GnuTLS > MBedTLS).

2. **JSON backend abstraction** (`jwt-json-ops.h`): Jansson and json-c each implement the same JSON operations interface. Selected at compile time via `WITH_JSON_C`.

   - **json-c asserts (aborts)** where Jansson returns gracefully: e.g. `json_object_array_length()`/`_get_idx()` abort on a non-array (Jansson returns 0/NULL). Type-check in the json-c wrapper. Test any JSON handling under BOTH backends.
   - `jwt_json_obj_set`/`jwt_json_arr_append` STEAL the value reference in both backends — never free what you set/append.

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

## Compiler Flags

The project compiles with `-Wall -Werror -Wextra -Wunused`. All warnings are errors.
