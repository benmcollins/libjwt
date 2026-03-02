# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LibJWT is a C library implementing RFC 7515-7519 for JSON Web Tokens (JWT), JSON Web Keys (JWK), and JWK Sets (JWKS). It supports multiple cryptographic backends (OpenSSL, GnuTLS, MBedTLS) and JSON backends (Jansson, json-c).

## Build Commands

```bash
# Standard build
mkdir build && cd build
cmake ..
make

# Build with options
cmake -DWITH_GNUTLS=ON -DWITH_MBEDTLS=ON -DWITH_LIBCURL=ON -DWITH_JSON_C=ON ..

# Run all tests
make check

# Run a single test (from build directory)
ctest -R jwt_builder -V

# Run tests with valgrind memory checking
ctest -T memcheck

# Code coverage (must configure with ENABLE_COVERAGE)
cmake -DENABLE_COVERAGE=YES ..
make check-code-coverage

# Build documentation (requires Doxygen >= 1.9.8)
# Docs are built automatically if Doxygen is found
```

## Key CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `WITH_JSON_C` | OFF | Use json-c instead of Jansson |
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

1. **Crypto backend abstraction** (`jwt-crypto-ops.c`, `jwt-private.h:jwt_crypto_ops`): Each crypto provider (OpenSSL, GnuTLS, MBedTLS) implements the `jwt_crypto_ops` struct with function pointers for sign/verify and JWK parsing. OpenSSL is always required (handles JWK parsing); GnuTLS and MBedTLS are optional additional providers. The active provider is selected at runtime via `jwt_set_crypto_ops()`.

2. **JSON backend abstraction** (`jwt-json-ops.h`): Jansson and json-c each implement the same JSON operations interface. Selected at compile time via `WITH_JSON_C`.

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
