![LibJWT - The C JWT Library](images/LibJWT-800x152.png)
---

[![codecov](https://codecov.io/gh/benmcollins/libjwt/graph/badge.svg?token=MhCaZ8cpwQ)](https://codecov.io/gh/benmcollins/libjwt)

[![maClara](https://img.shields.io/badge/Sponsored%20by-maClara%2C%20LLC-blue?style=plastic&logoColor=blue)](https://maclara-llc.com)

> [!WARNING] The current LibJWT code is under heavy reconstruction and is changing
> wildly from the API and ABI of v2 and prior. There's still a lot going on here,
> and there are no guarantees that this new API is set in stone. Users beware.

## :bulb: Supported Standards

Standard             | RFC                                                                        | Description
-------------------- | :------------------------------------------------------------------------: | ---------------------
``JWT``              | :page_facing_up: [RFC-7519](https://datatracker.ietf.org/doc/html/rfc7519) | JSON Web Token
``JWA``              | :page_facing_up: [RFC-7518](https://datatracker.ietf.org/doc/html/rfc7518) | JSON Web Algorithms
``JWS`` and ``JWE``  | :page_facing_up: [RFC-7518](https://datatracker.ietf.org/doc/html/rfc7518) | Specific types of JWA
``JWK`` and ``JWKS`` | :page_facing_up: [RFC-7517](https://datatracker.ietf.org/doc/html/rfc7517) | JSON Web Key & Sets

> [!NOTE]
> Throughout this documentation you will see links such as the ones
> above to RFC documents. These are relevant to that particular part of the
> library and are helpful to understand some of the specific standards that
> shaped the development of LibJWT.

## :construction: Build Prerequisites

### Required

- [JANSSON](https://github.com/akheron/jansson">JANSSON) (>= 2.0)
- [CMake](https://cmake.org) (>= 3.7)

### Crypto support

- OpenSSL (>= 3.0.0)
- GnuTLS (>= 3.6.0)

> [!NOTE]
> OpenSSL is required and used for JWK(S) operations. GnuTLS is optional for
> use in signing and verifying if configured.

### Optional

- [Check Library](https://github.com/libcheck/check/issues) (>= 0.9.10) for unit
  testing
- [Doxygen](https://www.doxygen.nl) (>= 1.13.0) for documentation

## :books: Docs and Source

:link: [Current codebase](https://libjwt.io)

:link: [Stable](https://libjwt.io/stable)

:link: [GitHub Repo](https://github.com/benmcollins/libjwt)

## :package: Pre-built Packages

LibJWT is available in most Linux distributions as well as through
[Homebrew](https://formulae.brew.sh/formula/libjwt#default)
for Linux, macOS, and Windows.

## :hammer: Build Instructions

### With CMake:

    $ mkdir build
    $ cd build
    $ cmake ..
    $ make
