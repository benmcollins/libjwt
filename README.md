![LibJWT - The C JWT Library](images/LibJWT-800x152.png)
---

[![codecov](https://codecov.io/gh/benmcollins/libjwt/graph/badge.svg?token=MhCaZ8cpwQ)](https://codecov.io/gh/benmcollins/libjwt)

[![maClara](https://img.shields.io/badge/Sponsored%20by-maClara%2C%20LLC-blue?style=plastic&logoColor=blue)](https://maclara-llc.com)

> [!WARNING]
> Version 3 of LibJWT is a complete overhaul of the code. Please see documentation for usage.

## :bulb: Supported Standards

Standard | RFC                                                                        | Description
-------- | :------------------------------------------------------------------------: | ----------------------
``JWS``  | :page_facing_up: [RFC-7515](https://datatracker.ietf.org/doc/html/rfc7515) | JSON Web Signature
``JWE``  | :page_facing_up: [RFC-7516](https://datatracker.ietf.org/doc/html/rfc7516) | JSON Web Encryption
``JWK``  | :page_facing_up: [RFC-7517](https://datatracker.ietf.org/doc/html/rfc7517) | JSON Web Keys and Sets
``JWA``  | :page_facing_up: [RFC-7518](https://datatracker.ietf.org/doc/html/rfc7518) | JSON Web Algorithms
``JWT``  | :page_facing_up: [RFC-7519](https://datatracker.ietf.org/doc/html/rfc7519) | JSON Web Token

> [!NOTE]
> Throughout this documentation you will see links such as the ones
> above to RFC documents. These are relevant to that particular part of the
> library and are helpful to understand some of the specific standards that
> shaped the development of LibJWT.

## :construction: Build Prerequisites

### Required

- [JANSSON](https://github.com/akheron/jansson) (>= 2.0)
- [CMake](https://cmake.org) (>= 3.7)

### Crypto support

- OpenSSL (>= 3.0.0)
- GnuTLS (>= 3.6.0)
- MbedTLS (>= 3.6.0)

> [!NOTE]
> OpenSSL is required and used for JWK(S) operations.

### Algorithm support matrix

JWS Algorithm ``alg``         | OpenSSL            | GnuTLS             | MbedTLS
:---------------------------- | :----------------- | :----------------- | :----------------------
``HS256`` ``HS384`` ``HS512`` | :white_check_mark: | :white_check_mark: | :white_check_mark:
``ES256`` ``ES384`` ``ES512`` | :white_check_mark: | :white_check_mark: | :white_check_mark:
``RS256`` ``RS384`` ``RS512`` | :white_check_mark: | :white_check_mark: | :white_check_mark:
``EdDSA`` using ``ED25519``   | :white_check_mark: | :white_check_mark: | :x:
``EdDSA`` using ``ED448``     | :white_check_mark: | :white_check_mark: ``>= 3.8.8`` | :x:
``PS256`` ``PS384`` ``PS512`` | :white_check_mark: | :white_check_mark: | :white_check_mark:``*``
``ES256K``                    | :white_check_mark: | :x:                | :white_check_mark:

``*`` RSASSA-PSS support in MbedTLS depends on Mbed-TLS/TF-PSA-Crypto#154

### Optional

- [Check Library](https://github.com/libcheck/check/issues) (>= 0.9.10) for unit
  testing
- [Doxygen](https://www.doxygen.nl) (>= 1.13.0) for documentation

## :books: Docs and Source

:link: [Current Docs](https://libjwt.io)

:link: [Legacy Docs v2.1.1](https://libjwt.io/stable)

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
