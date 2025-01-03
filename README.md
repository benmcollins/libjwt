![LibJWT - The C JWT Library](images/LibJWT-800x152.png)
---

[![Build Status](https://app.travis-ci.com/benmcollins/libjwt.svg?branch=master)](https://app.travis-ci.com/github/benmcollins/libjwt)
[![codecov](https://codecov.io/gh/benmcollins/libjwt/graph/badge.svg?token=MhCaZ8cpwQ)](https://codecov.io/gh/benmcollins/libjwt)

[![maClara](https://img.shields.io/badge/Sponsored%20by-maClara%2C%20LLC-blue?style=plastic&logoColor=blue)](https://maclara-llc.com)

## :bulb: Supported Standards

Standard             | RFC        | Description
-------------------- | :--------: | --------------------------------------
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

- [JANSSON](https://github.com/akheron/jansson) (>= 2.0)
- CMake (>= 3.7)

### One or more of these

- OpenSSL (>= 1.1.0)
- GnuTLS (>= 3.6.0)

> [!NOTE]
> OpenSSL >= 3.0 is required for JWK and JWKS support

### Optional

- [Check Library](https://github.com/libcheck/check/issues) for unit testing
- Doxygen

## :books: Docs and Source

:link: [Release](https://libjwt.io/)

:link: [Development](https://libjwt.io/HEAD/)

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

### Extra Build Info
If you have *libcheck* installed you can compile the test suite which you can
run using the ``check`` target.

CMake will auto detect *OpenSSL* and *GnuTLS* and use one or both. There are
CMake options to force either one on or off.
