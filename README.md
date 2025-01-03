![LibJWT - The C JWT Library](images/LibJWT-800x152.png)
---

[![Build Status](https://app.travis-ci.com/benmcollins/libjwt.svg?branch=master)](https://app.travis-ci.com/github/benmcollins/libjwt)
[![codecov](https://codecov.io/gh/benmcollins/libjwt/graph/badge.svg?token=MhCaZ8cpwQ)](https://codecov.io/gh/benmcollins/libjwt)

[![maClara](https://img.shields.io/badge/Sponsored%20by-maClara%2C%20LLC-blue?style=plastic&logoColor=blue)](https://maclara-llc.com)

## :construction: Build Prerequisites

### Required

- [JANSSON](https://github.com/akheron/jansson) (>= 2.0)
- CMake (>= 3.7)

### One or more of these

- OpenSSL (>= 1.1.0)
- GnuTLS (>= 3.6.0)

**NOTE:** OpenSSL >= 3.0 is required for JWK and JWKS support

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

@code{.sh}
$ mkdir build
$ cd build
$ cmake ..
$ make
@endcode

### Extra Build Info
If you have *libcheck* installed you can compile the test suite which you can
run using the ``check`` target.

CMake will auto detect *OpenSSL* and *GnuTLS* and use one or both. There are
CMake options to force either one on or off.
