![LibJWT - The C JWT Library](https://github.com/user-attachments/assets/8ca53c64-df33-4c2b-b799-0864a48d89cb)
---

<a href="https://jwt.io/libraries#:~:text=/libjwt">
<img alt="View on JWT.IO" align="right" src="http://jwt.io/img/badge.svg">
</a>

[![Build Status](https://app.travis-ci.com/benmcollins/libjwt.svg?branch=master)](https://app.travis-ci.com/github/benmcollins/libjwt)
[![codecov](https://codecov.io/gh/benmcollins/libjwt/graph/badge.svg?token=MhCaZ8cpwQ)](https://codecov.io/gh/benmcollins/libjwt)

## Build Prerequisites

### Required
- [JANSSON](https://github.com/akheron/jansson) (>= 2.0)

### Atleast one of these, you can use both
- OpenSSL (>= 1.1.0)
- GnuTLS (>= 3.4.0)

**NOTE:** OpenSSL >= 3.0 is required for JWK and JWKS support

### Optional
- [Check Library](https://github.com/libcheck/check/issues) for unit testing
- Doxygen

## Documentation
[GitHub Pages](https://benmcollins.github.io/libjwt/)

## Pre-built Packages
LibJWT is available in most Linux distributions as well as through
[Homebrew](https://formulae.brew.sh/formula/libjwt#default) for Linux,
macOS, and Windows.

## Build Instructions

**With GNU AutoTools:**
- ``autoreconf -if``
- ``mkdir build``
- ``cd build``
- ``../configure``
- ``make``

**With CMake:**
- ``mkdir build``
- ``cd build``
- ``cmake ..``
- ``make``

### Common
If you have *libcheck* installed, both targets will compile the test suite.
You can use the ``check`` target on autoconf or the ``test`` target on cmake.

Both build systems will auto detect *OpenSSL* and *GnuTLS* and use one or both.
Each build system has a way to force-enable (error if not found) or force-disable
either library.
