![LibJWT](https://github.com/user-attachments/assets/d486f8c1-4025-4018-8d95-bf8753d9662f)

# The JWT C Library +JWK +JWKS

[![View on JWT.IO](http://jwt.io/img/badge.svg)](https://jwt.io)

[![Build Status](https://app.travis-ci.com/benmcollins/libjwt.svg?branch=master)](https://app.travis-ci.com/github/benmcollins/libjwt) [![codecov](https://codecov.io/gh/benmcollins/libjwt/graph/badge.svg?token=MhCaZ8cpwQ)](https://codecov.io/gh/benmcollins/libjwt)

## Build Prerequisites

### Required

- [JANSSON](https://github.com/akheron/jansson) (>= 2.0)

### Atleast one of these

- OpenSSL (>= 1.1.0)
- GnuTLS (>= 3.4.0)

**NOTE:** OpenSSL >= 3.0 is required for JWK and JWKS support

### Optional

- [Check Library](https://github.com/libcheck/check/issues) for unit testing
- Doxygen

## Documentation

[GitHub Pages](https://benmcollins.github.io/libjwt/)

## Pre-built Packages

LibJWT is available in most Linux distributions as well as through [Homebrew](https://brew.sh/)
for Linux, macOS, and Windows.

## Build Instructions

**With GNU Make:** Use ``autoreconf -i`` to create project files and run ``./configure``.
- ``make all``: build library.
- ``make check``: build and run test suite.
- See INSTALL file for more details on GNU Auto tools and GNU Make.
- By default, it will build with OpenSSL and GnuTLS support if found. You can
  exclude or force either one by using the ``--with-`` and ``--without-`` flags
  to ``./configure``.

**With CMake:**
- ``mkdir build``
- ``cd build``
- ``cmake ..``
- ``make``

If you have libcheck installed, both targets will compile the test suite
(``check`` target on autoconf, ``test`` target on cmake).

If you ``--enable-code-coverage`` on autoconf or ``-DENABLE_COVERAGE=1``
on cmake, for the targets of ``check-code-coverage`` or ``coverage``
respectively.
