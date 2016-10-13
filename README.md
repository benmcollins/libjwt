# JWT C Library

[![Build Status](https://travis-ci.org/benmcollins/libjwt.svg?branch=master)](https://travis-ci.org/benmcollins/libjwt) [![codecov.io](http://codecov.io/github/benmcollins/libjwt/coverage.svg?branch=master)](http://codecov.io/github/benmcollins/libjwt?branch=master)

[![View on JWT.IO](https://jwt.io/assets/badge.svg)](https://jwt.io)

## Build Requirements

- https://github.com/akheron/jansson
- OpenSSL

## Documentation

[GitHub Pages](http://benmcollins.github.io/libjwt/)

## Pre-built Ubuntu Packages (PPA)

`sudo add-apt-repository ppa:ben-collins/libjwt`

## Build Instructions

**With GNU Make:** Use ``autoreconf -i`` to create project files and run ``./configure``.
- ``make all``: build library.
- ``make check``: build and run test suite.
- See INSTALL file for more details on GNU Auto tools and GNU Make.

**With CMake:** use ``cmake .`` in root project path to build the Makefile.
- ``make jwt``: build shared library in lib/ dir.
- ``make jwt_static``: build static library in lib/ dir.
- ``make check``: build and run test suite.
- ``make clean``.
