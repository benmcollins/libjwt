# JWT C Library

[![Build Status](https://travis-ci.org/benmcollins/libjwt.svg?branch=master)](https://travis-ci.org/benmcollins/libjwt) [![codecov.io](http://codecov.io/github/benmcollins/libjwt/coverage.svg?branch=master)](http://codecov.io/github/benmcollins/libjwt?branch=master)

## Build Requirements

- [Jansson](https://github.com/akheron/jansson)
- [OpenSSL](https://github.com/openssl/openssl)
- [Check](https://github.com/libcheck/check) (Tests)
- [Google Benchmark](https://github.com/google/benchmark) (Benchmarks)

## Documentation

[GitHub Pages](http://benmcollins.github.io/libjwt/)

## Pre-build Ubuntu Packages (PPA)

`sudo add-apt-repository ppa:ben-collins/libjwt`

## Build Instructions
**With CMake:** use ``cmake .`` in root project path to build the Makefile.
- ``make jwt``: build shared library in lib/ dir.
- ``make jwt_static``: build static library in lib/ dir.
- ``make tests``: build all test in buid/ directory and run all tests.
- ``make benchmark``: build benchmark in buid/ directory and run all benchmarks.
- ``make clean``.

## Benchmark functions

![Benchmark](http://i.imgur.com/ObJbX9Y.png)

