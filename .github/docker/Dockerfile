# syntax=docker/dockerfile:1
#
# CI base image for LibJWT: debian:forky with every backend usable.
#
#   * OpenSSL          - from forky apt (3.6.x, >= 3.5 so the OpenSSL ML-DSA path works)
#   * GnuTLS           - built FROM SOURCE --with-leancrypto so the ML-DSA
#                        (FIPS 204 / RFC 9964, kty="AKP") SUCCESS path works
#   * leancrypto       - built FROM SOURCE; the PQC provider GnuTLS links against
#   * MbedTLS          - built FROM SOURCE (3.6.x LTS, NOT the 4.x PSA rewrite,
#                        which drops the legacy mbedtls_pk_* API libjwt uses)
#   * jansson + json-c - both JSON backends, from apt
#   * libcurl, check, bats, jq, lcov, valgrind - from apt
#
# Only the three components that genuinely need a custom/newer build are built
# from source; every build-dependency comes from native Debian apt.
#
# We deliberately do NOT install forky's libgnutls28-dev or libmbedtls-dev:
# their gnutls.pc / mbedcrypto.pc under /usr/lib/<triplet>/pkgconfig would
# shadow our from-source .pc files and make CMake link the apt (no-leancrypto)
# libraries instead of ours. forky's apt GnuTLS is *also* 3.8.13, so the only
# reliable discriminator is the install prefix (/usr/local) + ML-DSA capability.
#
# Published at: ghcr.io/benmcollins/libjwt/gnutls-leancrypto-mbedtls
# Rebuilt by:   .github/workflows/ci-image.yml
#
FROM debian:forky

LABEL org.opencontainers.image.source="https://github.com/benmcollins/libjwt"
LABEL org.opencontainers.image.description="LibJWT CI base: debian:forky + OpenSSL (apt), GnuTLS built --with-leancrypto (ML-DSA success path), MbedTLS 3.6.x LTS from source, jansson + json-c, libcurl, check, bats, jq, lcov, valgrind."
LABEL org.opencontainers.image.licenses="MPL-2.0"

# ---- Pinned from-source versions (confirmed latest as of 2026-06-16) --------
ARG LEANCRYPTO_VERSION=v1.7.2
ARG GNUTLS_VERSION=3.8.13
ARG MBEDTLS_VERSION=3.6.6
# GnuTLS tarballs are laid out by major.minor; keep this in sync with the
# major.minor of GNUTLS_VERSION when bumping.
ARG GNUTLS_SERIES=v3.8

ENV DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8

# All three from-source installs use --libdir=lib, so their .pc files land in
# /usr/local/lib/pkgconfig and their .so files in /usr/local/lib (NOT Debian's
# multiarch lib/<triplet>). That keeps discovery arch-agnostic: this same
# Dockerfile builds correctly on amd64 and arm64. The apt deps' .pc files live
# on pkg-config's default system search path and need no help here.
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

# ---------------------------------------------------------------------------
# 1. apt dependencies: libjwt's own build/test deps + everything needed to
#    compile leancrypto, GnuTLS, and MbedTLS from source (all build-deps from
#    native Debian). NOTE: libgnutls28-dev and libmbedtls-dev are intentionally
#    absent so their apt .pc files cannot shadow our from-source ones.
# ---------------------------------------------------------------------------
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates git curl xz-utils \
        build-essential cmake pkg-config \
        gettext autoconf automake libtool \
        meson ninja-build nasm \
        python3 python3-jinja2 python3-jsonschema perl \
        nettle-dev libgmp-dev libtasn1-6-dev libidn2-dev libunistring-dev zlib1g-dev \
        libssl-dev libjansson-dev libjson-c-dev libcurl4-openssl-dev \
        check bats jq lcov valgrind; \
    rm -rf /var/lib/apt/lists/*

# Search /usr/local/lib first at run time so our from-source GnuTLS/MbedTLS/
# leancrypto win over any apt-provided copy.
RUN set -eux; \
    echo '/usr/local/lib' > /etc/ld.so.conf.d/000-usrlocal.conf; \
    ldconfig

# ---------------------------------------------------------------------------
# 2. leancrypto (PQC provider) -> /usr/local
#    -Ddefault_library=both: GnuTLS STATIC-links the provider (no dlopen), so a
#    static archive must exist; the shared lib is kept for completeness.
#    --libdir=lib puts leancrypto.pc on the default pkg-config path.
#    -Dtests=disabled skips the (large) test-binary suite we don't need; the
#    algorithm self-tests (enable_selftests, default on) stay enabled.
# ---------------------------------------------------------------------------
RUN set -eux; \
    git clone --depth 1 --branch "${LEANCRYPTO_VERSION}" \
        https://github.com/smuellerDD/leancrypto.git /tmp/leancrypto; \
    meson setup /tmp/leancrypto/build /tmp/leancrypto \
        --prefix=/usr/local --libdir=lib --buildtype=release \
        -Ddefault_library=both -Dtests=disabled; \
    meson compile -C /tmp/leancrypto/build; \
    meson install -C /tmp/leancrypto/build; \
    ldconfig; \
    pkg-config --exists leancrypto; \
    echo "leancrypto $(pkg-config --modversion leancrypto) installed"; \
    rm -rf /tmp/leancrypto

# ---------------------------------------------------------------------------
# 3. GnuTLS --with-leancrypto -> /usr/local
#    leancrypto.pc MUST be discoverable now (it is, via PKG_CONFIG_PATH), or
#    ./configure aborts in PKG_CHECK_MODULES([LEANCRYPTO],[leancrypto >= 1.2.0]).
#    Tools (certtool/gnutls-cli) are kept on purpose: certtool is the ML-DSA
#    smoke test below and some BATS tests may shell out to them. We use the apt
#    libtasn1 / libunistring (native build-deps), not GnuTLS's bundled copies.
# ---------------------------------------------------------------------------
RUN set -eux; \
    cd /tmp; \
    curl -fLO "https://www.gnupg.org/ftp/gcrypt/gnutls/${GNUTLS_SERIES}/gnutls-${GNUTLS_VERSION}.tar.xz"; \
    tar xf "gnutls-${GNUTLS_VERSION}.tar.xz"; \
    cd "gnutls-${GNUTLS_VERSION}"; \
    ./configure \
        --prefix=/usr/local \
        --with-leancrypto \
        --without-p11-kit \
        --without-tpm2 \
        --disable-doc \
        --disable-tests \
        --disable-guile \
        --disable-libdane \
        --enable-shared \
        --enable-static; \
    make -j"$(nproc)"; \
    make install; \
    ldconfig; \
    rm -rf "/tmp/gnutls-${GNUTLS_VERSION}" "/tmp/gnutls-${GNUTLS_VERSION}.tar.xz"

# ---------------------------------------------------------------------------
# 4. MbedTLS 3.6.x LTS -> /usr/local
#    Use the NAMED release asset (.tar.bz2) - it is self-contained (no
#    framework/ submodule). The default config is sufficient for libjwt's
#    JWS/JWK/JWE, so do NOT set MBEDTLS_CONFIG_FILE. The stock build installs
#    mbedcrypto.pc (+ mbedtls.pc, mbedx509.pc) to lib/pkgconfig.
# ---------------------------------------------------------------------------
RUN set -eux; \
    cd /tmp; \
    curl -fsSL -o "mbedtls-${MBEDTLS_VERSION}.tar.bz2" \
        "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VERSION}/mbedtls-${MBEDTLS_VERSION}.tar.bz2"; \
    tar xjf "mbedtls-${MBEDTLS_VERSION}.tar.bz2"; \
    cd "mbedtls-${MBEDTLS_VERSION}"; \
    cmake -S . -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DUSE_SHARED_MBEDTLS_LIBRARY=On \
        -DUSE_STATIC_MBEDTLS_LIBRARY=Off \
        -DENABLE_TESTING=Off \
        -DENABLE_PROGRAMS=Off \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DMBEDTLS_FATAL_WARNINGS=Off; \
    cmake --build build -j"$(nproc)"; \
    cmake --install build; \
    ldconfig; \
    rm -rf "/tmp/mbedtls-${MBEDTLS_VERSION}" "/tmp/mbedtls-${MBEDTLS_VERSION}.tar.bz2"

# ---------------------------------------------------------------------------
# 5. Build-time verification - fail the image build if any guarantee is broken.
# ---------------------------------------------------------------------------
RUN set -eux; \
    # 5a. pkg-config resolves the FROM-SOURCE installs (prefix == /usr/local), \
    #     not an apt copy (forky's apt GnuTLS reports the same 3.8.13 version). \
    test "$(pkg-config --variable=prefix gnutls)" = "/usr/local"; \
    test "$(pkg-config --variable=prefix mbedcrypto)" = "/usr/local"; \
    # 5b. Versions satisfy libjwt's pkg_check_modules floors (and ML-DSA gates). \
    pkg-config --atleast-version=3.8.10 gnutls; \
    pkg-config --atleast-version=3.6.0  mbedcrypto; \
    pkg-config --atleast-version=1.2.0  leancrypto; \
    pkg-config --atleast-version=3.5.0  openssl; \
    echo "openssl    $(pkg-config --modversion openssl)"; \
    echo "gnutls     $(pkg-config --modversion gnutls)"; \
    echo "mbedcrypto $(pkg-config --modversion mbedcrypto)"; \
    echo "leancrypto $(pkg-config --modversion leancrypto)"; \
    # 5c. GnuTLS's static link line resolves its private deps (leancrypto, \
    #     nettle, ...) without error. \
    pkg-config --static --libs gnutls >/dev/null; \
    # 5d. Runtime linker resolves our /usr/local GnuTLS, not the apt one. \
    ldd /usr/local/bin/gnutls-cli | grep -E 'libgnutls\.so' | grep -q '/usr/local/lib'; \
    # 5e. THE decisive check: GnuTLS actually has a PQC provider (leancrypto). \
    #     A stock GnuTLS with no provider fails ML-DSA key-gen with error -106. \
    #     The token is the non-hyphenated 'mldsa87' (certtool figure_key_type). \
    /usr/local/bin/certtool --generate-privkey \
        --key-type=mldsa87 --outfile=/tmp/mldsa87.key; \
    test -s /tmp/mldsa87.key; \
    rm -f /tmp/mldsa87.key; \
    echo "OK: GnuTLS ML-DSA / leancrypto provider verified"

# Sensible default working directory for CI checkouts.
WORKDIR /src
CMD ["/bin/bash"]
