#!/usr/bin/env bash

# Names of latest versions of each package
export VERSION_MUSL=musl-1.1.18
export VERSION_ZLIB=zlib-1.2.11
export VERSION_LIBRESSL=libressl-2.6.3
export VERSION_CURL=curl-7.58.0

# URLs to the source directories
export SOURCE_MUSL=http://www.musl-libc.org/releases/
export SOURCE_LIBRESSL=http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/
export SOURCE_CURL=https://curl.haxx.se/download/
export SOURCE_ZLIB=http://zlib.net/

# Path to local build
export BUILD_DIR=/tmp/curl-static-libressl/build
# Path for libressl
export STATICLIBSSL="${BUILD_DIR}/${VERSION_LIBRESSL}"

function setup() {
    # create and clean build directory
    mkdir -p ${BUILD_DIR}
    rm -Rf ${BUILD_DIR}/*
    # install build environment tools
    apk add linux-headers perl
}

function download_sources() {
    # todo: verify checksum / integrity of downloads!
    echo "Download sources"

    pushd ${BUILD_DIR}

    curl -sSLO "${SOURCE_MUSL}${VERSION_MUSL}.tar.gz"
    curl -sSLO "${SOURCE_ZLIB}${VERSION_ZLIB}.tar.gz"
    curl -sSLO "${SOURCE_LIBRESSL}${VERSION_LIBRESSL}.tar.gz"
    curl -sSLO "${SOURCE_CURL}${VERSION_CURL}.tar.gz"

    popd
}

function extract_sources() {
    echo "Extracting sources"

    pushd ${BUILD_DIR}

    tar -xf "${VERSION_MUSL}.tar.gz"
    tar -xf "${VERSION_LIBRESSL}.tar.gz"
    tar -xf "${VERSION_CURL}.tar.gz"
    tar -xf "${VERSION_ZLIB}.tar.gz"

    popd
}

function compile_musl() {
    echo "Configure & build static musl"

    pushd "${BUILD_DIR}/${VERSION_MUSL}"

    make clean
    ./configure --prefix=/usr/local --disable-shared
    make -j4
    make install
}

function compile_zlib() {
    echo "Configure & build static zlib"

    pushd "${BUILD_DIR}/${VERSION_ZLIB}"

    make clean
    ./configure --static --prefix=/usr/local
    make -j4
    make install
}

function compile_libressl() {
    echo "Configure & build static libressl"

    pushd "${BUILD_DIR}/${VERSION_LIBRESSL}"

    make clean
    ./configure --prefix=/usr/local --enable-shared=no
    make -j4
    make install
}

function compile_curl() {
    echo "Configure & Build curl"

    pushd "${BUILD_DIR}/${VERSION_CURL}"

    make clean

    LIBS="-ldl -lpthread" LDFLAGS="-static" CFLAGS="-no-pie" PKG_CONFIG_FLAGS="--static" PKG_CONFIG_PATH=/usr/local/lib/pkgconfig/ ./configure --disable-shared --enable-static

    make -j4
    make install

    popd
}

echo "Building ${VERSION_CURL} with static ${VERSION_LIBRESSL}, and ${VERSION_ZLIB} ..."

setup && download_sources && extract_sources && compile_musl && compile_zlib && compile_libressl && compile_curl

retval=$?
echo ""
if [ $retval -eq 0 ]; then
    echo "Your curl binary is located at ${BUILD_DIR}/${VERSION_CURL}/src/curl."
    echo "Listing dynamically linked libraries ..."
    ldd ${BUILD_DIR}/${VERSION_CURL}/src/curl
    echo ""
    ${BUILD_DIR}/${VERSION_CURL}/src/curl --version
else
    echo "Ooops, build failed. Check output!"
fi
