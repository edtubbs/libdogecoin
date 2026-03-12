#!/bin/bash

# build depends: contrib/scripts/build.sh --host <host triple> --depends
# build: contrib/scripts/build.sh --host <host triple>

export LC_ALL=C
set -e -o pipefail

if [ $# -eq 0 ]; then
    echo "No arguments provided"
    exit 1
fi

has_param() {
    local term="$1"
    shift
    for arg; do
        if [[ $arg == "$term" ]]; then
            return 0
        fi
    done
    return 1
}

DEPENDS=""
TARGET_HOST_TRIPLET=""
TARGET_ARCH=""
CONFIGURE_OPTIONS=()
PREFIX=""

if [ -f "`pwd`/such*" ]; then
    rm "`pwd`/such*"
fi

if [ -f "`pwd`/sendtx*" ]; then
    rm "`pwd`/sendtx*"
fi

if [ -f "`pwd`/tests*" ]; then
    rm "`pwd`/tests*"
fi

if [ -d "`pwd`/.libs" ]; then
    rm -rf "`pwd`/.libs"
    make clean
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --host)
            TARGET_HOST_TRIPLET="$2"
            shift 2
        ;;
        --depends)
            DEPENDS=1
            shift
        ;;
        *)
            CONFIGURE_OPTIONS+=("$1")
            shift
        ;;
    esac
done

if [ -n "$TARGET_HOST_TRIPLET" ]; then
    case "$TARGET_HOST_TRIPLET" in
        "arm-linux-gnueabihf") 
            TARGET_ARCH="armhf"
        ;;
        "aarch64-linux-gnu")
            TARGET_ARCH="arm64"
        ;;
        "x86_64-w64-mingw32")
            TARGET_ARCH="amd64"
        ;;
        "i686-w64-mingw32")
            TARGET_ARCH="i386"
        ;;
        "x86_64-apple-darwin15")
            TARGET_ARCH="amd64"
        ;;
        "arm64-apple-darwin")
            TARGET_ARCH="arm64"
        ;;
        "x86_64-pc-linux-gnu")
            TARGET_ARCH="amd64"
        ;;
        "i686-pc-linux-gnu")
            TARGET_ARCH="i386"
        ;;
    esac
fi

if [ "$DEPENDS" = "1" ]; then
    if [ -z "$TARGET_HOST_TRIPLET" ]; then
        echo "--depends requires --host <host triple>"
        exit 1
    fi

    DEPENDS_ARGS=("HOST=$TARGET_HOST_TRIPLET")
    if has_param '--enable-liboqs' "${CONFIGURE_OPTIONS[@]}"; then
        DEPENDS_ARGS+=("NO_LIBOQS=")
    fi

    make -C depends "${DEPENDS_ARGS[@]}"

    export PREFIX="`pwd`/depends/$TARGET_HOST_TRIPLET"
    export CONFIG_SITE="$PREFIX/share/config.site"
    export CFLAGS="${CFLAGS:+$CFLAGS }-I$PREFIX/include/"
    export LDFLAGS="${LDFLAGS:+$LDFLAGS }-L$PREFIX/lib/"
    export LD_LIBRARY_PATH="$PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
fi

./autogen.sh
if [ "$DEPENDS" ]; then
    ./configure \
    --prefix="${PREFIX}" \
    --disable-maintainer-mode \
    --disable-dependency-tracking \
    --enable-static \
    --disable-shared \
    "${CONFIGURE_OPTIONS[@]}"
else
    ./configure "${CONFIGURE_OPTIONS[@]}"
fi
make
