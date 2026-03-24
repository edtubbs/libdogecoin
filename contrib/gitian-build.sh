#!/bin/bash

# inspired by the work of @patricklodder for gitian building dogecoin core as found below:
# https://gist.github.com/patricklodder/88d6c4e3406db840963f85d95ceb44fe
# usage: ./gitian-build.sh --mem=8000 --proc=2 --commit=0.1-dev-rc1 --url=https://github.com/xanimo/libdogecoin --sign=xanimo --docker --codesign-win --codesign-macos

export LC_ALL=C
set -e -o pipefail

if [ $# -eq 0 ]; then
    echo "No arguments provided"
    exit 1
fi

check_error() {
    if [ "$ERROR" ]; then
        echo "Please provide a commit or tag to build and try again."
        exit $ERROR
    fi
}

help()
{
    echo "Usage: build 
               [ -c | --commit ]
               [ --codesign-macos ]
               [ --codesign-win ]
               [ --docker ]
               [ --lxc ]
               [ -m | --mem ]
               [ --macos-keychain ]
               [ --macos-team-id ]
               [ -p | --proc ]
               [ -s | --sign ]
               [ -t | --tag ]
               [ -u | --url ]
               [ --windows-cert-file ]
               [ --windows-cert-password ]
               [ -h | --help  ]"
    exit 2
}

BUILD_SUFFIX="`pwd`/gitian/builds"
DESCRIPTORS=('osx' 'win' 'linux')

export USE_DOCKER=0
export USE_LXC=0
export CODESIGN_WIN=0
export CODESIGN_MACOS=0

sign_windows_targets() {
    if [ "$CODESIGN_WIN" -ne 1 ]; then
        echo "[sign-win] skipped: --codesign-win not enabled"
        return 0
    fi

    local cert_file="${WINDOWS_CERT_FILE:-${LIBDOGECOIN_DEV_WINDOWS_CERT_PATH}}"
    local cert_password="${WINDOWS_CERT_PASSWORD:-${LIBDOGECOIN_DEV_WINDOWS_CERT_PASSWORD}}"

    if ! command -v osslsigncode >/dev/null 2>&1; then
        echo "osslsigncode is required for --codesign-win"
        exit 1
    fi

    if [ -z "$cert_file" ] || [ -z "$cert_password" ]; then
        echo "Windows code signing requires --windows-cert-file and --windows-cert-password (or LIBDOGECOIN_DEV_WINDOWS_CERT_PATH/LIBDOGECOIN_DEV_WINDOWS_CERT_PASSWORD)."
        exit 1
    fi

    echo "[sign-win] enabled: cert file present, scanning zips in ${BUILD_SUFFIX}"

    # Create an OpenSSL config that enables the legacy provider so that
    # osslsigncode can read PKCS#12 files encrypted with RC2-40-CBC
    # (common in older / "legacy" code-signing certificates).
    local legacy_conf
    legacy_conf=$(mktemp)
    # This config is consumed through OPENSSL_CONF only for the signing
    # command below; it does not modify the runner's global OpenSSL config.
    cat > "$legacy_conf" <<'OSSL_CONF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
OSSL_CONF

    for zip_file in "${BUILD_SUFFIX}"/libdogecoin-*.zip; do
        [ -e "$zip_file" ] || continue
        echo "[sign-win] processing zip: $(basename "$zip_file")"
        workdir=$(mktemp -d)
        unzip -q "$zip_file" -d "$workdir"
        signed_any=0

        for exe_target in spvnode.exe such.exe sendtx.exe; do
            exe_path=$(find "$workdir" -type f -name "$exe_target" | head -n 1)
            if [ -n "$exe_path" ]; then
                echo "[sign-win] signing binary: $exe_target"
                # OPENSSL_CONF loads the legacy provider so osslsigncode can
                # read older PKCS#12 files (e.g. RC2-40-CBC encrypted certs).
                OPENSSL_CONF="$legacy_conf" osslsigncode sign \
                    -pkcs12 "$cert_file" \
                    -pass "$cert_password" \
                    -n "libdogecoin" \
                    -i "https://github.com/dogecoinfoundation/libdogecoin" \
                    -in "$exe_path" \
                    -out "${exe_path}.signed"
                mv "${exe_path}.signed" "$exe_path"
                echo "[sign-win] signed binary: $exe_target"
                signed_any=1
            fi
        done

        if [ "$signed_any" -eq 1 ]; then
            (
                cd "$workdir"
                zip -X -r -q "${zip_file}.signed" .
            )
            mv "${zip_file}.signed" "$zip_file"
            echo "[sign-win] replaced zip with signed contents: $(basename "$zip_file")"
        else
            echo "[sign-win] no signable binaries found in: $(basename "$zip_file")"
        fi
        rm -rf "$workdir"
    done

    # Remove temporary OpenSSL provider config after signing completes.
    rm -f "$legacy_conf"
}

sign_macos_targets() {
    if [ "$CODESIGN_MACOS" -ne 1 ]; then
        echo "[sign-macos] skipped: --codesign-macos not enabled"
        return 0
    fi

    local team_id="${MACOS_TEAM_ID:-${LIBDOGECOIN_DEV_APPLE_TEAM_ID}}"
    local keychain_path="${MACOS_KEYCHAIN:-${HOME}/Library/Keychains/build.keychain}"

    if ! command -v codesign >/dev/null 2>&1; then
        echo "codesign is required for --codesign-macos"
        exit 1
    fi

    if [ -z "$team_id" ]; then
        echo "macOS code signing requires --macos-team-id (or LIBDOGECOIN_DEV_APPLE_TEAM_ID)."
        exit 1
    fi

    echo "[sign-macos] enabled: team id present, scanning tarballs in ${BUILD_SUFFIX}"

    for tar_file in "${BUILD_SUFFIX}"/libdogecoin-*.tar.gz; do
        [ -e "$tar_file" ] || continue
        echo "[sign-macos] processing tarball: $(basename "$tar_file")"
        workdir=$(mktemp -d)
        tar -xzf "$tar_file" -C "$workdir"
        signed_any=0

        for mac_target in spvnode such sendtx; do
            mac_path=$(find "$workdir" -type f -name "$mac_target" | head -n 1)
            if [ -n "$mac_path" ]; then
                echo "[sign-macos] signing binary: $mac_target"
                /usr/bin/codesign --force --keychain "$keychain_path" -s "$team_id" --deep --options=runtime --verbose "$mac_path"
                echo "[sign-macos] signed binary: $mac_target"
                signed_any=1
            fi
        done

        if [ "$signed_any" -eq 1 ]; then
            tar -czf "${tar_file}.signed" -C "$workdir" .
            mv "${tar_file}.signed" "$tar_file"
            echo "[sign-macos] replaced tarball with signed contents: $(basename "$tar_file")"
        else
            echo "[sign-macos] no signable binaries found in: $(basename "$tar_file")"
        fi
        rm -rf "$workdir"
    done
}

for i in "$@"
do
case $i in
    -c=* | --commit=* )
      export COMMIT="${i#*=}"
    ;;
    --codesign-macos )
      export CODESIGN_MACOS=1
    ;;
    --codesign-win )
      export CODESIGN_WIN=1
    ;;
    --docker )
      export USE_DOCKER=1
    ;;
    --help )
        help
    ;;
    --lxc )
      export USE_LXC=1
    ;;
    -m=* | --mem=* )
      export MEM="${i#*=}"
      ;;
    --macos-keychain=* )
      export MACOS_KEYCHAIN="${i#*=}"
      ;;
    --macos-team-id=* )
      export MACOS_TEAM_ID="${i#*=}"
      ;;
    -p=* | --proc=* )
      export PROC="${i#*=}"
      ;;
    -s=* | --sign=* )
      export SIGNER="${i#*=}"
      ;;
    -t=* | --tag=* )
      export TAG="${i#*=}"
    ;;
    -u=* | --url=* )
      export URL="${i#*=}"
      ;;
    --windows-cert-file=* )
      export WINDOWS_CERT_FILE="${i#*=}"
      ;;
    --windows-cert-password=* )
      export WINDOWS_CERT_PASSWORD="${i#*=}"
      ;;
    *)
        ERROR=1
    ;;
esac
done

check_error

if [ ! "$USE_LXC" ] && [ ! "$USE_DOCKER" ]; then
    echo "Please choose either --docker or --lxc and try again."
    exit 1
fi

# allow either tag or commit for git repositories
if [ "$TAG" ] && [ "$COMMIT" ]; then
    echo "Please specify only a commit or a tag and try again."
    exit 1
else
    if [ "$TAG" ]; then
        # logic may need refining
        if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
            echo "$TAG is a legitimate commit"
            # git tag -f -s $TAG -m "$TAG"
        else
            echo "$TAG does not exist. Exiting..."
            exit 1
            # git tag -s $TAG -m "$TAG"
        fi
        COMMIT="v$TAG"
    fi
    BUILD_SUFFIX=$BUILD_SUFFIX/$COMMIT
fi
export COMMIT=$COMMIT

if [ ! -d "gitian" ]; then
    mkdir -p gitian
fi

pushd gitian
if [ ! -d "gitian-builder" ]; then
    git clone https://github.com/devrandom/gitian-builder.git
fi

if [ ! -d "libdogecoin" ]; then
    git clone $URL
fi

pushd libdogecoin
    git checkout ${COMMIT}
popd

pushd gitian-builder
if [ ! -d "patches" ]; then
    mkdir -p patches
fi

if [ ! -f "patches/fix-mirror_base.patch" ]; then
    wget -P patches https://gist.githubusercontent.com/xanimo/aeb7d031bc5ced761f8b2a28af3779ae/raw/241426ddcf5d272e02fe2b9fd7019afddea0f67a/fix-mirror_base.patch
    git apply patches/fix-mirror_base.patch
fi

if [ "$USE_DOCKER" ]; then
    bin/make-base-vm --docker --suite focal --arch amd64
elif [ "$USE_LXC" ]; then
    bin/make-base-vm --lxc --suite focal --arch amd64
fi

if [ ! -d "inputs" ]; then
    mkdir -p inputs
fi

if [ ! -f "inputs/osslsigncode-Backports-to-1.7.1.patch" ]; then
    wget -P inputs https://depends.dogecoincore.org/osslsigncode-Backports-to-1.7.1.patch
fi

if [ ! -f "inputs/osslsigncode_1.7.1.orig.tar.gz" ]; then
    wget -P inputs https://depends.dogecoincore.org/osslsigncode_1.7.1.orig.tar.gz
fi

if [ ! -f "inputs/Xcode-12.2-12B45b-extracted-SDK-with-libcxx-headers.tar.gz" ]; then
    wget -P inputs https://bitcoincore.org/depends-sources/sdks/Xcode-12.2-12B45b-extracted-SDK-with-libcxx-headers.tar.gz
fi

make -C ../libdogecoin/depends download SOURCES_PATH=`pwd`/cache/common

if [ ! -d "${BUILD_SUFFIX}" ]; then
    mkdir -p ${BUILD_SUFFIX}
fi

./bin/gbuild -m ${MEM} -j ${PROC} --commit libdogecoin=${COMMIT} --url libdogecoin=${URL} ../libdogecoin/contrib/gitian-descriptors/gitian-linux.yml
if [ "$SIGNER" ]; then
./bin/gsign --signer "$SIGNER" --release "$COMMIT"-"linux" \
                --destination ${BUILD_SUFFIX}/sigs/ ../libdogecoin/contrib/gitian-descriptors/gitian-linux.yml 2>&- || \
                echo "$0: Error on signature, detached signing"
fi
mv build/out/src/libdogecoin-*.tar.gz ${BUILD_SUFFIX}

./bin/gbuild -m ${MEM} -j ${PROC} --commit libdogecoin=${COMMIT} --url libdogecoin=${URL} ../libdogecoin/contrib/gitian-descriptors/gitian-win.yml
if [ "$SIGNER" ]; then
./bin/gsign --signer "$SIGNER" --release "$COMMIT"-"win" \
                --destination ${BUILD_SUFFIX}/sigs/ ../libdogecoin/contrib/gitian-descriptors/gitian-win.yml 2>&- || \
                echo "$0: Error on signature, detached signing"
fi
mv build/out/src/libdogecoin-*.zip ${BUILD_SUFFIX}

./bin/gbuild -m ${MEM} -j ${PROC} --commit libdogecoin=${COMMIT} --url libdogecoin=${URL} ../libdogecoin/contrib/gitian-descriptors/gitian-osx.yml
if [ "$SIGNER" ]; then
./bin/gsign --signer "$SIGNER" --release "$COMMIT"-"osx" \
                --destination ${BUILD_SUFFIX}/sigs/ ../libdogecoin/contrib/gitian-descriptors/gitian-osx.yml 2>&- || \
                echo "$0: Error on signature, detached signing"
fi
mv build/out/src/libdogecoin-*.tar.gz ${BUILD_SUFFIX}

popd

sign_windows_targets
sign_macos_targets

pushd $BUILD_SUFFIX
if [ -f "checksums.txt" ]; then
    rm checksums.txt
fi
sha256sum *.tar.gz > checksums.txt
sha256sum *.zip >> checksums.txt
cat checksums.txt
popd
