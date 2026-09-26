#!/bin/sh
# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

readonly XMLSEC_VERSION="1.3.12"
readonly XMLSEC_ARCHIVE_SHA256="24045199af12d93fe5fdbbbf7e386e823e4842071e9432e2b90ac108b889a923"
readonly XMLSEC_ARCHIVE_NAME="xmlsec1-${XMLSEC_VERSION}.tar.gz"
readonly XMLSEC_RELEASE_URL="https://github.com/lsh123/xmlsec/releases/download/${XMLSEC_VERSION}/${XMLSEC_ARCHIVE_NAME}"

if [ "$#" -ne 1 ]; then
    echo "usage: install-xmlsec-linux.sh ABSOLUTE_INSTALL_PREFIX" >&2
    exit 2
fi

install_prefix=$1
case "$install_prefix" in
    /*) ;;
    *)
        echo "XMLSec install prefix must be absolute" >&2
        exit 2
        ;;
esac

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/reallyme-xmlsec.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

archive_path="${work_dir}/${XMLSEC_ARCHIVE_NAME}"
curl \
    --fail \
    --location \
    --proto '=https' \
    --retry 3 \
    --show-error \
    --silent \
    --tlsv1.2 \
    --output "$archive_path" \
    "$XMLSEC_RELEASE_URL"

printf '%s  %s\n' "$XMLSEC_ARCHIVE_SHA256" "$archive_path" | sha256sum --check --status
tar -xzf "$archive_path" -C "$work_dir"

source_dir="${work_dir}/xmlsec1-${XMLSEC_VERSION}"
build_dir="${work_dir}/build"
mkdir "$build_dir"
cd "$build_dir"

"${source_dir}/configure" \
    --prefix="$install_prefix" \
    --libdir="${install_prefix}/lib" \
    --disable-apps \
    --disable-crypto-dl \
    --disable-dependency-tracking \
    --disable-dsa \
    --disable-md5 \
    --disable-ripemd160 \
    --disable-sha1 \
    --disable-static \
    --disable-des \
    --enable-shared \
    --with-default-crypto=openssl \
    --with-openssl \
    --without-gcrypt \
    --without-gnutls \
    --without-nss

make -j2
make install

PKG_CONFIG_PATH="${install_prefix}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}" \
    pkg-config --atleast-version="$XMLSEC_VERSION" xmlsec1-openssl
