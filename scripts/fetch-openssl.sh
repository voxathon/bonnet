#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CACHE_DIR="${PROJECT_ROOT}/.cache/openssl"
VERSION_FILE="${PROJECT_ROOT}/.openssl-version"

if [ ! -f "$VERSION_FILE" ]; then
    echo "Error: .openssl-version file not found" >&2
    exit 1
fi

source "$VERSION_FILE"

CACHE_PATH="${CACHE_DIR}/${OPENSSL_VERSION}"
MARKER_FILE="${CACHE_PATH}/.extracted"

if [ -f "$MARKER_FILE" ]; then
    echo "OpenSSL ${OPENSSL_VERSION} already cached at ${CACHE_PATH}"
    exit 0
fi

echo "Downloading OpenSSL ${OPENSSL_VERSION}..."

mkdir -p "$CACHE_PATH"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

download_and_verify() {
    local filename="$1"
    local expected_hash="$2"
    local url="${UBUNTU_MIRROR}/pool/main/o/openssl/${filename}"
    local dest="${TMPDIR}/${filename}"

    echo "Downloading ${filename}..."
    curl -fsSL -o "$dest" "$url"

    echo "Verifying SHA256..."
    actual_hash=$(sha256sum "$dest" | cut -d' ' -f1)

    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "Error: SHA256 mismatch for ${filename}" >&2
        echo "Expected: ${expected_hash}" >&2
        echo "Got:      ${actual_hash}" >&2
        exit 1
    fi

    echo "SHA256 verified OK"
}

extract_deb() {
    local deb_file="$1"
    local output_dir="$2"

    echo "Extracting ${deb_file}..."

    cd "$TMPDIR"
    ar x "$deb_file"
    tar -xf data.tar.xz -C "$output_dir" 2>/dev/null || tar -xf data.tar.zst -C "$output_dir" 2>/dev/null || {
        echo "Error: Could not extract .deb file (unsupported compression)" >&2
        exit 1
    }
}

download_and_verify "$LIBSSL_DEV_DEB" "$LIBSSL_DEV_SHA256"
download_and_verify "$LIBSSL_DEB" "$LIBSSL_SHA256"

extract_deb "${TMPDIR}/${LIBSSL_DEB}" "$CACHE_PATH"
extract_deb "${TMPDIR}/${LIBSSL_DEV_DEB}" "$CACHE_PATH"

touch "$MARKER_FILE"

echo ""
echo "OpenSSL ${OPENSSL_VERSION} successfully cached at:"
echo "  ${CACHE_PATH}"
echo ""
echo "Include path:  ${CACHE_PATH}/usr/include"
echo "Library path:  ${CACHE_PATH}/usr/lib/x86_64-linux-gnu"