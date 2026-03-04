#!/bin/bash
set -e

MIN_VERSION="${OPENSSL_MIN_VERSION:-0x30200000}"

if ! command -v pkg-config &>/dev/null; then
    echo "no"
    exit 0
fi

if ! pkg-config --exists openssl 2>/dev/null; then
    echo "no"
    exit 0
fi

VERSION_HEX=$(pkg-config --modversion openssl 2>/dev/null | while IFS=. read -r major minor patch; do
    printf "0x%02x%02x%02x00\n" "$major" "$minor" "${patch:-0}"
done)

if [ -z "$VERSION_HEX" ]; then
    echo "no"
    exit 0
fi

if [ "$VERSION_HEX" -ge "$MIN_VERSION" ] 2>/dev/null; then
    echo "yes"
else
    echo "no"
fi