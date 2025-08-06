#!/usr/bin/env bash
set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGETS=(
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
    "x86_64-unknown-linux-gnu"
    "i686-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
    "armv7-unknown-linux-gnueabihf"
)

export CARGO_TARGET_DIR="$PROJECT_DIR/target"

# macOS targets with osxcross
export CC_x86_64_apple_darwin="/home/tsubaki/osxcross/target/bin/o64-clang"
export CC_aarch64_apple_darwin="/home/tsubaki/osxcross/target/bin/aarch64-apple-darwin23.5-clang"
export CFLAGS_aarch64_apple_darwin="-arch arm64 -mmacosx-version-min=14.5"
export CFLAGS_x86_64_apple_darwin="-arch x86_64 -mmacosx-version-min=10.13"

for TARGET in "${TARGETS[@]}"; do
    echo "🔧 Building for $TARGET..."
    cargo build --release --target "$TARGET"
done

echo "✅ All builds completed!"
