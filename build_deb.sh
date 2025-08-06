#!/bin/bash
set -e

timestamp=$(date +"%Y%m%d-%H%M%S")
base_dir=$(pwd)
targets=(
    "x86_64-unknown-linux-gnu:amd64"
    "i686-unknown-linux-gnu:i386"
    "aarch64-unknown-linux-gnu:arm64"
    "armv7-unknown-linux-gnueabihf:armhf"
)

mkdir -p dpkg

for entry in "${targets[@]}"; do
    IFS=":" read -r target arch <<< "$entry"
    echo "🔧 Building for $target..."
    cargo build --release --target "$target"

    echo "📦 Extracting template for $arch..."
    rm -rf nuntium
    tar -xzf nuntium-tmp.tar.gz

    echo "🚚 Moving binary to ./nuntium/usr/sbin/..."
    install -Dm755 "target/$target/release/nuntium" "$base_dir/nuntium/usr/sbin/nuntium"

    echo "📂 Copying service file..."
    install -Dm644 ./nuntium.service "$base_dir/nuntium/etc/systemd/system/nuntium.service"

    echo "🖊️ Writing DEBIAN/control..."
    mkdir -p nuntium/DEBIAN
    cat > nuntium/DEBIAN/control <<EOF
Package: nuntium
Version: 0.1.0
Section: net
Priority: optional
Architecture: $arch
Maintainer: 289CH4n
Description: Nuntium client for encrypted IPv6 overlay network
EOF

    pkg_name="nuntium_${arch}_${timestamp}.deb"
    echo "📦 Building .deb: $pkg_name"
    dpkg-deb --build nuntium "dpkg/$pkg_name"
done

echo "🧹 Cleaning up temporary directory..."
rm -rf nuntium

echo "✅ All .deb packages created in ./dpkg/"
