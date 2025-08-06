#!/bin/bash
set -e

# 日時の取得
timestamp=$(date +"%Y%m%d-%H%M%S")
pkg_name="nuntium-$timestamp.deb"

# 作業ディレクトリのベース
base_dir=$(pwd)

echo "🔧 Building release binary..."
cargo build --release

echo "📦 Extracting template..."
tar -xzf nuntium-tmp.tar.gz

echo "🚚 Moving binary to ./nuntium/usr/sbin/..."
install -Dm755 target/release/nuntium "$base_dir/nuntium/usr/sbin/nuntium"

echo "📂 Copying service files..."
install -Dm644 ./nuntium.service "$base_dir/nuntium/etc/systemd/system/nuntium.service"

echo "📦 Building .deb package..."
mkdir -p dpkg
dpkg-deb --build "$base_dir/nuntium" "dpkg/$pkg_name"

echo "🧹 Cleaning up temporary directory..."
rm -rf nuntium

echo "✅ Done! Package created at: dpkg/$pkg_name"
