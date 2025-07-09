# 🏗 ビルドステージ
FROM ubuntu:22.04 AS builder

# 開発環境セットアップ
RUN apt-get update && apt-get install -y \
    curl build-essential pkg-config libssl-dev \
    git iproute2 iputils-ping net-tools sudo \
    && rm -rf /var/lib/apt/lists/*

# rustup + rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY . .

# ビルド（リリースビルド）
RUN cargo build --release

# 🚀 ランタイムステージ
FROM ubuntu:22.04

COPY wait-for-it.sh /usr/local/bin/wait-for-it.sh
RUN chmod +x /usr/local/bin/wait-for-it.sh

RUN apt-get update && apt-get install -y \
    iproute2 iputils-ping net-tools libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/nuntium /usr/local/bin/nuntium

COPY nuntium.conf /etc/nuntium.conf

# CMD は初期動作確認用にヘルプ表示（--mode は docker run 側で指定する）
CMD ["/usr/local/bin/nuntium", "--help"]
