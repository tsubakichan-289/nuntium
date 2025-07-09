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

# ビルド（--releaseでもOK）
RUN cargo build --release

# 🚀 ランタイムステージ
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    iproute2 iputils-ping net-tools libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# ビルドしたバイナリだけコピー
COPY --from=builder /app/target/release/nuntium /usr/local/bin/nuntium

# 必要な特権は docker run 時に付与
CMD ["/usr/local/bin/nuntium", "--help"]

