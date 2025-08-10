FROM ubuntu:22.04

# 必要なパッケージのインストール（実行に必要なものだけ）
RUN apt-get update && apt-get install -y \
    iproute2 iputils-ping net-tools libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# wait-for-it.sh をコピー（存在する場合）
COPY wait-for-it.sh /usr/local/bin/wait-for-it.sh
COPY scripts/tcp_tune.sh /usr/local/bin/tcp_tune.sh
RUN chmod +x /usr/local/bin/wait-for-it.sh /usr/local/bin/tcp_tune.sh

# ビルド済みのバイナリをコピー（debug モードの例）
COPY ./target/debug/nuntium /usr/local/bin/nuntium

# 設定ファイルをコピー（存在する場合）
COPY nuntium.conf /opt/nuntium/nuntium.conf

# デフォルトコマンド（オプションとしてヘルプ表示）
ENTRYPOINT ["/usr/local/bin/tcp_tune.sh"]
CMD ["/usr/local/bin/nuntium", "--help"]
