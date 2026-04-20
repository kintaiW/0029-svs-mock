# 多阶段构建：先在完整 Rust 环境编译，再复制二进制到精简镜像
FROM rust:1.75-slim AS builder

WORKDIR /app

# 先复制依赖声明，利用 Docker 缓存层加速重复构建
COPY Cargo.toml Cargo.lock ./
# 创建空 src/main.rs 占位，预先拉取依赖
RUN mkdir src && echo 'fn main(){}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

# 复制完整源码并编译
COPY src/ ./src/
RUN touch src/main.rs && cargo build --release

# ── 运行阶段 ────────────────────────────────
FROM debian:bookworm-slim

# 运行时依赖（libssl、CA 证书）
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制可执行文件和配置
COPY --from=builder /app/target/release/svs-mock /usr/local/bin/svs-mock
COPY mock_certs.toml ./

EXPOSE 9000
CMD ["svs-mock"]
