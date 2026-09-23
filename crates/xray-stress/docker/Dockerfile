# xray-stress Linux 容器镜像。
# 构建（仓库根为 context）：
#   docker build -f crates/xray-stress/docker/Dockerfile -t xray-stress .
# 冒烟（10min 四场景）：
#   docker run --rm --cpus=8 --memory=32g -v "$(pwd)/stress-out:/out" xray-stress \
#     --duration 600 --scenarios s1,s2,s3,s4 --sample-interval 30 --out-dir /out
# 长跑（2-4 天，标准档）：
#   docker run -d --name xray-stress-long --cpus=8 --memory=32g \
#     -v "$(pwd)/stress-out:/out" xray-stress \
#     --duration 345600 --concurrency 8 --s2-conns 4 --sample-interval 30 --out-dir /out
FROM rust:latest

# 编译公式等价物：boringssl cmake 构建链（cmake/nasm/go）+ bindgen（clang/llvm-dev）
# + protobuf（apt 版本随 debian 而异，直接取官方 release 对齐 CI v36.1）
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       cmake nasm pkg-config libssl-dev git python3 golang-go \
       clang llvm-dev libclang-dev unzip xz-utils \
    && curl -fsSL -o /tmp/protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v36.1/protoc-36.1-linux-x86_64.zip \
    && unzip -o /tmp/protoc.zip -d /usr/local \
    && rm /tmp/protoc.zip
ENV PATH="/usr/local/go/bin:${PATH}" \
    PROTOC=/usr/local/bin/protoc \
    CARGO_NET_RETRY=10 \
    CARGO_HTTP_TIMEOUT=120

WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY protos ./protos
COPY tools ./tools
COPY vendor ./vendor
COPY benches ./benches
COPY tests ./tests

# 依赖预取 + 已补丁 boringssl 源码树（与 CI setup-boringssl 同源逻辑）
# 国内网络适配：rsproxy sparse index（Docker Hub/crates.io 直连超时时启用）
RUN mkdir -p /usr/local/cargo \
    && printf '[source.crates-io]\nreplace-with = "rsproxy-sparse"\n[source.rsproxy-sparse]\nregistry = "sparse+https://rsproxy.cn/index/"\n[net]\ngit-fetch-with-cli = true\n' > /usr/local/cargo/config.toml
RUN cargo fetch
# 已补丁 boringssl 源码树：直接注入宿主机 boringssl-fv（boringssl pin + 4 patch +
# REALITY + post-handshake 注入均已应用），绕过容器内 github clone（国内网络超时）。
# 刷新方式：.docker-boringssl/ 由宿主机 BORING_BSSL_SOURCE_PATH 同步（gitignored）。
COPY .docker-boringssl /tmp/boringssl-stress/boringssl

# harness 二进制（-p 只构建所需子树）
RUN BORING_BSSL_ASSUME_PATCHED=1 BORING_BSSL_SOURCE_PATH=/tmp/boringssl-stress/boringssl \
    cargo build --release -p xray-stress

ENV BORING_BSSL_ASSUME_PATCHED=1 \
    BORING_BSSL_SOURCE_PATH=/tmp/boringssl-stress/boringssl
ENTRYPOINT ["/workspace/target/release/xray-stress"]
