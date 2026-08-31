#
# How to use:
#
# 1. docker build -t wasm-ll --build-arg VER=0.0.0 -f Dockerfile .
#
# 2. publish packages
#
# docker run --rm -it -e NPM_TOKEN="put-your-token" wasm-ll bash -c \
#     "cd pkg-web; npm publish"
#
# docker run --rm -it -e NPM_TOKEN="put-your-token" wasm-ll bash -c \
#     "cd pkg-node; npm publish"
#
# docker run --rm -it -e NPM_TOKEN="put-your-token" wasm-ll bash -c \
#     "cd pkg-bundler; npm publish"
#
# docker run --rm -it -e NPM_TOKEN="put-your-token" wasm-ll bash -c \
#     "cd pkg-vrf-web; npm publish"
#
# docker run --rm -it -e NPM_TOKEN="put-your-token" wasm-ll bash -c \
#     "cd pkg-vrf-node; npm publish"
#
# docker run --rm -it -e NPM_TOKEN="put-your-token" wasm-ll bash -c \
#     "cd pkg-vrf-bundler; npm publish"
#

FROM rust:1.88-bookworm as builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq -y && apt-get install -y jq

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    set -e; \
    rustup target add wasm32-unknown-unknown; \
    cargo install wasm-opt; \
    cargo install wasm-pack --version 0.14.0 --locked

WORKDIR /src

COPY . .

ARG VER
ARG SCOPE

RUN ./ci/build-npm-packages.sh -v ${VER} && \
    ./ci/build-npm-packages.sh -v ${VER} -f vrf

FROM node:20-bookworm

WORKDIR /pkg

COPY --from=builder /src/wrapper/wasm-ll/pkg-web  ./pkg-web
COPY --from=builder /src/wrapper/wasm-ll/.npmrc   ./pkg-web/.npmrc

COPY --from=builder /src/wrapper/wasm-ll/pkg-node ./pkg-node
COPY --from=builder /src/wrapper/wasm-ll/.npmrc   ./pkg-node/.npmrc

COPY --from=builder /src/wrapper/wasm-ll/pkg-bundler ./pkg-bundler
COPY --from=builder /src/wrapper/wasm-ll/.npmrc   ./pkg-bundler/.npmrc

COPY --from=builder /src/wrapper/wasm-ll/pkg-vrf-web  ./pkg-vrf-web
COPY --from=builder /src/wrapper/wasm-ll/.npmrc       ./pkg-vrf-web/.npmrc

COPY --from=builder /src/wrapper/wasm-ll/pkg-vrf-node ./pkg-vrf-node
COPY --from=builder /src/wrapper/wasm-ll/.npmrc       ./pkg-vrf-node/.npmrc

COPY --from=builder /src/wrapper/wasm-ll/pkg-vrf-bundler ./pkg-vrf-bundler
COPY --from=builder /src/wrapper/wasm-ll/.npmrc          ./pkg-vrf-bundler/.npmrc
