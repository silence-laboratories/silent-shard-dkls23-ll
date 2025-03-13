#
# How to use:
#
# 1. docker build -t wasm-ll --build-arg VER=0.0.0 -f Dockerfile.wasm .
#
# 2. publish packages
#
# docker run --rm -it -e NPM_TOKEN="put-your-token" wasm-ll bash -c \
#     "cd pkg-web; npm publish"
#
# docker run --rm -it -e NPM_TOKEN="put-your-token" wasm-ll bash -c \
#     "cd pkg-node; npm publish"
#

FROM rust@sha256:80ccfb51023dbb8bfa7dc469c514a5a66343252d5e7c5aa0fab1e7d82f4ebbdc as builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq -y && apt-get install -y jq

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    set -e; \
    rustup target add wasm32-unknown-unknown; \
    cargo install wasm-opt; \
    cargo install wasm-pack

WORKDIR /src

COPY . .

ARG VER
ARG SCOPE

RUN ./ci/build-npm-packages.sh -v ${VER}

FROM node:20-bookworm

WORKDIR /pkg

COPY --from=builder /src/wrapper/wasm-ll/pkg-web  ./pkg-web
COPY --from=builder /src/wrapper/wasm-ll/.npmrc   ./pkg-web/.npmrc

COPY --from=builder /src/wrapper/wasm-ll/pkg-node ./pkg-node
COPY --from=builder /src/wrapper/wasm-ll/.npmrc   ./pkg-node/.npmrc

COPY --from=builder /src/wrapper/wasm-ll/pkg-bundler ./pkg-bundler
COPY --from=builder /src/wrapper/wasm-ll/.npmrc   ./pkg-bundler/.npmrc
