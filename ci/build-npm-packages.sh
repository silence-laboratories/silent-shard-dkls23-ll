#!/bin/sh

set -e

ver=""
scope="@silencelaboratories"

usage() {
    echo "build-npm-packages.sh [ -v version ] [ -s scope ]";
    exit 1
}

while getopts "v:s:" opt; do
    case "${opt}" in
        v)
            ver=${OPTARG}
            ;;
        s)
            scope=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done

if [ -z "${ver}" ]; then
    echo 'pass -v "version"'
    exit 1
fi


build() {
    local suffix="$1"
    local target="$2"

    wasm-pack build \
          -t ${target} \
          -d pkg-${suffix} \
          --out-name dkls-wasm-ll-${suffix} \
          wrapper/wasm-ll

          jq ".name=\"${scope}/dkls-wasm-ll-${suffix}\" | .version=\"${ver}\" | .license=\"SLL\"" \
            < wrapper/wasm-ll/pkg-${suffix}/package.json \
            > wrapper/wasm-ll/pkg-${suffix}/package.json.new

           mv wrapper/wasm-ll/pkg-${suffix}/package.json.new \
              wrapper/wasm-ll/pkg-${suffix}/package.json
}

build "web"  "web"
build "node" "nodejs"
