#!/bin/sh

set -e

ver=""
scope="@silencelaboratories"
features=""
name_prefix="dkls-wasm-ll"
dir_prefix="pkg"

usage() {
    echo "build-npm-packages.sh [ -v version ] [ -s scope ] [ -f vrf ]";
    exit 1
}

while getopts "v:s:f:" opt; do
    case "${opt}" in
        v)
            ver=${OPTARG}
            ;;
        s)
            scope=${OPTARG}
            ;;
        f)
            features=${OPTARG}
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

if [ -n "${features}" ]; then
    if [ "${features}" != "vrf" ]; then
        echo "unsupported feature: ${features} (only vrf)"
        exit 1
    fi
    name_prefix="dkls-wasm-ll-vrf"
    dir_prefix="pkg-vrf"
fi

build() {
    local suffix="$1"
    local target="$2"
    local pkg_dir="${dir_prefix}-${suffix}"
    local out_name="${name_prefix}-${suffix}"
    local feature_args=""

    if [ -n "${features}" ]; then
        feature_args="--features ${features}"
    fi

    (cd wrapper/wasm-ll && wasm-pack build \
          -t ${target} \
          -d ${pkg_dir} \
          --out-name ${out_name} \
          ${feature_args})

          jq ".name=\"${scope}/${out_name}\" | .version=\"${ver}\" | .license=\"SLL\"" \
            < wrapper/wasm-ll/${pkg_dir}/package.json \
            > wrapper/wasm-ll/${pkg_dir}/package.json.new

           mv wrapper/wasm-ll/${pkg_dir}/package.json.new \
              wrapper/wasm-ll/${pkg_dir}/package.json
}

build "web"  "web"
build "node" "nodejs"
build "bundler" "bundler"
