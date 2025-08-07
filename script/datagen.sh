#!/usr/bin/env bash

# shellcheck disable=SC2155
declare -r P_ROOT=$(realpath "$(dirname "${BASH_SOURCE[0]}")")

set -e

pushd "${P_ROOT}"

rm -rvf data
mkdir data

pushd data

mkdir dir_{a..c}
for dir in dir_{a..c}; do
    touch "${dir}/${dir}".file_{a..c}
done; unset dir
touch file_{a..c}

find . -type f -exec sh -c 'echo "I am $1" > "$1"' shell "{}" \;

popd

rm -rvf pack unpack
mkdir pack unpack

popd
