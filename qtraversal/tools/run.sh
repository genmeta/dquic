#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

image=${TRAVERSAL_IMAGE:-dquic-traversal-test:local}
mkdir -p target/traversal-docker
if [[ ${TRAVERSAL_SKIP_BUILD:-0} != 1 ]]; then
    docker build -t "$image" -f qtraversal/tools/dockerfile qtraversal/tools
    docker run --rm \
        -v "$PWD:/dquic:ro" \
        -v dquic-traversal-registry:/usr/local/cargo/registry \
        -v dquic-traversal-git:/usr/local/cargo/git \
        -v dquic-traversal-target:/build \
        "$image" bash qtraversal/tools/build.sh
fi

# The privileged phase has no Docker network or host network access.
docker run --rm --privileged --network none \
    -v "$PWD:/dquic:ro" \
    -v "$PWD/target/traversal-docker:/logs" \
    -v dquic-traversal-target:/build:ro \
    -e "TRAVERSAL_ATTEMPTS=${TRAVERSAL_ATTEMPTS:-3}" \
    "$image" bash qtraversal/tools/matrix.sh "$@"
