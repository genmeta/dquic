#!/usr/bin/env bash
set -euo pipefail

case "${TESTCASE:-}" in
    handshake|transfer|multiconnect) ;;
    *) exit 127 ;;
esac

/setup.sh
mkdir -p /logs
case "${ROLE:-}" in
    client)
        /wait-for-it.sh sim:57832 -s -t 30
        read -r -a params <<< "${CLIENT_PARAMS:-}"
        ;;
    server)
        read -r -a params <<< "${SERVER_PARAMS:-}"
        ;;
    *)
        echo "ROLE must be client or server" >&2
        exit 1
        ;;
esac

exec /usr/local/bin/dquic-interop --keylog "${params[@]}" "$@" > /logs/interop.log 2>&1
