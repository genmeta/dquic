#!/usr/bin/env bash
set -euo pipefail
[[ -f /.dockerenv ]] || { echo 'Run through qtraversal/tools/run.sh in Docker' >&2; exit 1; }
source qtraversal/tools/network.sh
trap cleanup_network EXIT
if (( $# > 1 )); then echo 'Usage: run.sh [unit-test-name-filter]' >&2; exit 1; fi
attempts=${TRAVERSAL_ATTEMPTS:-3}
if [[ ! $attempts =~ ^[0-9]+$ ]] || (( attempts < 1 )); then
    echo 'TRAVERSAL_ATTEMPTS must be a positive integer' >&2; exit 1
fi
bin=$(cat /build/traversal-test-bin)
prefix=punch::puncher::network_tests
mapfile -t cases < <("$bin" "${1:-nat_}" --list | sed -n "/^$prefix::nat_.*: test$/s/: test$//p")
(( ${#cases[@]} > 0 )) || { echo 'No matching network unit tests' >&2; exit 1; }
mkdir -p /logs
echo 'test,attempt,result' > /logs/results.csv
echo '11.0.0.1 nat.genmeta.net' >> /etc/hosts

run_case() {
    local test=$1 logs=$2 a_nat b_nat a_public=11.0.0.10 b_public=11.0.0.20
    local name=${test##*::}
    case "$name" in
        nat_rp_rp_*) a_nat=RestrictedPort; b_nat=RestrictedPort ;;
        nat_rp_sym_*) a_nat=RestrictedPort; b_nat=Symmetric ;;
        nat_sym_rp_*) a_nat=Symmetric; b_nat=RestrictedPort ;;
        nat_sym_sym_*) a_nat=Symmetric; b_nat=Symmetric ;;
        *) echo "Unknown topology for $test" >&2; return 1 ;;
    esac
    if [[ $name == *_both_a_larger ]]; then a_public=11.0.0.20; b_public=11.0.0.10; fi
    mkdir -p "$logs"
    setup_network "$a_nat" "$b_nat" "$a_public" "$b_public"
    if [[ $name == *_blocked ]]; then
        ns nat-a iptables -I FORWARD -d "$b_public" -j DROP
        ns nat-b iptables -I FORWARD -d "$a_public" -j DROP
    fi
    ns relay "$bin" --exact "$prefix::stun_service" --ignored --nocapture > "$logs/stun.log" 2>&1 &
    local stun_pid=$! ready=0 poll
    for ((poll = 0; poll < 100; poll++)); do
        if grep -q STUN_READY "$logs/stun.log"; then ready=1; break; fi
        kill -0 "$stun_pid" || return 1
        sleep 0.1
    done
    (( ready )) || { cat "$logs/stun.log"; return 1; }
    ns peers timeout 45 "$bin" --exact "$test" --ignored --nocapture > "$logs/test.log" 2>&1
    kill -0 "$stun_pid"
}

for test in "${cases[@]}"; do
    name=${test##*::}
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        logs="/logs/$name/attempt-$attempt"
        echo "Testing $name (attempt $attempt)"
        set +e
        (set -e; run_case "$test" "$logs")
        status=$?
        set -e
        ns nat-a iptables-save -c > "$logs/nat-a.rules" || true
        ns nat-b iptables-save -c > "$logs/nat-b.rules" || true
        cleanup_network
        if (( status == 0 )); then
            echo "$name,$attempt,PASS" >> /logs/results.csv
            echo "PASS $name (attempt $attempt)"
            break
        fi
        if (( status == 101 && attempt < attempts )) && grep -qx NAT_RANDOM_MISS "$logs/test.log"; then
            echo "$name,$attempt,MISS" >> /logs/results.csv
            echo 'Random port search exhausted; retrying with fresh namespaces'
            continue
        fi
        cat "$logs/"*.log >&2 || true
        echo "$name,$attempt,FAIL" >> /logs/results.csv
        exit 1
    done
done
