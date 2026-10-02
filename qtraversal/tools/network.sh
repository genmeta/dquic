#!/usr/bin/env bash
# Two source-routed interfaces in one test namespace, as in build_nat.sh.

ns() { local name=$1; shift; ip netns exec "$name" "$@"; }

cleanup_network() {
    local name pid
    for name in peers nat-a nat-b relay; do
        for pid in $(ip netns pids "$name" 2>/dev/null); do
            kill "$pid" 2>/dev/null || true
        done
    done
    wait 2>/dev/null || true
    # Processes started by a completed case subshell may still be exiting. Remove
    # the root-side veths explicitly so their names are immediately reusable.
    for name in nat-a nat-b relay; do
        ip link del "v-$name" 2>/dev/null || true
    done
    for name in peers nat-a nat-b relay; do
        ip netns del "$name" 2>/dev/null || true
    done
    ip link del wan 2>/dev/null || true
}

wan_link() {
    local name=$1 address=$2
    ip link add "v-$name" type veth peer name uplink netns "$name"
    ip link set "v-$name" master wan
    ip link set "v-$name" up
    ns "$name" ip link set uplink up
    ns "$name" ip addr add "$address/24" dev uplink
}

nat_link() {
    local peer=$1 subnet=$2 public=$3 mode=$4 device=$5 table=$6
    local router="nat-$peer"
    ip link add "$device" netns peers type veth peer name lan netns "$router"
    ns peers ip addr add "$subnet.2/24" dev "$device"
    ns peers ip link set "$device" up
    ns peers ip route add "$subnet.0/24" dev "$device" table "$table"
    ns peers ip route add default via "$subnet.1" dev "$device" table "$table"
    ns peers ip rule add from "$subnet.2" table "$table"
    ns "$router" ip addr add "$subnet.1/24" dev lan
    ns "$router" ip link set lan up
    wan_link "$router" "$public"
    ns "$router" sysctl -qw net.ipv4.ip_forward=1
    # qtraversal unit builds use KNOCK_TTL=1 for the old host-side filter topology.
    # Restore the production TTL before forwarding and confirming the SNAT flow.
    ns "$router" iptables -t mangle -A PREROUTING -i lan -p udp \
        -m ttl --ttl-eq 1 -j TTL --ttl-set 5
    ns "$router" iptables -P FORWARD DROP
    # Reject LAN-to-LAN routing; only the emulated public WAN is reachable.
    ns "$router" iptables -A FORWARD -i lan ! -d 11.0.0.0/24 -j DROP
    if [[ $mode == Symmetric ]]; then
        # Disjoint STUN ranges make endpoint-dependent mapping unambiguous.
        # Peer traffic uses the entire unprivileged port range with random SNAT.
        for index in 1 2 3; do
            ns "$router" iptables -t nat -A POSTROUTING -s "$subnet.2" -o uplink \
                -d "11.0.0.$index" -p udp -j SNAT \
                --to-source "$public:$((index * 10000))-$((index * 10000 + 9999))" --random-fully
        done
        ns "$router" iptables -t nat -A POSTROUTING -s "$subnet.2" -o uplink \
            -p udp -j SNAT --to-source "$public:1024-65535" --random-fully
        # Unmapped collision probes should be silently filtered.
        ns "$router" iptables -A INPUT -i uplink -p udp -j DROP
    else
        ns "$router" iptables -t nat -A POSTROUTING -s "$subnet.2" -o uplink \
            -p udp -j SNAT --to-source "$public"
        ns "$router" iptables -t nat -A PREROUTING -d "$public" -i uplink \
            -p udp -j DNAT --to-destination "$subnet.2"
    fi
    case "$mode" in
        FullCone)
            ns "$router" iptables -A FORWARD -i uplink -o lan -p udp -j ACCEPT
            ;;
        RestrictedCone)
            ns "$router" iptables -A FORWARD -i lan -o uplink -p udp \
                -m recent --name contacted --rdest --set -j ACCEPT
            ns "$router" iptables -A FORWARD -i uplink -o lan -p udp \
                -m recent --name contacted --rsource --rcheck --seconds 300 -j ACCEPT
            ;;
        RestrictedPort|Symmetric)
            ns "$router" iptables -A FORWARD -i uplink -o lan -p udp \
                -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            ;;
        *) echo "Unknown NAT mode: $mode" >&2; return 1 ;;
    esac
    ns "$router" iptables -A FORWARD -i lan -o uplink -p udp -j ACCEPT
}

setup_network() {
    local name a_public=$3 b_public=$4
    for name in peers nat-a nat-b relay; do
        ip netns add "$name"
        ns "$name" ip link set lo up
    done
    ip link add wan type bridge
    ip link set wan up
    wan_link relay 11.0.0.1
    ns relay ip addr add 11.0.0.2/24 dev uplink
    ns relay ip addr add 11.0.0.3/24 dev uplink
    nat_link a 192.168.10 "$a_public" "$1" eth0 101
    nat_link b 192.168.20 "$b_public" "$2" eth1 102
    ns peers sysctl -qw net.ipv4.conf.all.rp_filter=0
    ns peers sysctl -qw net.ipv4.conf.eth0.rp_filter=0
    ns peers sysctl -qw net.ipv4.conf.eth1.rp_filter=0
}
