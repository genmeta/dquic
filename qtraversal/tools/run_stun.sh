qtraversal/tools/build_nat.sh
cargo build --example stun_server --release
ip netns exec nss nohup target/release/examples/stun_server --bind-addr1 10.10.0.64:20002 --bind-addr2 10.10.0.64:20003 --change-addr1 10.10.0.66:20003 --change-addr2 10.10.0.66:20002 --outer-addr1 10.10.0.64:20002 --outer-addr2 10.10.0.64:20003 &
ip netns exec nss nohup target/release/examples/stun_server --bind-addr1 10.10.0.66:20002 --bind-addr2 10.10.0.66:20003 --change-addr1 10.10.0.68:20003 --change-addr2 10.10.0.68:20002 --outer-addr1 10.10.0.66:20002 --outer-addr2 10.10.0.66:20003 &
ip netns exec nss nohup target/release/examples/stun_server --bind-addr1 10.10.0.68:20002 --bind-addr2 10.10.0.68:20003 --change-addr1 10.10.0.64:20003 --change-addr2 10.10.0.64:20002 --outer-addr1 10.10.0.68:20002 --outer-addr2 10.10.0.68:20003 &
