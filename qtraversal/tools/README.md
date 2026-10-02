# qtraversal Docker 网络单元测试

参考原来的 `build_nat.sh` 和固定地址表测试方式：在一个测试进程中构造两个
`ArcPuncher`，可靠帧通过内存通道转发，真实 UDP 探测包经过两个独立 NAT。
所有测试和本地 STUN helper 都在 `qtraversal/src/punch/puncher/network_tests.rs`
的 `#[cfg(test)]` 模块内，不编译或运行 example，不依赖 qconnection。

## 运行

在仓库根目录执行，需要运行中的 Docker：

```sh
bash qtraversal/tools/run.sh
```

脚本编译 `cargo test -p qtraversal --lib` 的测试二进制，先运行普通单元测试，
再像旧 CI 一样用 `--list` 枚举网络用例，在虚拟网络中逐个执行
`--exact <test> --ignored --nocapture`。每个用例使用新进程和新网络，
避免全局 Dock、端口调度配额和 conntrack 在用例间串扰。

按测试名称筛选：

```sh
bash qtraversal/tools/run.sh nat_rp_sym
bash qtraversal/tools/run.sh nat_sym_rp_both_a_larger
```

复用上次编译结果：

```sh
TRAVERSAL_SKIP_BUILD=1 bash qtraversal/tools/run.sh
```

修改 Rust 代码后应重新构建。普通单元测试也可直接执行：

```sh
cargo test -p qtraversal --lib
```

网络测试仅在 Linux 编译，默认标记 ignored；Docker 入口负责准备所需拓扑。
STUN 服务本身是一个单独的 ignored 单元测试，由脚本在独立 namespace 启动并清理。
首次构建需要网络下载镜像、系统包和依赖；实际测试使用 `--network none`，
`nat.genmeta.net` 在容器内指向本地 STUN，不访问线上服务。

## 覆盖范围

A、B 表示两个 Puncher，没有 QUIC client/server 身份。

| A NAT | B NAT | 场景 | 数量 |
| --- | --- | --- | --- |
| RestrictedPort | RestrictedPort | A 主动、B 主动、双主动且 A 较大、双主动且 B 较大 | 4 |
| RestrictedPort | Symmetric | 同上 | 4 |
| Symmetric | RestrictedPort | 同上 | 4 |
| Symmetric | Symmetric | 断言当前策略明确返回 unsupported NAT pair | 1 |
| RestrictedPort | RestrictedPort | 阻断 NAT 间流量，断言没有任何直连成功证据 | 1 |

共 14 个网络测试，另有本地 STUN helper。

单主动场景只给主动端交付对方的 ADD_ADDRESS，被动端通过 PUNCH_ME_NOW 启动。
双主动场景先等待两端都实际发出 PUNCH_ME_NOW，再开放可靠帧交付；直接检查事务实例：
较大端点保留原主动事务，较小端点创建被动事务。
`transaction_tests.rs` 另外覆盖两种请求到达顺序和旧主动任务延迟清理的竞态。

正例同时断言：

1. 两端真实 STUN 分类与测试配置一致。
2. 双方收到经过 NAT 的直接探测报文，事务完成。
3. Symmetric 一端保留获胜的临时 socket。
4. 在该真实 UDP 链路上完成三次完整回显，来源地址与获胜链路一致。

测试的 Encoder 编解码真实 punch frame，用固定测试前缀替代 QUIC 包保护；
可靠通道通过 SendFrame mock 驱动。测试覆盖打洞策略、主被动协商、临时 socket
和 NAT 后的 UDP 可达性，不测试 TLS 握手、QUIC 流及连接层路径验证。

## 虚拟网络

```text
peers namespace（一个 qtraversal 单元测试进程）
  A: eth0 / 192.168.10.2  ---- NAT A: 192.168.10.1 / 11.0.0.10
  B: eth1 / 192.168.20.2  ---- NAT B: 192.168.20.1 / 11.0.0.20
                                         |
                                      wan bridge
                                         |
                             STUN: 11.0.0.1 / .2 / .3
                                    UDP 20002 / 20003
```

与旧脚本一样用源地址策略路由，让两张虚拟网卡各走自己的 NAT，临时 socket
也按绑定 IP 选择路由。测试只广告公网映射，并检查所有探测包的对端地址为另一端
公网 IP，防止走内网捷径。双主动 A 较大的场景交换 `.10` / `.20`。
`11.0.0.0/24` 仅在无外部网络的临时容器内模拟公网。

- RestrictedPort：保持端口的 SNAT/DNAT，入站只允许已建立的 UDP 会话。
- Symmetric：按目标变化的随机 SNAT，没有静态 DNAT；三个 STUN 地址使用
  不重叠端口范围，peer 映射使用完整 `1024–65535` 随机范围。
- 旧单元测试配置使用 KNOCK_TTL=1；在此路由器过滤拓扑下，仅将 TTL=1 的包
  在 NAT 入口恢复为生产配置的 5，确保经过 FORWARD/SNAT 建立端口过滤状态。

暂不覆盖 Dynamic、hairpin、同 LAN 和 IPv6。

## 日志与重试

汇总：`target/traversal-docker/results.csv`。
每次尝试的日志：`target/traversal-docker/<unit-test-name>/attempt-N/`。

- `test.log`：Rust 测试输出、NAT 分类、双主动协商结果和断言失败。
- `stun.log`：本地 STUN 服务输出。
- `nat-a.rules`、`nat-b.rules`：iptables 规则及计数器。

生日碰撞可能随机未命中。只有 Rust 测试确认双方事务结束且完全没有直接探测报文，
并输出 `NAT_RANDOM_MISS` 时，脚本才重新建立网络重试，最多 3 次；其他错误立即失败。
`TRAVERSAL_ATTEMPTS=1` 禁用重试。每次 MISS 和最终结果都保留在汇总中。

退出时清理 namespace、进程和临时容器；日志及三个 `dquic-traversal-*` 构建缓存卷
保留。请串行运行脚本，避免覆盖日志。CI 运行同一入口并在结束后上传日志。
