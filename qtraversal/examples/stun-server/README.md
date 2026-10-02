# 可部署的 dquic STUN 节点

`stun_server` 使用 `qprotocol::StunProtocol`，提供地址映射、换 IP/端口响应，
并可通过 `--relay` 启用 `ForwardProtocol` 中转。报文采用本仓库的 dquic
STUN/Forward 格式。此 example 独立于 `qtraversal` 的 Docker 单元测试。

## 编译与启动

在部署目标 Linux 机器或相同架构的 Linux 构建环境中：

```sh
cargo build --release -p qtraversal --example stun_server
target/release/examples/stun_server --help
```

一台节点监听同一个本地 IP 上的两个 UDP 端口，默认 `20002` 和 `20003`：

```sh
RUST_LOG=info target/release/examples/stun_server \
  --bind-ip 10.0.0.10 \
  --public-ip 198.51.100.10 \
  --change-ip 198.51.100.20 \
  --relay
```

以上是示意地址，部署时替换为实际配置：

- `--bind-ip`：本机网卡实际拥有的具体 IP。
- `--public-ip`：客户端看到的公网 IP；公网 IP 直接配置在网卡上时可省略。
- `--change-ip`：下一台 STUN 节点的公网 IP。
- `--port` / `--alternate-port`：两个不同的非零 UDP 端口。
- `--relay`：启用中转，支持当前 traversal 示例经 agent 完成初始握手。省略时仅提供 STUN。

地址必须同属 IPv4 或 IPv6。程序启动时校验配置并绑定两个 socket，任一监听
失败都会非零退出；全部就绪后输出 `STUN server ready`。
日志写 stdout/stderr，由 `RUST_LOG` 控制。Ctrl-C 和 SIGTERM 会撤销服务、关闭
监听并正常退出；接收循环因 I/O 错误退出时，进程会非零退出供服务管理器重启。

自定义端口可以不连续，例如 `--port 21002 --alternate-port 21007`；三个节点
须使用同一对端口。systemd 部署时在 env 中设置 `STUN_PORT` 和
`STUN_ALTERNATE_PORT`。

### IPv6

支持 IPv6。下面使用文档示意地址，替换为网卡实际地址及下一节点地址后运行：

```sh
target/release/examples/stun_server \
  --bind-ip 2001:db8:1::10 \
  --public-ip 2001:db8:1::10 \
  --change-ip 2001:db8:2::20 \
  --port 21002 --alternate-port 21007 --relay
```

这些参数接收纯 IP，因此 IPv6 不加方括号、也不附带端口。每个进程绑定一个
具体 IP；双栈服务分别启动 IPv4 和 IPv6 进程，换源节点也使用对应地址族。

## 三节点拓扑

完整 NAT 分类需要三个不同公网 IP，每个节点都开放同样的两个 UDP 端口：

| 节点 | public-ip | change-ip |
| --- | --- | --- |
| A | 198.51.100.10 | 198.51.100.20 |
| B | 198.51.100.20 | 198.51.100.30 |
| C | 198.51.100.30 | 198.51.100.10 |

每台节点用自己的实际 `bind-ip` 启动一个进程，配置形成 A→B→C→A。
三个 IP 可以在不同机器，也可以在同一机器上运行三个进程。节点之间须能访问
彼此的两个公网 UDP 端口，客户端也须能访问全部节点。

若机器位于云平台的一对一 NAT 后，两个公网端口分别映射到相同的本地端口，
且出站源端口保持不变。配置节点和客户端所需的 UDP 防火墙/安全组规则。
启用中转时还需允许向客户端的映射地址发送 UDP。

本仓库客户端默认解析 `nat.genmeta.net:20002`，部署替换该服务时将相应 DNS
记录指向这些节点；使用自定义域名或主端口的客户端需显式指定服务地址。

## systemd

目录中提供了 `stun-server.service` 与 `stun-server.env`。在每个节点安装：

```sh
sudo install -d /opt/dquic /etc/dquic
sudo install -m 0755 target/release/examples/stun_server /opt/dquic/stun_server
sudo install -m 0644 qtraversal/examples/stun-server/stun-server.env /etc/dquic/stun-server.env
sudo install -m 0644 qtraversal/examples/stun-server/stun-server.service /etc/systemd/system/stun-server.service
sudoedit /etc/dquic/stun-server.env
sudo systemctl daemon-reload
sudo systemctl enable --now stun-server
sudo journalctl -u stun-server -f
```

先把 env 文件中的三个 IP 和两个端口改成当前节点的实际配置，再启动服务。
unit 使用 systemd 动态普通用户运行，默认端口不需要 root；失败后自动重启。
unit 默认带 `--relay`，仅需 STUN 时从 `ExecStart` 中去掉该参数。

修改 env 中的 IP 或端口后执行 `sudo systemctl restart stun-server`。
修改 unit 文件后，还需先执行 `sudo systemctl daemon-reload`。
升级时先停止服务，再替换 `/opt/dquic/stun_server` 并启动。
