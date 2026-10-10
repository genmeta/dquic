# qconnection

顺序 TLS 成长与收发接线。`InitialPhase`、`MaturePhase` 只提供发送材料，连接级组件由角色各自的 growing 协程及任务闭包持有。

## 组件归属

- `InitialPhase`：仅有 Initial Space、SCID 和 ODCID；创建它时不分配 Handshake Space。
- `MaturePhase`：通过 qtransport::space::Spaces 保存 initial、handshake、data 三个空间，另持有 SCID、DataStreams、FlowController、可靠帧与确定的 ArcParameters；不保存 InitialPhase 引用。
- `ArcConnPhase`：Initial 只有 Initial space；Connecting 增加 Handshake space；参数齐备进入 Handshaking；客户端收到 HANDSHAKE_DONE 后进入 Mature。每条路径每轮 Burst 重新取快照。
- `Paths`：连接级外部控制项，持有 `ArcConnPhase`、空闲计时、关闭状态、拥塞反馈和当前路径。
- `client_growing`：接收 `Paths` 与外部已注册的 Router channel，推进 TLS、连接空间接收拓扑和关闭流程。
- `server_growing`：从传入的 `Paths` 取得同一份阶段、路径及关闭状态，推进服务端连接。
- 路径发送任务：每轮 Burst 读取阶段材料，结合本路径的 ACK、Challenge、Response、心跳及发送约束，依次尝试 Initial、Handshake、Data，再批量发送。Phase 不提供 assemble/send 方法。
- `Paths::add_path`：创建并登记 `Path`，在 `Path` 上记录是否为握手选中路径，并启动该路径唯一的发送任务。重复添加同一 `Pathway` 返回已有路径。

## 全局入口

`qprotocol::Dock::global()` 提供唯一的 Dock/Topology；`QuicProtocol::global()` 返回其中的 QUIC 协议实例。

`qtransport::router::QuicRouter::global()` 首次取得时将自己接到全局协议收包入口；也可由外部用 connectless sender 创建独立 Router。全局 listener 通过 `take_connectless_packets()` 取得未知包 receiver。qprotocol 不反向依赖 qtransport。

路由表由 `Signpost` 索引，非空 CID 按 CID 查找，空 CID 按对端地址查找。`packet::channel::new()` 返回 `Inbox` 和 `RcvdPacket`：前者包含四级 sender，后者暴露 `initial / handshake / zero_rtt / one_rtt` 四个 typed receiver。`QuicRouter::insert` 插入路由并返回 `QuicRouterRegistry`，由 `LocalCids::clear` 或析构撤销本地 CID 与服务端 ODCID 路由；退休 CID 时不会删除指向另一组 channel 的新路由。`Way` 为 `(Pathway, Link)`；`ReceivedPacket` 用 `Option<usize>` 表示该包是否承担整个 datagram 的收包记账。

`qtransport::router::QuicRouterRegistry` 为 ArcLocalCids 提供 CID 占位注册、撤销和 NEW_CONNECTION_ID 可靠帧投递。服务端用 `insert(signpost, inbox, issued_cids)` 返回的 registry 构造 LocalCids；客户端用 `registry_on_issuing_scid` 构造 registry，无需插入 ODCID 路由。

## 使用

### 具名端点与匿名建连

`Endpoint`、`Option<Endpoint>` 及其 Arc 形式、`Anonymous` 均可通过 `.into()`
构造 `QuicEndpoint`。所有端点统一调用 `QuicEndpoint::connect(server_name)` 建连。
具名端点可监听；匿名端点调用 `listen` 只打印 warn 并返回 `Ok(())`，不注册监听。
`listen` 回调只在握手成功时接收 `Accepted`；握手失败由内部记录日志并关闭清理，
不触发回调。`listen` 自身的 `Result` 仍用于报告本地监听配置错误。

匿名连接不提交客户端证书，但仍验证服务器名称、证书及 OCSP。匿名客户端的
`Connected.0` 为 None，服务端的 `Accepted.0` 为 None；客户端握手失败返回 Err，
无效凭据不会降级为匿名。连接的身份以握手结果为准。

端点字段私有，通过 `set_alpn` 配置 ALPN（同时用于客户端和服务端，默认 `h3`），
通过 `set_parameters(role, id, value)` 配置传输参数。取消尚未交付的 connect future
会请求连接关闭；客户端生命周期停止解析并按现有 Closing/Draining 流程清理路径和 CID。连接交付后
由连接句柄管理生命周期，包括匿名连接。

### 本地多流文件传输测试

在 IPv4 loopback 上建立一条 QUIC 连接，同时打开 1024 条双向流，每条流从客户端
向服务端传输同一个 10 MiB 文件，总计 10 GiB。测试生成临时文件，读取后共享内容，
以 64 KiB 分块发送；每条流就绪后立即传输自己的数据，逐字节验证内容、长度和 EOF，
并逐流返回完成确认。结束时输出耗时和有效载荷吞吐量，删除临时文件并撤销 socket 注册。
使用仓库内的测试证书和本地静态名称解析，不需要另外启动服务端。

此压力测试默认忽略，显式运行：

```sh
cargo test --release -p qconnection --test local_transfer -- --ignored --nocapture
```

默认传输超时为 600 秒，握手超时为 15 秒。可通过 `DQUIC_TEST_TIMEOUT_SECS`
调整传输超时。快速验证可以减少流数量（`1..=1024`，每条流仍传 10 MiB）：

```sh
DQUIC_TEST_STREAMS=4 cargo test -p qconnection --test local_transfer -- --ignored --nocapture
```

可运行的 client/server 示例见 [STUN 与 QUIC 打洞](examples/traversal/README.md)。examples 的 `network` 模块统一扫描网卡、注册 Dock 并探测地址。客户端通过全局 `Resolver::add` 注册解析源，再调用 `QuicEndpoint::connect`；全局 resolver 默认为空。`ArcConnection::validated_paths()` 提供已验证路径快照。

网络所有者通过 `Dock::add(socket)` 登记接收任务及直接 QUIC 地址，额外别名通过 `QuicProtocol::register` 登记。地址发布由所有者显式调用 `AddressBook::insert_inner / insert_outer`；撤回时调用 `AddressBook::remove_bound(bound)`，再从 Dock 移除 socket。Dock 按实际绑定地址调用 `QuicProtocol::unregister(bound)`，撤销该绑定的全部 endpoint。

`QuicEndpoint::connect(server_name)` 将名称传给 `client_growing`，由客户端生命周期启动并持有 DNS 查询任务。查询使用全局 Resolver 的快照调用 `lookup(server_name, "", None)`，持续消费返回的流；每条 DNS 记录与当前 AddressBook 配对后调用 `paths.add_path`，重复 Pathway 复用已有路径。显式端口用于解析，TLS 使用去掉端口的主机名。解析失败或流结束后仍无可用路径时通知连接关闭；客户端在握手失败或连接关闭时取消并等待查询任务退出，再回收路径。服务端不启动 DNS 查询，Paths 仅管理路径。

客户端将 DNS 来源直接交给 `AddressBook::pathways_to(peer, &source)`。AddressBook 使用 `EndpointAddr::matches_peer` 匹配端点类型和地址族，回环与非回环端点在两个方向都不配对；其他 scope 不要求相同，保留私网端点经 NAT 访问公网的候选。客户端检查候选对应的 socket 注册是否仍有效，然后添加路径。mDNS 的 `nic` 精确匹配登记时的网卡名称，缺少网卡信息时跳过候选；其他 DNS 来源也可以返回内网地址。配对时不枚举系统网卡，不根据 IP 推断网卡，也不改写网卡名称。

`insert_inner / insert_outer` 直接接收已创建的 socket，例如 `addresses.insert_inner(&socket, endpoint)`。目录读取其 `local_addr()` 和 `bound_device()`，与端点发布原子地记录绑定信息，不持有 socket。同一绑定的 aliases 必须使用一致的网卡信息；普通 socket 的网卡信息记为未知。冲突会导致登记失败；`remove_bound` 同时清除端点、NAT 和网卡记录。`BindUri` 的解析结果保留 `netdev` 返回的原始网卡名称和索引。后绑定网卡的 `UdpSocket::bind_device` 要求可变引用，并在成功时同步元数据；已发布的绑定需要先撤销再重新登记。

### mDNS 跨仓库约束

- mDNS 实现在独立的 `../ddns` 仓库（包名 `dyns`），本仓库提供解析接口并消费解析结果。
- mDNS 创建、socket 绑定和来源匹配的网卡枚举及标识解析必须统一使用 `netdev`。`Source::Mdns.nic` 与本地绑定必须遵循同一套网卡标识约定。
- mDNS 来源的生成需要在 `ddns` 仓库落实；连接层的去括号等字符串处理不能代替跨仓库的标识一致性。
- 当前 mDNS 入口仍接受调用者传入的名称，上述约束尚需在其实现中落实，不代表已完成跨平台兼容验证。

### 底层接线

客户端调用者准备 TLS context、本地参数、Initial keys 和 `Paths`，向 Router 注册 SCID，并通过 `Paths::add_path` 添加可用路径。`client_growing` 接收同一份 `Paths`。服务端收到第一条 Initial 后创建 `Paths` 并添加来源路径；原始 DCID 仍由 listener 通过同一 Router 注册，listener 保留其 entry 至成长协程退出。

`Paths::new(role, phase, max_idle_timeout, defer_idle_timeout)` 创建连接共享的 `ArcIdleTimer`，并启动等待 `timeout().await` 的任务；超时通过 `close_reason` 进入已有关闭流程。各空间成功收发的所有包都通知该计时器，包括 ACK-only 和 PING。每条路径单独持有 `ArcHeartbeat`，接收真实的 `PacketContent`，并作为 `Package` 参与 Initial、Handshake 和 Data 组包；只有有效载荷更新其活动计时。参数协商后更新连接超时和已有路径的心跳间隔，新路径使用更新后的配置。关闭连接时取消空闲计时和心跳，路径退休时取消该路径的心跳。

客户端和服务端都在创建连接任务时，将成长协程与 `recv::tick(paths.clone())` 放进同一个 `tokio::join!`。直接使用底层成长协程的调用者也需要这样接线；取消连接任务会同时取消 tick。

```rust,ignore
let phase = ArcConnPhase::initial(InitialPhase::new(scid, original_dcid, initial_keys));
let paths = qconnection::Paths::new(Role::Client, phase, max_idle_timeout, defer_idle_timeout);
let (inbox, rcvd_pkt) = qtransport::packet::channel::new();
let cid_registry = QuicRouter::global().registry_on_issuing_scid(inbox, reliable_frames);

paths.add_path(pathway);
let tick = qconnection::recv::tick(paths.clone());
let growing = qconnection::client_growing(
    server_name,
    client_params,
    paths,
    rcvd_pkt,
    tls,
    cid_registry,
    tokens,
    |result| {
        // 回调只调用一次：TLS 验证后交付身份和连接，失败时交付建连错误。
        deliver(result);
    },
);
tokio::spawn(async move { tokio::join!(growing, tick).0 });
```

服务端调用 `server_growing` 并从 SNI 注册项取得服务端参数。双方各自先创建 `param::Requirements`，客户端初始化原始 DCID；Initial 包解密和解析成功后，在交付 CRYPTO 数据前记录包头 SCID。双方参数齐备后构造 `param::ArcParameters`，由 growing 调用 `authenticate_cids(requirements)` 验证 CID，再创建 MaturePhase。Retry 的 CID 记录和校验接口已具备，完整 Retry 握手仍未接入。

## 阶段与退出

客户端首先启动 Initial 接收与 TLS/CRYPTO 接线。取得 Handshake keys 后才建立 Handshake space，退役 Initial CRYPTO 两端，启动 Handshake 收包及 CRYPTO 输入。TLS 输出任务等待各 level 的 CRYPTO stream 就绪，不负责组包或发送。

server parameters 到达后才创建可靠帧、成对 CID 管理、DataStreams、FlowController 和 Data space，进入 Handshaking。取得 1-RTT keys 并完成 TLS 验证后退役 Handshake CRYPTO recver、开放 Data 接收并交付应用连接。Handshake CRYPTO sender 保留 Finished 的恢复能力，直到 HANDSHAKE_DONE 才退役并进入 Mature。客户端实际发送 Handshake 包后退役 Initial 包空间。

外层 select 覆盖每次 TLS 等待、HANDSHAKE_DONE 等待和成熟阶段，close 可在任一阶段打断成长。关闭只处理已经建立的空间，不为清理预建 Handshake 或 Data。

三个 CC feedback 由 `Paths` 持有。各路径发送任务观察阶段变化，在 Handshake/Data journal 就绪后接线；尚未创建的空间保持 Pending。Phase 不保存 feedback 数组。

Initial、Handshake、1-RTT 各自持有 typed receiver 并独立等待该空间密钥；没有统一 Packet 队列或中间分流任务。Closing 期间这些任务继续接收 CLOSE；Draining 结束后 growing 取消接收任务、淘汰密钥并释放 CID 与路由守卫。额外 ODCID entry 的拥有者在协程退出后释放它。

## 范围

### Puncher 接线

客户端和服务端在创建 `MaturePhase` 时各创建并持有一个 `ArcPuncher`，复用连接的可靠帧队列。`ProbeEncoder` 使用同一 Data space 的 1-RTT 密钥、包号和对端 CID。1-RTT 接收流程解密认证后，将 `ADD_ADDRESS`、`REMOVE_ADDRESS`、`PUNCH_ME_NOW`、`PUNCH_HELLO`、`PUNCH_DONE` 交给该 Puncher；后两者保留收到数据报时的实际 `Link`，不从广告地址重建 UDP 地址。

Puncher 不接收 STUN server 参数。`stun` 模块内常量指定 `nat.genmeta.net`；`StunProtocol::global()` 首次初始化时启动唯一的后台任务调用 `StunProtocol::stun_servers()`，该函数用进程内静态缓存保证系统 DNS 只解析一次（端口 `20002`），保存 IPv4/IPv6 地址快照。全局 Dock 的 Topology 复用该 STUN 实例，所有 Puncher 共用解析结果，空结果和错误同样保存，不重试、不定时刷新，等待者取消不影响解析。

接收流程当前先通过 `path_for` 取得或创建路径、记入接收字节，再进行解密认证。认证成功后才接纳新的被动路径（第 7 项）已回退，仍待后续处理。

AddressBook 订阅、路径验证与发送限制、地址撤销后的路径退休和恢复、Puncher 关闭清理仍待完成。

真实 UDP 测试覆盖匿名/双向身份、丢失 ServerHello/Finished、成熟后新增路径及接替原路径、流传输和 detached 任务释放。阶段测试覆盖 Handshake keys 前不创建 Handshake space，以及等待参数、1-RTT keys、HANDSHAKE_DONE 时关闭；交付时检查 Handshake recver 已退役而 sender 仍可用。

0-RTT、Retry、版本协商、Stateless Reset、Endpoint/listener 策略尚未接入。路由提供 0-RTT 队列，但成长协程尚未启用 0-RTT。
