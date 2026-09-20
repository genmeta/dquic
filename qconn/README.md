# qconn

顺序 TLS 成长与收发接线。`InitialPhase`、`MaturePhase` 只提供发送材料，连接级组件由角色各自的 growing 协程及任务闭包持有。

## 组件归属

- `InitialPhase`：仅有 Initial Space、SCID 和 ODCID；创建它时不分配 Handshake Space。
- `MaturePhase`：通过 qtransport::space::Spaces 保存 initial、handshake、data 三个空间，另持有 SCID、DataStreams、FlowController、可靠帧与确定的 ArcParameters；不保存 InitialPhase 引用。
- `ArcConnPhase`：Initial 只有 Initial space；Connecting 增加 Handshake space；参数齐备进入 Handshaking；客户端收到 HANDSHAKE_DONE 后进入 Mature。每条路径每轮 Burst 重新取快照。
- `client_growing`：接收外部已注册的 Router channel，推进 TLS、连接空间接收拓扑和关闭流程；不添加路径、不启动包发送任务。
- `ClientState`：由外部创建，与客户端成长协程及路径发送任务共享恢复入口、握手状态、关闭状态和路径信息；不提前分配 Handshake/Data space 或参数相关组件。
- `server_growing`：服务端入口仍通过 `started` 提供路径发送入口。
- 路径发送任务：每轮 Burst 读取阶段材料，结合本路径的 ACK、Challenge、Response、心跳及发送约束，依次尝试 Initial、Handshake、Data，再批量发送。Phase 不提供 assemble/send 方法。
- `qtransport::path::Paths`：只登记连接当前的 Path。qconn 生成的 `AddPath` 负责创建 Path 并启动该路径唯一的 detached 发送任务。

## 全局入口

`qprotocol::Dock::global()` 提供唯一的 Dock/Topology；`QuicProtocol::global()` 返回其中的 QUIC 协议实例。

`qtransport::router::QuicRouter::global()` 首次取得时将自己接到全局协议收包入口；也可由外部用 connectless sender 创建独立 Router。全局 listener 通过 `take_connectless_packets()` 取得未知包 receiver。qprotocol 不反向依赖 qtransport。

路由表由 `Signpost` 索引，非空 CID 按 CID 查找，空 CID 按对端地址查找。`packet::channel::new()` 返回 `Inbox` 和 `RcvdPacket`：前者包含四级 sender，后者暴露 `initial / handshake / zero_rtt / one_rtt` 四个 typed receiver。`QuicRouterEntry` 释放时撤销对应路由，旧 entry 不会删除指向另一组 channel 的新路由。`Way` 为 `(Pathway, Link)`；`ReceivedPacket` 用 `Option<usize>` 表示该包是否承担整个 datagram 的收包记账。

`qtransport::router::QuicRouterRegistry` 为 ArcLocalCids 提供 CID 占位注册、撤销和 NEW_CONNECTION_ID 可靠帧投递。growing 从传入的路由守卫取得所属 router，不在 qconn 中另写 registry，也不把独立 router 的 CID 注册到全局实例。

## 使用

客户端调用者准备 TLS context、本地参数、Initial keys、关闭信号和 `qtransport::path::Paths`，向 Router 注册 SCID。`client_sender` 返回由调用者使用的路径发送入口；`client_growing` 接收同一份共享状态及 `(route, rcvd_pkt)`。服务端的原始 DCID 由 listener 通过同一 Router 注册，listener 保留其 entry 至成长协程退出。

```rust,ignore
let phase = ArcConnPhase::new(InitialPhase::new(scid, original_dcid, initial_keys));
let closed = ArcReceiving::default();
let paths = Arc::new(qtransport::path::Paths::default());
let (inbox, rcvd_pkt) = qtransport::packet::channel::new();
let route = QuicRouter::global().insert(scid.into(), inbox);
let state = Arc::new(qconn::ClientState::new(&phase, paths, idle, closed));
let add_path = qconn::client_sender(phase.clone(), state.clone());

// 调用者决定何时添加路径并启动其发送任务，也可保留入口以便后续添加路径。
add_path(pathway)?;
qconn::client_growing(
    phase,
    tls,
    local,
    (route, rcvd_pkt),
    state,
    tokens,
    |result| {
        // 回调只调用一次：TLS 验证后交付身份和连接，失败时交付建连错误。
        deliver(result);
    },
).await;
```

服务端调用 `server_growing` 并传入 `ServerParameters`。双方参数齐备后直接构造 `param::fixed::ArcParameters`，不再使用参数回调。

## 阶段与退出

客户端首先启动 Initial 接收与 TLS/CRYPTO 接线。取得 Handshake keys 后才建立 Handshake space，退役 Initial CRYPTO 两端，启动 Handshake 收包及 CRYPTO 输入。TLS 输出任务等待各 level 的 CRYPTO stream 就绪，不负责组包或发送。

server parameters 到达后才创建可靠帧、成对 CID 管理、DataStreams、FlowController 和 Data space，进入 Handshaking。取得 1-RTT keys 并完成 TLS 验证后退役 Handshake CRYPTO recver、开放 Data 接收并交付应用连接。Handshake CRYPTO sender 保留 Finished 的恢复能力，直到 HANDSHAKE_DONE 才退役并进入 Mature。实际发送 Handshake 包的通知仍用于退役 Initial 包空间。

外层 select 覆盖每次 TLS 等待、HANDSHAKE_DONE 等待和成熟阶段，close 可在任一阶段打断成长。关闭只处理已经建立的空间，不为清理预建 Handshake 或 Data。

客户端的三个 CC feedback 由外部 ClientState 持有。Handshake/Data journal 就绪后由 growing 接线；尚未创建的空间保持 Pending。Phase 不保存 feedback 数组。

Initial、Handshake、1-RTT 各自持有 typed receiver 并独立等待该空间密钥；没有统一 Packet 队列或中间分流任务。Closing 期间这些任务继续接收 CLOSE；Draining 结束后 growing 取消接收任务、淘汰密钥并释放 CID 与路由守卫。额外 ODCID entry 的拥有者在协程退出后释放它。

## 范围

真实 UDP 测试覆盖匿名/双向身份、丢失 ServerHello/Finished、成熟后新增路径及接替原路径、流传输和 detached 任务释放。阶段测试覆盖 Handshake keys 前不创建 Handshake space，以及等待参数、1-RTT keys、HANDSHAKE_DONE 时关闭；交付时检查 Handshake recver 已退役而 sender 仍可用。

0-RTT、Retry、版本协商、Stateless Reset、Endpoint/listener 策略尚未接入。路由提供 0-RTT 队列，但成长协程尚未启用 0-RTT。
