# qtransport

握手成功的 QUIC 连接 API 与数据传输组件。依赖 qtls、qprotocol、qbase、qrecovery、qcongestion；不依赖 qconn 或 qconnection。

## 应用 API

从 crate 根导入 `ArcConnection`、`StreamReader`、`StreamWriter`、`StreamId`、`ArcParameters`、`Role`、`VarInt`、`Error`、`StreamError`、`StopSending`、`CancelStream` 即可。

| 方法 | 结果与语义 |
| --- | --- |
| `role()` / `alpn()` / `parameters()` | 同步只读；ALPN 是协商选中的单个字节串 |
| `open_bi_stream().await` | `Result<Option<(StreamId, (StreamReader, StreamWriter))>, Error>` |
| `open_uni_stream().await` | `Result<Option<(StreamId, StreamWriter)>, Error>` |
| `accept_bi_stream().await` | `Result<(StreamId, (StreamReader, StreamWriter)), Error>` |
| `accept_uni_stream().await` | `Result<(StreamId, StreamReader), Error>` |
| `close(self, code, reason)` | 消费一个句柄，终止全部克隆与已有流的业务使用 |

流数量额度不足时 `open` 等待；`None` 只表示流编号耗尽。每个方向使用一个 `accept` 循环。
取消等待不取走流。正常流结束/重置不会关闭连接。关闭唤醒开流、接流及未完成流的读写等待者，保留原错误与固定参数。已收齐的流可继续读完至 EOF，已完成发送的流保留原终态。
使用独立读写端期间保留至少一个连接句柄；最后一个句柄释放会关闭业务，协议任务只持有 Transport 或组件。

## 协议集成

这些模块是 qconn 的构建接口，不是额外的应用连接 API：

| 模块 | 责任 |
| --- | --- |
| `transport` | 保存确定性传入的 Data Space、参数、streams、flow、可靠帧、Paths；只有业务关闭入口 |
| `space` | 每空间独立的恢复记录、CRYPTO 和不可复活的收发许可；没有父级回指 |
| `keys` | Pending / Waiting(Waker) → Ready → Retired、异步就绪、1-RTT 代次、认证与 AEAD 用量；OpenPacket、SealPacket、私有 open_with 包保护基础实现 |
| `router` | QuicRouter：CID → 有界 inbox，未知 Initial 进入有界新连接队列 |
| `recv` | run / route_packets / run_receive / receive_packet / frame_dispatcher；通过闭包接入组件 |
| `path` | 每路径一个 CC、路径验证/重试、反放大信用、按实例退役 |
| `send` | 每路径一个 Sender；独立的 `acknowledge` 函数供原组件管道捕获 |
| `send/packet` | 自持 buffer 的 OneRttPacket、异构 Package 源、消费式 seal |
| `send/records` | 永不归还的 PN、有限恢复记录、实际提交顺序、按发送路径归属 ACK |

建立连接的外部驱动按以下顺序工作：

1. 创建 QuicRouter，将 qprotocol 接收回调接到 receive；qconn 消费 `(original_dcid, packet_receiver)` 新连接入口。客户端预建有界 channel，用 insert 注册自己的 CID。
2. 创建各 Space、keys 和 Path。Space/Path 使用同一个 submission 短同步边界；ArcKeys 只持有密钥状态锁，不再传入 submission。KeyState、ArcKeys 实现 Future<Output = Option<K>>，用单读者 Waker 等待材料；Ready 返回克隆句柄，Retired 返回 None。取得密钥后直接使用 opening/sealing；收包用具体解密函数接线，不再有 ReceiveKeys 或 with_ready/is_ready。
3. 用 recv 函数接线：route_packets 只分流，run_receive 分层解密/去重，frame_dispatcher 捕获已有组件。全部组件就绪时可用 run 在同一协程内驱动这条链路；轻量握手阶段由 qconn 用下层函数和闭包组合。
4. 参数成型后准备 streams/flow，TLS 允许处理 Data 时安装其密钥。成熟时同一批组件传给 Transport，选定 ALPN 和同一个 closing 开关传给 ArcConnection::new；构造函数不重复握手校验。
5. 安装 1-RTT 后通过 await 取得 OneRttKeys，克隆传给 Sender::new(keys, transport, path)。每路径唯一发送任务使用 Sender::prepare / poll_send 与握手发送协调，或驱动 Sender::run。
6. 应用关闭、接收错误、对端 CLOSE 切换 Connection 共享的 closing；同一收包引擎继续解密，只投递 CLOSE。原组件唤醒 accept/open/流读写并返回错误。qconn 负责 Closing/Draining、取消任务，以及 remove_connection 删除此 inbox 的全部 CID。

Initial/Handshake 实例、TLS、角色淘汰规则、关闭发送与定时器、CID/token 管理实例由外部驱动持有；QuicRouter 实现已经在 qtransport，运行实例由外部持有，无隐式全局变量。

1-RTT 密钥分为固定的 `HeaderKeys { opening, sealing }` 和共享的 `OneRttPacketKeys`。
`qtls::DirectionalKeys` 与 `OneRttKeys` 均实现 `keys::OpenPacket`、`keys::SealPacket`，
分别提供 `open`、`seal`。`open` 统一接收 PTO，固定密钥忽略它；`SealPacket::Output`
分别为 `()` 和 `(u64, KeyPhaseBit)`。两类 `open` 共用本模块的私有函数 `open_with`，仅接收 `decode_pn` 闭包；
journal 在接线处捕获，不传入密钥层。使用扩展方法分别导入 `OpenPacket`、`SealPacket`。
`ArcOneRttKeys.await` 返回 `Option<OneRttKeys>`，Data 接收接入 `OneRttKeys::open`。
`OneRttKeys::open/seal` 负责头保护，内部 `OneRttPacketKeys::decrypt/encrypt` 负责 AEAD、
密钥代次和用量。`update/allow_update/on_ack/with_generation/seal/tag_len` 均属于已就绪的
`OneRttKeys`；`ArcOneRttKeys` 只安装、等待和淘汰，不提供密钥操作的转调。包对象只提供
buffer 与布局。Data ACK 回调捕获本次解密的就绪材料；Space 的停止开关阻止淘汰后发送。
包密钥用一个 `VecDeque` 保存成对的 opening/sealing，队尾 sealing 永远用于发送，
`next_secret` 独立保存后续派生材料。主动更新直接派生一对入队；被动更新先临时派生，
认证成功才入队并推进 secret，失败不改变正式状态。双方同时更新时使用已有队尾 opening，
不重复入队。队列最多三对；收到新代认证包后，旧对按 3 PTO 淘汰。旧密文提交仍受代次检查。
主动更新仅用 `can_update` 表示许可：qconn 在握手确认时调用 `allow_update()`，实际更新
发送密钥后清零，当前非初始发送代次获 ACK 后重新开放。被动接收更新不受本地许可限制，
也不会因解密成功而重新开放许可。qconn 的正式握手授权接线仍属于后续集成。
这不是 0-RTT 恢复材料；ticket/PSK 由 qtls 独立管理。

每个空间只有一个接收者，单 Path 只有一个发送 owner。路由和空间 channel 都有界，满时丢弃未处理密文；可靠帧已经交给组件后发生错误则关闭连接。CRYPTO 缓冲预算及队列等待寿命由 qconn 的握手/TLS 驱动管理。当前不提供 0-RTT 或 DATAGRAM，握手配置不得启用未接入能力。

实际接线与客户端/服务端 Space 淘汰时机见 [logic.md](../design/qtransport/logic.md)。本轮没有迁移 qconn 的 Incoming/Connecting、Endpoint 交付及完整关闭流程，也没有修改 qconnection。

## 与底层组件的兼容

- qtransport 导出的 `ArcParameters` 位于 `qbase::param::fixed`，由完整双方参数构造，同步只读。旧 `qbase::param::ArcParameters` 保留给 qconnection；没有把异步参数或连接错误带入成熟 Transport。
- qrecovery 增加已知窗口的开流/接流入口。关闭通过原有 input/output/listener 传播；Listener 管理 accept 的唤醒，不额外增加 DataStreams 关闭订阅或登记已移除的流端点。
- qprotocol 的 `poll_send_packet` 一次只提交一个 UDP datagram，明确区分 Pending 和完成，返回包含转发开销的实际字节数。
- 提交、停止发送、ACK 记账共用短同步边界；密钥代次判断与实际提交由密钥自身的锁保护，均不跨 await。ACK 在提交回调之前到达时等待发送记账完成，因此不需要另存 pending ACK 或增加接收命令。
- 组包依次读取异构 `Package` 源；前置队列受配额限制但允许一个可容纳的大帧，末尾流数据通过已有 `Repeat` 填满剩余容量。发送等待只订阅本次阻塞所需的信号，避免退还流控信用导致空闲空转。
- qcongestion 直接按发送队列中的位置间距判断包阈值丢失。ACK 保留原最大 PN 和范围，使用已有 `on_ack_rcvd` 及最大 PN 匹配条件采样 RTT。
- 实际发送先扣除反放大信用，再交给 CC 设置定时器；信用耗尽时暂停 PTO，收到新 datagram 恢复信用后重新设置。

## 验证

`cargo test -p qtransport -p qprotocol -p qrecovery -p qcongestion -p qbase -p qtls --offline`

`cargo clippy -p qtransport --all-targets --offline --no-deps -- -D warnings`

测试包含真实 qtls 密钥的流收发、本地 UDP 提交、关闭唤醒与终态端点、跳号/跨路径超越、重传流控记账、ACK/提交竞态、路径验证、去重认证、密钥更新与退役、组包容量及空闲任务让出。UDP 测试需要允许绑定本地 socket。完整 qconn 握手/Closing 的接线与端到端互操作验收属于后续集成。
