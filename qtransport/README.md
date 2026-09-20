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
| `transport` | 保存确定性传入的 Data 组件；提供 on_tick 连接级恢复驱动和业务关闭入口 |
| `space` | 每空间独立的恢复记录、CRYPTO 和不可复活的收发许可；仅 Initial/Handshake 提供 retire，Data 保留到连接收尾；没有父级回指 |
| `keys` | Pending / Waiting(Waker) → Ready → Retired、异步就绪、1-RTT 代次、认证与 AEAD 用量；OpenPacket、SealPacket、私有 open_with 包保护基础实现 |
| `packet` | qtls 密钥驱动的 `CipherPacket<H>` / `PlainPacket<H>`；`channel` 提供四个加密级别的 typed channel |
| `router` | Signpost → Inbox；RAII 路由守卫、CID registry、未知包 channel |
| `recv` | run / run_receive / receive_packet / frame_dispatcher；各空间直接消费自己的 typed receiver |
| `path` | 每路径一个 CC、路径验证/重试、反放大信用、按实例退役 |
| `send` | 每路径一个 Sender，分空间组包、Burst 批量提交；独立的 `acknowledge` 函数供原组件管道捕获 |
| `send/write` | 四种包型共用的 Packet、含 datagram.msg 的 buffer、带约束和记录的 PacketWriter、消费式 seal |
| `send/records` | 独立的 ArcSendJournal，永不归还的 PN、IndexDeque 集中存储 Option<GuaranteedFrame>及每包 frame_range、明确放弃的 PN 集合、ACK 帧恢复记录 |

建立连接的外部驱动按以下顺序工作：

1. 使用 `let (inbox, rcvd_pkt) = packet::channel::new()` 创建四级 channel。将 `inbox` 注册到 Router，把 `(route, rcvd_pkt)` 传给 qconn。独立 Router 由调用者传入 connectless sender；全局 Router 的 listener 用 `take_connectless_packets()` 取得唯一 receiver。
2. 创建各 Space、keys 和 Path。Space/Path 各自管理原有状态，构造时不传额外同步锁；ArcKeys 只持有密钥状态锁。KeyState、ArcKeys 实现 Future<Output = Result<K, KeyRetired>>，用单读者 Waker 等待材料；Ready 返回 Ok(克隆句柄)，Retired 返回 Err(KeyRetired)。取得密钥后直接使用 opening/sealing；收包用具体解密函数接线，不再有 ReceiveKeys 或 with_ready/is_ready。
3. `rcvd_pkt.initial / handshake / zero_rtt / one_rtt` 分别具有对应 header 类型。每个空间把自己的 receiver 直接交给 `run_receive`，完成路径取得、记账、解密、去重和帧投递；不经过统一 Packet 队列和二次分流。
4. 参数成型后准备 streams/flow，TLS 允许处理 Data 时安装其密钥。成熟时同一批组件传给 Transport，选定 ALPN 和同一个 closing 开关传给 ArcConnection::new；构造函数不重复握手校验。
5. 每路径创建 Sender，传入 QuicProtocol、Pathway、CC、共享 AntiAmplifier 和 send_waker。Sender 不持有 Path、Transport、flow 或 keys；STREAM 源从完整 Transport 取得发送流控，握手阶段无需预建零额度流控。外部闭包同步 try_get 密钥（Ok(None) 尚未就绪，Ok(Some(keys)) 可用，Err(KeyRetired) 禁止继续使用该层发送），向 assemble_initial_packet / assemble_handshake_packet / assemble_0rtt_packet / assemble_1rtt_packet 传入 header、journal、Constraints 和 Package 源；burst 收集批次，poll_send 提交，或用 run 驱动两者。
6. 应用关闭、接收错误、对端 CLOSE 切换 Connection 共享的 closing；同一收包引擎继续解密，只投递 CLOSE。Closing/Draining 结束后 qconn 取消四级接收任务、清理 CID registry 并释放路由守卫；最后一个 `Inbox` sender 释放后 receiver 关闭。

Initial/Handshake 实例、TLS、角色淘汰规则、关闭发送与定时器、CID/token 管理实例由外部驱动持有；QuicRouter 实现在 qtransport，支持独立实例和显式取得的全局实例。

路由保留 `Signpost`、`QuicRouterEntry` 和 `QuicRouterRegistry`，不包含 `QuicRouterComponent`、admissibility 或 handler。`Way = (Pathway, Link)`。`receive` 解析 datagram 并为同一连接的 CID 别名只记一次字节数；未知包直接 `try_send` 到 connectless channel。`packet::channel::Inbox` 将 Data packet 按 header 类型投递，满 channel 时直接丢包。

1-RTT 密钥分为固定的 `HeaderKeys { opening, sealing }` 和共享的 `OneRttPacketKeys`。
`qtls::DirectionalKeys` 与 `OneRttKeys` 均实现 `keys::OpenPacket`、`keys::SealPacket`，
分别提供 `open`、`seal`。`open` 统一接收 PTO，固定密钥忽略它；`SealPacket::Output`
分别为 `()` 和 `(u64, KeyPhaseBit)`。两类 `open` 共用本模块的私有函数 `open_with`，仅接收 `decode_pn` 闭包；
journal 在接线处捕获，不传入密钥层。使用扩展方法分别导入 `OpenPacket`、`SealPacket`。
`CipherPacket` 直接使用 qtls 的 `DirectionalKeys`、`HeaderProtectionKey` 和 `PacketKey`，qtransport 不直接依赖 rustls。`ArcOneRttKeys.await` 返回 `Result<OneRttKeys, KeyRetired>`，Data 接收接入 `OneRttKeys::open_packet` 并产出 `PlainPacket<OneRttHeader>`。
`OneRttKeys::reserve` 在同一锁内固定密钥代次、领取 PN 并预留 AEAD 用量；返回的
`OneRttSealingKey` 在锁外执行加密和头保护。`update/allow_update/on_ack/seal/tag_len` 均属于已就绪的
`OneRttKeys`；`ArcOneRttKeys` 只安装、等待、同步取材和淘汰，不提供密钥操作的转调。包对象只提供
buffer 与布局。Data ACK 回调捕获本次解密的就绪材料；Space 的停止开关阻止淘汰后发送。
包密钥用一个 `VecDeque` 保存成对的 opening/sealing，新 PN 领取队尾 sealing 快照，
`next_secret` 独立保存后续派生材料。主动更新直接派生一对入队；被动更新先临时派生，
认证成功才入队并推进 secret，失败不改变正式状态。双方同时更新时使用已有队尾 opening，
不重复入队。队列最多三对；收到新代认证包后，旧对按 3 PTO 淘汰。已领取包的密钥和相位固定，旧密文可以晚于新代包提交。
主动更新仅用 `can_update` 表示许可：qconn 在握手确认时调用 `allow_update()`，实际更新
发送密钥后清零，当前非初始发送代次获 ACK 后重新开放。被动接收更新不受本地许可限制，
也不会因解密成功而重新开放许可。qconn 的正式握手授权接线仍属于后续集成。
这不是 0-RTT 恢复材料；ticket/PSK 由 qtls 独立管理。

每个空间只有一个接收者，单 Path 只有一个发送 owner。路由和空间 channel 都有界，满时丢弃未处理密文；可靠帧已经交给组件后发生错误则关闭连接。CRYPTO 缓冲预算及队列等待寿命由 qconn 的握手/TLS 驱动管理。发送侧已支持 0-RTT 包编码和 DATAGRAM 帧源；TLS 早期数据接受/拒绝及 DATAGRAM 的接收与应用 API 尚未接入，握手配置不得启用未接入能力。

实际接线与客户端/服务端 Space 淘汰时机见 [logic.md](../design/qtransport/logic.md)。本轮没有迁移 qconn 的 Incoming/Connecting、Endpoint 交付及完整关闭流程，也没有修改 qconnection。

## 与底层组件的兼容

- qtransport 导出的 `ArcParameters` 位于 `qbase::param::fixed`，由完整双方参数构造，同步只读。旧 `qbase::param::ArcParameters` 保留给 qconnection；没有把异步参数或连接错误带入成熟 Transport。
- qrecovery 增加已知窗口的开流/接流入口。关闭通过原有 input/output/listener 传播；Listener 管理 accept 的唤醒，不额外增加 DataStreams 关闭订阅或登记已移除的流端点。
- qprotocol 的 `poll_send` / `send` 接受一批 IoSlice，每项是一个 UDP datagram，返回成功提交的前缀数量。Sender 按累计 CC/反放大信用组包；部分成功保留原密文后缀，后续续发；Pending 不记账。每批上限复用 qudp::BATCH_SIZE。
- 一次非阻塞提交先借用本路径 CC，再按 Epoch 顺序借用涉及的 journal；成功前缀的 journal/反放大/CC 记账完成后释放数据锁。ACK 同样先借用接收路径 CC，再访问 journal；不增加空锁或 pending ACK。组包、加密、等待可写和发送回调都不持这些 guard。Space/Path 停止只更新状态并唤醒任务，已通过本轮许可检查的批次允许完成，后续提交清理停止层的 pending。
- 组包按 ACK → CRYPTO → Path 帧 → reliable frames → streams 依次读取异构 `Package` 源，不设来源配额；装不下的数据留待后续包。流数据通过已有 `Repeat` 使用剩余容量，不同流的公平调度由 streams 组件负责。发送等待只订阅本次阻塞所需的信号，避免退还流控信用导致空闲空转。
- 每空间使用一份可克隆的 ArcSendJournal，共享一份 Mutex<SendJournal> 和组件回投闭包；skipped_pns: BTreeSet<u64> 只保存明确放弃的 PN，最多保留 256 项，不再保存成功发送区间或提交上界。qrecovery::ArcSentJournal 保持原实现。
- `Packet::new(buffer, header, tag_len)` 预留 4 字节 PN 后组帧；空组包或约束不足不领号。Sender 在 OneRttKeys::reserve 内调用 `record_pending(generation, records)`，一并固定密钥代次、领取 PN/编码、建立恢复记录。随后调用 `packet.seal(&key, pn, encoded_pn)`；长包调用 `seal_long(&keys, pn, encoded_pn)`。两者只返回封包结果，由 Sender 的 finish_sealing 在失败时 cancel_pending、取回帧描述，成功时接入待提交包的取消清理。按实际 2/3/4 字节 PN 右移小段包头、裁掉头部余量，不搬动帧数据，不二次补装帧。HP 和显式 padding 都在组帧阶段预留预算。ACK 拒绝未领取、Pending 和保留的 skipped PN；合法 ACK 单调更新 largest_acked 供后续编码。跨路径允许 PN10 晚于 PN11 提交，密钥更新不作废已经封好的包。
- Sender 复用一个帧描述数组；assemble 将 packet、Constraints 和该数组借用组合为 PacketWriter，数据源只调用 dump(&mut writer)，由 writer 检查约束并记录帧；Packet 和 PendingPacket 均不保存帧或帧数组的引用。领取 PN 时可靠描述以 GuaranteedFrame 批量移动到 journal；加密失败则取消记录、归还描述；路径描述单独保存在 PendingPacket，发送成功后通过回调通知 Path。PacketWriter.datagram().msg 可访问当前数据报 buffer。未提交的 PendingPacket 在 Drop 时通过 journal 回投可靠数据，成功提交后解除此取消责任。ACK/PING/PADDING/DATAGRAM 不进入恢复记录。记录范围使用帧追加下标，独立于 PN 顺序。frames 使用 Option<GuaranteedFrame>：ACK/Failed 通过 take 移出描述，Retired 清空槽位；重传保留 Some 以接收迟到 ACK。回收只弹出队头连续 None，不再扫描包寻找最小帧范围；非队头发送失败也直接移出帧。被前面记录挡住的 None 仍占槽位并计入存储上限，底层容量继续复用。SentPacketState 明确区分 Pending、Flighting、Retransmitted、Failed、Acked、Retired；Flighting 保存 retrans_at 与 expire_after 两个 Instant；发送成功时分别按 CC 的重传等待时间和 3 PTO 确定。Retransmitted 只保留 expire_after，判丢后原样沿用；journal 不重复保存 CC 已有的发送时间。判丢时立即转为 Retransmitted，并通过 Space 构建时捕获组件的 on_loss 闭包同步回投，不使用 Lost 中间态或 loss_pending 标记。每个旧 PN 只交回一次重传数据，保留原记录处理延迟 ACK；重复判丢不延长保留期，发送失败或撤销提交进入 Failed，归还帧；Failed/Acked/Retired 按 PN 直接删除记录、截止时间索引；reclaim 只回收帧队列的空槽位前缀。
- 外部连接任务定期调用 `transport.on_tick(now)`，从 `BTreeSet<(Instant, u64)>` 队头处理到期项，遇到截止时间大于 now 即停止；Flighting 登记 retrans_at，Retransmitted 改登记 expire_after，每包最多一项，同一时刻按 PN 区分。CC 提前判丢与 tick 共用状态转换和同步回投闭包：CryptoStream/DataStreams 标记数据范围可能丢失，可靠帧克隆回原队列；组件负责唤醒发送。不设 retransmissions 集合、take_lost 接口或定时回投临时数组。ACK 直接取消截止时间索引；Sender 只读取组件待发数据。Path::retire 不再强制判丢，无需交接，全部路径销毁后定时驱动仍可继续；qtransport 不自动启动该任务。
- qcongestion 直接按发送队列中的位置间距判断包阈值丢失。ACK 保留原最大 PN 和范围，使用已有 `on_ack_rcvd` 及最大 PN 匹配条件采样 RTT。
- 实际发送先扣除反放大信用，再交给 CC 设置定时器；信用耗尽时暂停 PTO，收到新 datagram 恢复信用后重新设置。

## 验证

`cargo test -p qtransport -p qprotocol -p qrecovery -p qcongestion -p qbase -p qtls --offline`

`cargo clippy -p qtransport --all-targets --offline --no-deps -- -D warnings`

测试包含真实 qtls 密钥的流收发、本地 UDP 提交、关闭唤醒与终态端点、跳号/跨路径超越、重传流控记账、ACK/提交竞态、路径验证、去重认证、密钥更新与退役、组包容量及空闲任务让出。UDP 测试需要允许绑定本地 socket。完整 qconn 握手/Closing 的接线与端到端互操作验收属于后续集成。
