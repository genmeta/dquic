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
| `space` / `control` | 每空间独立的恢复记录、CRYPTO 和不可复活的收发许可；没有父级回指 |
| `keys` | Pending → Ready → Invalid、异步就绪、1-RTT 代次、认证与 AEAD 用量 |
| `recv` | `run_receive`、`open_packet`、`receive_packet`；通过闭包投递，无 Topology 容器或命令队列 |
| `path` | 每路径一个 CC、路径验证/重试、反放大信用、按实例退役 |
| `send` | 每路径一个 Sender；独立的 `acknowledge` 函数供原组件管道捕获 |
| `send/packet` | 自持 buffer 的 OneRttPacket、异构 Package 源、消费式 seal |
| `send/records` | 永不归还的 PN、有限恢复记录、实际提交顺序、按发送路径归属 ACK |

建立连接的外部驱动按以下顺序工作：

1. 建立一个 `Arc<Mutex<()>>` 提交边界，供各空间 Control 和各 Path 共享。先创建 Space/keys，再将稳定的 Space feedback 交给 Path/CC。
2. 创建有界包队列和帧管道；每个空间各运行一次 `run_receive`。统一 dispatch 闭包只捕获组件和 channel 入口。Data 的许可在 TLS complete 前保持关闭。
3. 参数验证后构造 streams、flow、可靠帧队列；ACK pipe 捕获这些原组件，调用 `send::acknowledge`，不必等待 Transport 出现。
4. TLS complete 后将同一批组件传给 `Transport::new`，打开 Data 收发许可，用选定 ALPN 调用 `ArcConnection::new` 交付。
5. 每路径唯一发送任务使用 `Sender::prepare` / `poll_send` 与握手发送协调，或驱动 `Sender::run`。创建另一个 Data Sender 会失败；qconn 仍须保证握手与关闭发送不另起物理 owner。
6. 关闭时 Listener 使用已有 waker 唤醒 `accept_bi/accept_uni` 并返回错误。qconn 管理协议收尾及任务结果；对端 CLOSE 直接推进外部 Draining，并调用 `Transport::close`。取消正常收包和 pipe，保留原 CID inbox 继续 Closing/Draining，最终 join 全部任务。

Initial/Handshake 的实例、TLS、握手确认规则、Closing/Draining、Router、CID/token 管理、DNS/STUN、Endpoint 均由外部驱动持有。qtransport 不执行这些连接状态转换，未改动现有 qconn 的 Endpoint 交付链路，也未改动 qconnection。

包队列必须限制数量、总字节数及等待寿命，包括正在等待密钥的包。`run_receive` 的取消由任务 owner 负责，不能只关闭仍有积压的 channel。同空间只有一个消费者；关闭后的旧正常接收任务不能再次启动。dispatch 的可靠帧出口入队失败必须成为终止错误，不能丢帧后 ACK；pipe 后续消费失败同样交给外部关闭驱动。

CRYPTO 的接收缓冲预算由外部 TLS pipe 在调用 CryptoStream 前检查；CID、token、HANDSHAKE_DONE 与 CLOSE 由原控制面处理。当前应用 API 提供可靠流，不提供 0-RTT 或 DATAGRAM，握手配置不得启用这些未接入的能力。

## 与底层组件的兼容

- qtransport 导出的 `ArcParameters` 位于 `qbase::param::fixed`，由完整双方参数构造，同步只读。旧 `qbase::param::ArcParameters` 保留给 qconnection；没有把异步参数或连接错误带入成熟 Transport。
- qrecovery 增加已知窗口的开流/接流入口。关闭通过原有 input/output/listener 传播；Listener 管理 accept 的唤醒，不额外增加 DataStreams 关闭订阅或登记已移除的流端点。
- qprotocol 的 `poll_send_packet` 一次只提交一个 UDP datagram，明确区分 Pending 和完成，返回包含转发开销的实际字节数。
- 提交、关闭/密钥撤销、ACK 记账共用短同步边界，均不跨 await。ACK 在提交回调之前到达时等待同一边界，因此不需要另存 pending ACK 或增加接收命令。
- 组包依次读取异构 `Package` 源；前置队列受配额限制但允许一个可容纳的大帧，末尾流数据通过已有 `Repeat` 填满剩余容量。发送等待只订阅本次阻塞所需的信号，避免退还流控信用导致空闲空转。
- qcongestion 直接按发送队列中的位置间距判断包阈值丢失。ACK 保留原最大 PN 和范围，使用已有 `on_ack_rcvd` 及最大 PN 匹配条件采样 RTT。
- 实际发送先扣除反放大信用，再交给 CC 设置定时器；信用耗尽时暂停 PTO，收到新 datagram 恢复信用后重新设置。

## 验证

`cargo test -p qtransport -p qprotocol -p qrecovery -p qcongestion -p qbase -p qtls --offline`

`cargo clippy -p qtransport --all-targets --offline --no-deps -- -D warnings`

测试包含真实 qtls 密钥的流收发、本地 UDP 提交、关闭唤醒与终态端点、跳号/跨路径超越、重传流控记账、ACK/提交竞态、路径验证、去重认证、密钥更新与退役、组包容量及空闲任务让出。UDP 测试需要允许绑定本地 socket。完整 qconn 握手/Closing 的接线与端到端互操作验收属于后续集成。
