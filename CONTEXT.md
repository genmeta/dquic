# dquic

本项目的领域术语。以下定义记录已确定的含义。

## Language

**本地端点**：本地提供给对端使用的通信端点，具有对应的本地网络绑定和通信地址。

**ArcAddrBook**：共享的本地地址簿。socket_addr 登记正式 UDP socket 的实际地址，供 mDNS 按 IP 查询；endpoint_addr 保存 Direct / Mediate 通信端点（包括 Direct 回环），通过内部 watch 和 attach_publisher(publisher, scopes) 异步任务向 DNS 发布器提供最新完整列表，通过 matches(peer_ep_addr) 为路径发现筛选可连接的本地端点；candidates 单独保存 Link → NatType，通过 attach_puncher 补发和通知打洞观察者。端点登记与候选登记互不触发。

**NAT 信息**：从实际 socket 地址到 outer 地址这一条 Link 的 NAT 特征。只有明确取得类型后才登记 Candidate；公网 socket 的 inner 与 outer 相等。内网直接可达的 self Link 可由所有者显式登记为 FullCone，普通 socket / endpoint 登记不隐式创建候选。

**本地绑定（bound）**：UDP socket 实际绑定的本地地址，用于在同一 Dock 中定位当前 socket。绑定地址可在关闭后复用，不代表跨生命周期的同一个 socket。

**BindUri**：创建本地绑定的配置描述，表达绑定地址或网卡、端口和附加选项；端口可以尚未分配，网卡地址也可以尚未解析。

**PathCids**：连接内路径与发送目标 CID 的使用关系，包含握手期间的共享使用、选中路径以及握手后的独立分配。
