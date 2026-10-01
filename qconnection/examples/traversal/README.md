# 中转握手、公网直连和内网直连

两个独立程序：`traversal-server` 提供 echo 服务，`traversal-client` 每两秒发一句问候。
初始连接只使用中转端点。握手后，连接通过 `ADD_ADDRESS` / `PUNCH_ME_NOW` 等帧交换地址、
执行打洞并验证公网和内网直连路径。

## 运行

在仓库根目录启动 server：

```sh
cargo run -p qconnection --example traversal-server
```

等待 STUN 探测完成。server 直接打印可复制执行的命令，例如：

```sh
cargo run -p qconnection --example traversal-client -- \
  --server 54.69.99.32:20002-113.80.22.156:50000
```

在另一个终端执行 **本次输出** 的命令，地址已填入实际探测结果。

client 每两秒继续发送问候，但仅在回显内容变化时打印；server 仅在回显字节数变化时打印。
双方仅在路径集合变化时通过 `println!("{path}")` 输出，统一使用 `Pathway` 的 `Display` 格式，例如：

```text
192.168.5.179:59828---113.80.22.156:23489
192.168.5.179:59828---192.168.5.179:60135
35.78.0.4:20002-113.80.22.156:23521---35.78.0.4:20002-113.80.22.156:23489
```

用 Ctrl-C 结束。两端在同一个可达局域网时，预期中转、公网直连和内网直连都能验证成功。

默认只输出状态变化和警告。
公网直连是否成功仍取决于 NAT；同机测试涉及路由器的 NAT hairpin 支持。

## 代码结构

- `traversal-client.rs`：配置测试身份，注册 mock resolver，`endpoint.connect("localhost")`，收发消息。
- `traversal-server.rs`：配置测试身份，`endpoint.listen(...)`，回显每个双向流。
- `traversal/network.rs`：进程内全局初始化一次。用 `netdev` 扫描活动物理网卡的 IPv4 地址，
  为每个地址绑定一个 socket，保存原始网卡名称和索引，注册到 Dock / QuicProtocol。
  同一个 socket 完成 NAT 分类、映射探测、中转收发和直连收发。

STUN 使用 `nat.genmeta.net:20002`。server 选择一个 IPv4 STUN/中转服务地址；client 使用
server 端点中的同一个 agent，以保证返回地址对应这台中转服务。内网地址和探测出的公网地址
都发布到 AddressBook，连接内的 Puncher 自动消费这些地址。

全局 `Resolver` 默认没有任何解析源。示例仅用 `Resolver::add` 注册一个 mock，将测试证书
上的域名 `localhost` 映射为 server 的 **中转端点**。公网 Direct 和内网 Direct 地址均通过
连接内的地址帧交换，不加入 mock DNS。STUN 自己解析服务域名，不依赖这个全局 resolver。

证书和 CA 使用仓库 `tests/keychain/localhost` 的测试材料。

## 实测

2026-10-01，同机双进程自动扫描到 en0，双方经线上 `nat.genmeta.net` 探测为
`RestrictedPort`。中转握手和 echo 成功，client / server 两端均同时显示中转、公网 Direct、
内网 Direct 三条已验证路径。此结果覆盖同一 NAT 下的公网映射回环，不代表跨两个独立 NAT 的实测。


握手恢复状态修复后重新连续实测 8 轮：前 7 轮各保持 20 秒，最后一轮保持 90 秒，
共收到 117 次回显；每轮双方的中转、公网直连和内网直连路径均保持已验证状态，未再出现
`Too many PTOs`。修复覆盖早期密钥退役后的未确认包清理、Initial 退役时机，以及 Handshake ACK
完成地址验证后的 PTO 状态同步。
