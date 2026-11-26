# ESP32-C3、ESP32-C6 / ESP-IDF 验证

工程位于 `dquic/esp-idf/`，与 `dquic/examples/`、`dquic/interop/` 平级。
保留独立 Cargo workspace，隔离 ESP-IDF 的工具链和目标配置，使用 `std`、
单线程 Tokio 和现有 `qrustls + ring`。包含两个可执行固件：

- `dependencies`：Tokio UDP 回环、带证书验证的 QUIC TLS 握手。
- `echo`：ESP UDP 后端的报文边界/截断/缓冲复用、32 位指标回绕及采样差值、完整 dquic 握手、一个双向流的回显及双向 FIN。

两端均运行于同一芯片的 ESP-IDF/lwIP 回环接口。C3 使用官方 QEMU，
C6 使用 USB 连接的实物开发板；Wi-Fi 联网收发需要另行验证。

## 构建

需要 Rust 1.88.0 的 `rust-src`、Python 3.11、`ldproxy`、CMake 3、Ninja
和 libclang。目录中的 `rust-toolchain.toml` 固定 Rust 版本，`Cargo.lock`
固定 Rust 依赖。首次安装 SDK 应从非虚拟环境的 Python 启动，或使用已有
ESP-IDF 环境。SDK 和工具放在 `.embuild/`；完整首次安装建议预留至少 6 GiB。

```sh
cargo install ldproxy --locked
cd dquic/esp-idf
python3 tools/build.py dependencies
python3 tools/build.py echo
```

默认构建 C3；构建 C6 时增加芯片参数：

```sh
python3 tools/build.py dependencies esp32c6
python3 tools/build.py echo esp32c6
```

C3 的 Rust 目标为 `riscv32imc-esp-espidf`，C6 为
`riscv32imac-esp-espidf`。两者共用 Rust 工具链、SDK 和应用代码，生成的
SDK 配置分别存放在 `target/esp32c3/`、`target/esp32c6/`。

`build.py` 先构建 SDK，再让 ring 使用其 GCC。它还生成含绝对分区表路径的
本地 sdkconfig defaults。Rust 1.88 通过 `RUSTC_BOOTSTRAP=1` 使用 `build-std`；
应用代码使用稳定 Rust。使用该版本可避开本机较新 nightly 已复现的 ESP-IDF
`std`/libc 文件时间字段不兼容。

`.cargo/config.toml` 对此目标启用 `espidf_time64`，并为 Espressif GCC 14
补充与 `-mabi=ilp32` 一致的 `__ILP32__` 宏，供 ring 识别 CPU 字宽。
C 库关闭调试信息以控制临时磁盘占用；Rust ELF 保留调试信息。

## QEMU 执行

使用 ESP-IDF 官方安装器安装 `qemu-riscv32`，并满足本机动态库依赖。
安装与主机平台要求见 [ESP-IDF QEMU 指南](https://docs.espressif.com/projects/esp-idf/en/v5.4.2/esp32c3/api-guides/tools/qemu.html)。

使用 `.embuild/espressif/python_env/idf5.4_py3.11_env/bin/python` 运行：

```sh
python tools/qemu.py dependencies
python tools/qemu.py echo
```

这里的 `python` 指 SDK 的 Python 环境。脚本生成 4 MiB 完整 Flash 镜像，
使用 SDK 提供的 C3 revision 0.3 eFuse 默认值，禁用模拟网卡，并检查所有
成功标记以及 `Returned from app_main()`；超时或缺少标记返回失败。
串口日志与镜像在 `target/qemu/`。

本机已准备的临时工具可这样复跑：

```sh
export PATH="/private/tmp/dquic-esp-tools/bin:/private/tmp/dquic-esp-tools/python/bin:$PATH"
export DYLD_LIBRARY_PATH="/private/tmp/dquic-esp-tools/qemu-libs/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
python3 tools/build.py echo
.embuild/espressif/python_env/idf5.4_py3.11_env/bin/python tools/qemu.py echo
```

临时目录可能在系统清理后消失；标准 SDK/工具安装可按前面的步骤重新准备。

## C6 上板执行

使用原生 USB Serial/JTAG 接口，`sdkconfig.defaults.esp32c6` 将控制台输出到
同一 USB 端口。下面的 `python` 仍指 SDK Python；串口路径以实际枚举结果为准。
刷入前可用 `python -m esptool --port PORT flash_id` 确认芯片与 Flash 容量，
再用 `read_flash 0 SIZE backup.bin` 备份原固件。

```sh
python tools/flash.py dependencies /dev/cu.usbmodem142401
python tools/flash.py echo /dev/cu.usbmodem142401
```

脚本将所选 Rust ELF 转为镜像，按 SDK 生成的偏移写入 bootloader、分区表和
应用，然后复位并检查所有成功标记及 `Returned from app_main()`。串口记录、
应用镜像和烧录日志保存在 `target/hardware/esp32c6/`。分区及镜像仍使用
4 MiB 布局，也可用于实际 Flash 容量更大的板子。

### 2026-11-26 C6 实板结果

| 项目 | 结果 |
| --- | --- |
| 芯片 / Flash | ESP32-C6 revision 0.2 / 16 MiB |
| 目标 / SDK | `riscv32imac-esp-espidf` / ESP-IDF v5.4.2 |
| 依赖链固件 | 编译、链接、实板 UDP 回环与 QUIC TLS 握手通过 |
| dquic 固件 | 计数器回绕、UDP 边界/截断、证书验证握手、18 字节回显及双向 FIN 通过 |
| 正常退出 | 两份固件均出现 `Returned from app_main()` |
| 依赖链应用镜像 | 2,018,064 字节 |
| dquic 应用镜像 | 3,469,568 字节 |
| dquic 剩余堆 | 初始化 399,520 字节；最低 177,088 字节；完成时 197,760 字节 |

实板串口记录仅保存在本地 `target/hardware/esp32c6/`，分别为
`dependencies.txt` 和 `echo.txt`。当前板上保留 `echo` 验证固件。
原始 16 MiB Flash 已备份到 `target/hardware/esp32c6/original-flash-16mb.bin`，
记录了 SHA-256，并通过 `esptool verify_flash` 与板上原始数据比对一致。
该备份仅保存在本机，受 Git 忽略规则保护。恢复命令为：

```sh
python -m esptool --chip esp32c6 --port /dev/cu.usbmodem142401 write_flash 0 target/hardware/esp32c6/original-flash-16mb.bin
```

增加 C6 构建选择后，默认 C3 的完整固件构建及 QEMU 回显回归均通过。

## 2026-11-26 C3 QEMU 验证结果

| 项目 | 结果 |
| --- | --- |
| 目标 | `riscv32imc-esp-espidf` / ESP32-C3 revision 0.3 |
| SDK / C 编译器 | ESP-IDF v5.4.2 / Espressif GCC 14.2.0 |
| Rust / 模拟器 | Rust 1.88.0 / Espressif QEMU 9.0.0 (`20240606`) |
| Tokio / Mio | 1.47.1 / 1.0.4 |
| TLS | qrustls 0.23.46 / ring 0.17.14 |
| 依赖链固件 | 编译、链接、QEMU 执行通过 |
| dquic 固件 | 编译、链接、QEMU 执行通过 |
| 回显 | 18 字节校验一致，双向 FIN，正常返回 |
| 依赖链应用镜像 | 2,072,064 字节 |
| dquic 应用镜像 | 3,534,128 字节 |
| dquic 仿真剩余堆 | 初始化约 247 KiB；最低约 26 KiB；完成时约 48 KiB |

完整串口记录仅保存在本地 `target/qemu/dependencies.log` 和
`target/qemu/echo.log`。Flash 分区表与 SDK 生成结果已比较一致。
镜像大小对应上述验证构建，不是去除所有可选功能后的最小体积。

桌面验证覆盖 `qudp` 20 项、连接/密钥 17 项、计数器 8 项、流发送 14 项、
解析器 7 项。指标切换到 `AtomicUsize` 后重跑了计数器和流发送的 22 项，
并重编译、运行了 C3 回显固件。接收预算改为 1536 后，`qbase`、`qudp`、
`qprotocol` 的桌面回归共 471 项通过，C3 固件再次通过回显验证。
GRO 容量与截断修正后，`qudp` / `qprotocol` 的本机 118 项测试和 C3 回显通过。
Linux 后端及 15/32/64 段聚合测试通过交叉类型检查；测试链接遇到本机 Zig
不支持的 Cortex-A53 链接参数，Linux 的实际 GRO 收发未运行。Windows
UDP 后端在此前已通过交叉编译，运行时收发测试未在本机执行。
桌面入口为 `src/loopback.rs`，由外层 `dquic` 包注册为 example，
与固件入口通过 `mod echo;` 共用同目录的回显代码。在仓库根运行：

```sh
cargo run -p dquic --example esp-loopback
```

## 使用范围

- ESP UDP 后端要求绑定具体本地 IP，接口索引为零；不支持通配绑定或通过
  packet-info 指定另一源地址。不支持的请求返回明确错误。
- 单报文默认预算和本端 `MaxUdpPayloadSize` 默认值均为 1536 字节。
  ESP 每次处理一个 UDP 报文，Dock 接收缓冲为 1536 字节。Linux/Android
  开启 GRO 时，每槽按内核 64 段上限分配 `1536 * 64`，8 槽共 768 KiB；
  其他无 GRO 的桌面后端为 8 槽、共 12 KiB。聚合容量与发送 burst 的
  8 包上限独立，`udp_offload_opt` 保持默认开启。GRO 段长直接写入
  `Line.seg_size`，不额外处理截断前缀。仍检查 `MSG_TRUNC`，将较小调用方
  缓冲或超长报文导致的截断内容整包丢弃。示例同时缩小流控窗口和并发流数，
  见 `src/echo.rs`。
- 连接指标使用 `AtomicUsize`，累计 ACK 字节数允许回绕。采样增量使用
  `current.wrapping_sub(previous)`；C3/C6 上两次采样之间须少于 4 GiB。
  pending/inflight 各自需能由 `usize` 表示。密钥安全限制仍使用 64 位计数。
- 验证固件把编译时间设为测试时钟，并在无 Wi-Fi 的回环测试中启用 SAR
  熵源。实际联网应用需要自己的时间同步和熵源初始化；Wi-Fi/BT 与 SAR
  熵源的使用约束见 [Espressif RNG 文档](https://docs.espressif.com/projects/esp-idf/en/v5.4.2/esp32c3/api-reference/system/random.html)。
- 主任务栈配置为 64 KiB，Tokio 阻塞任务栈为 8 KiB。最低堆余量来自同芯片
  双端回环，C3 使用 QEMU、C6 使用实板，均不包含 Wi-Fi。实物 Wi-Fi、吞吐、丢包、NAT 穿越、迁移、
  断线重连和长期运行尚未验证。
