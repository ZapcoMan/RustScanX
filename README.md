<div align="center" markdown="1">

<img src="pictures/rustscan.png" height=400px width=400px>

# RustScanX

**快速、智能、高效的现代化端口扫描器。**

![Built with Rust][badge-2] ![Discord][badge-5]

</div>

> ⚠️ **合法使用声明**：请勿在未经授权的目标上运行本工具。端口扫描在诸多司法
> 辖区可能违法，使用者须自行承担全部法律责任。本工具仅用于安全研究、渗透测试
> 授权范围内的资产自查等合法用途。

---

# 🔱 关于 RustScanX（二次开发说明与致谢）

**RustScanX 是基于原开源项目 [RustScan](https://github.com/bee-san/RustScan) 二次
开发（fork）而来的分支。**

原项目地址：<https://github.com/bee-san/RustScan.git>

我们在此向 RustScan 的原作者与全体贡献者致以诚挚的敬意 🙏。RustScan 由
[Bee (Autumn)](https://skerritt.blog) 与社区共同创造，其"以 Rust 重写更快的 Nmap
前端 + 脚本引擎"的核心思路、以及大量基础架构均源自原项目。RustScanX 在保留原有
设计理念与 GPL-3.0 许可证的前提下，进行独立的维护与改进。

- 上游文档与 Wiki：<https://github.com/bee-san/RustScan/wiki>
- 上游贡献者名单遵循 [all-contributors](https://github.com/all-contributors/all-contributors)
  规范，完整名单请见原项目 README。

本项目的许可证沿用原项目的 **GPL-3.0-only**，详见 [`LICENSE`](LICENSE)。

---

# 🤔 这是什么？

![fast][speed-1]

RustScanX 是一个用 Rust 编写的**端口扫描器**。它的设计目标是：以极高的并发把
"发现哪些端口开放"这件事做到最快，再把确定开放的结果**管道（pipe）给 Nmap 或
自定义脚本**做深度探测——把"连接扫描"这种 Nmap 做得较慢的脏活，用异步 I/O 快速
完成，把需要复杂协议探测的活交给成熟的脚本引擎。

核心能力（均来自实际代码实现）：

- **极速端口发现**：单个 future 驱动 `FuturesUnordered`，在同一时刻维持最多
  `batch_size` 个在途连接尝试；可在秒级内扫完 65535 个端口。
- **TCP 与 UDP 扫描**：TCP 采用带超时/重试的 connect 探测；UDP 使用编译期从
  `nmap-payloads` 生成的端口→有效载荷表发送真实协议探测包，并通过读取 ICMP
  "port unreachable"（Linux 上的 `EPOLLERR`）来区分"关闭"与"被过滤"。
- **随机化端口顺序**：随机扫描顺序基于**线性同余生成器（LCG）**——选取与端口总数
  互质的步长，保证一次遍历所有端口且彼此不相邻，从而降低被入侵检测系统识别的概率。
- **地址输入**：支持字面量 IP、IPv6、CIDR（含非规范化 CIDR，自动对齐到网络地址）、
  主机名（DNS 解析）、以及每行一个地址的输入文件；`-x/--exclude-addresses` 可按
  CIDR/IP/主机名排除目标。
- **DNS 惰性解析**：绝大多数目标为字面量 IP/CIDR 时，不会初始化 DNS 解析器；只有
  真正需要解析主机名时才按需创建，避免拖慢扫描。
- **端口排除**：`--exclude-ports` 通过一张 8 KiB 的完整 u16 位图在异步轮询帧之外
  过滤被排除端口，对短列表退化为直接成员检查。
- **脚本引擎**：按标签（tags）匹配脚本，将发现的端口自动管道进 `nmap`，或运行
  任意语言的自定义脚本（`{{script}}`/`{{ip}}`/`{{port}}` 模板替换）。
- **自适应批量大小**（Unix）：根据进程的文件描述符限额（`ulimit`）自动下调批量
  大小，避免"打开文件数过多"导致扫描失败。
- **无障碍与可 grep 输出**：`--greppable` 只输出 IP 与端口便于管道/落盘；
  `--accessible` 关闭彩色 ASCII 等对屏幕阅读器不友好的特性。
- **稳健输出**：所有面向用户的输出经由 `println_safe`，在管道被提前关闭（如
  `| head` 触发 `BrokenPipe`）时安静退出而非 panic。

---

# 🛠️ 安装

RustScanX 是原项目的二次开发分支，**尚未发布到 crates.io / 各发行版包仓库**，
因此目前请从源码构建安装。

从源码安装（需要已安装 Rust 工具链）：

```bash
git clone https://github.com/bee-san/RustScan.git   # 或本分支对应的仓库地址
cd RustScan
cargo install --path .
```

构建产物二进制名为 **`rustscanx`**。开发调试时也可以直接运行：

```bash
cargo run --release -- -a 127.0.0.1
```

> 说明：原项目 RustScan 可通过 `cargo install rustscan` 及各包管理器
> （Homebrew / pacman / apt 等）安装，参见上游
> [安装指南](https://github.com/bee-san/RustScan/wiki/Installation-Guide)。

---

# 🤸 快速开始

以下命令行参数均取自 `src/input.rs` 中的 `Opts` 定义（`rustscanx --help` 可查看
完整列表）。

```bash
# 扫描单个主机的常见端口范围
rustscanx -a 127.0.0.1 -r 1-1000

# 指定端口列表
rustscanx -a 127.0.0.1 -p 22,80,443,8080

# 扫描全部 65535 端口（默认范围），并调整超时与并发
rustscanx -a 192.168.1.0/24 -t 2000 -b 5000

# 随机顺序扫描，排除某些端口
rustscanx -a example.com --scan-order random --exclude-ports 80,443

# 排除部分目标地址
rustscanx -a 192.168.0.0/16 -x 192.168.1.0/24

# 只输出可 grep 的结果，不运行脚本
rustscanx -a 10.0.0.1 -g --scripts none

# UDP 扫描
rustscanx -a 127.0.0.1 -r 1-1024 --udp

# 慢速、低噪声扫描：每个端口之间等待 250ms，并列出主动拒绝的关闭端口
rustscanx -a 127.0.0.1 -r 1-1000 --interval 250 --closed

# 把额外参数透传给脚本引擎（默认会把结果管道进 nmap）
rustscanx -t 1500 -a 127.0.0.1 -- -A -sC
```

主要参数一览：

| 参数 | 含义 |
| :--- | :--- |
| `-a, --addresses` | 逗号分隔或文件形式的 CIDR/IP/主机列表 |
| `-p, --ports` | 逗号分隔的端口列表，如 `80,443,8080` |
| `-r, --range` | 端口范围，`start-end` 逗号分隔，如 `1-500,1000-2500` |
| `-b, --batch-size` | 并发批量大小（默认 4500） |
| `-t, --timeout` | 判定端口关闭前的超时毫秒数（默认 1500） |
| `--tries` | 连接重试次数（为 0 时自动纠正为 1） |
| `--scan-order` | `serial`（升序）或 `random`（LCG 随机） |
| `--scripts` | `none` / `default` / `custom` |
| `--exclude-ports` | 排除的端口列表 |
| `-x, --exclude-addresses` | 排除的 CIDR/IP/主机列表 |
| `--udp` | 启用 UDP 扫描 |
| `--closed` | 额外列出主动拒绝（关闭）的 TCP 端口 |
| `--interval` | 每扫完一个端口后等待的毫秒数，用于慢扫 |
| `-g, --greppable` | 只输出 IP 与端口，便于管道/落盘 |
| `--accessible` | 关闭对屏幕阅读器不友好的输出 |
| `-u, --ulimit` | 自动提高 Unix 文件描述符限额（仅 Unix） |
| `-- -- <args>` | 将 `--` 之后的参数透传给脚本 |

---

# ⚙️ 配置文件

RustScanX 会读取 TOML 配置文件，命令行显式给出的选项**优先于**配置文件
（`Opts::merge` 记录了哪些字段来自命令行）。默认查找路径按顺序尝试：

1. `$XDG_CONFIG_HOME/rustscanx/config.toml`（Linux；未设置该变量时回退 `~/.config`），
   以及 macOS / Windows 上平台等价的 `dirs::config_dir()` 位置；
2. 为兼容历史版本而保留的旧路径（`.rustscan.toml`）。

也可用 `-C, --config-path` 指定路径，或用 `-n, --no-config` 忽略配置文件。

配置示例：

```toml
addresses = ["127.0.0.1"]
range = "1-1000"           # 也支持 { start = 1, end = 1000 } 或 [[1, 1000]]
ports = [80, 443, 8080]    # 与 range 互斥
batch_size = 4500
timeout = 1500
tries = 1
scan_order = "Serial"      # 或 "Random"
scripts = "default"        # "none" / "default" / "custom"
greppable = false
exclude_ports = [8080, 9090]
udp = false
```

仓库根目录的 [`config.toml`](config.toml) 是一份端口→分类的数据文件。

---

# 🧠 架构与代码逻辑

以下梳理基于对 `src/` 全部源码的通读。

## 模块划分

| 模块 | 职责 |
| :--- | :--- |
| `main.rs` | CLI 入口：解析 `Opts`、合并配置、校验平台、初始化脚本、解析地址、计算有效批量、构建并运行 `Scanner`、聚合结果、运行脚本、输出运行时基准 |
| `lib.rs` | 声明公开模块与输出宏，供库调用者复用扫描能力 |
| `input.rs` | `Opts`（clap 命令行）、`Config`（TOML）、`PortRanges` 解析、`ScanOrder`/`ScriptsRequired` 枚举，以及"命令行覆盖配置文件"的合并逻辑 |
| `address.rs` | 地址解析：IP / IPv6 / CIDR（含非规范化对齐）/ 主机名 / 文件；DNS 惰性解析器（hickory，回退系统配置或 Cloudflare DoT）；目标排除；去重 |
| `port_strategy/` | `PortStrategy`（`Manual`/`Serial`/`Random`）；`range_iterator` 用 LCG 生成随机顺序、用 seen 表串行去重 |
| `scanner/` | 扫描核心：`SocketIterator` 无缓冲展开 ip×port 组合；`FuturesUnordered` 并发驱动；位图端口过滤；TCP/UDP 探测；`PortStatus` 结果；输出与慢扫间隔 |
| `scripts/` | 脚本引擎：按 tags 匹配脚本，模板替换并执行（默认管道进 nmap） |
| `tui.rs` | `println_safe`（BrokenPipe 安全）与 `warning!`/`detail!`/`output!`/`funny_opening!` 输出宏 |
| `benchmark/` | 命名计时器，扫描阶段耗时汇总 |
| `build.rs` | 编译期读取 `nmap-payloads`，生成 `src/generated.rs` 的 UDP 端口→有效载荷表 |

## 扫描执行流程

```
命令行/配置文件
      │  (Opts::merge，命令行优先)
      ▼
地址解析 parse_addresses
  IP/CIDR/主机名/文件 → 去重 → 移除被排除地址（惰性 DNS）
      ▼
端口顺序 PortStrategy::order()
  serial：按输入顺序去重产出
  random：LCG（步长与总数互质 → 满循环遍历、端口彼此分散）
      ▼
端口过滤 filter_excluded_ports
  8 KiB u16 位图排除 --exclude-ports（短列表退化为成员检查）
      ▼
SocketIterator
  零分配遍历 (ip, port) 组合，产出 SocketAddr
      ▼
scan_sockets  (current-thread Tokio 运行时)
  最多 batch_size 个在途连接；每轮 WORK_PER_TURN=128 后向运行时让出，
  保证定时器与 I/O 得到及时处理
      ▼
每个套接字：
  TCP → connect（timeout 超时 / tries 重试）；拒绝即 Closed
  UDP → 按端口取 nmap 有效载荷发送探测，等待回应或 ICMP 错误
      ▼
聚合结果 → 按 IP 归并 Open / Closed
      ▼
脚本引擎 → 对开放端口运行 nmap / 自定义脚本
      ▼
输出 → 终端（彩色/无障碍）或 -g 可 grep 结果；附带运行时基准
```

## 关键实现细节

- **让出与并发预算**：扫描用 `tokio::task::unconstrained` 包裹，并在每轮处理
  `WORK_PER_TURN`（128）个套接字后 `yield_now`，把运行时的 I/O 轮询与定时器触发
  控制在约 1ms 内，避免一次轮询长时间霸占线程导致超时先于结果触发。
- **UDP 结果判定**：绑定本地未指定地址的非阻塞套接字发送探测；先做一次非阻塞
  `recv`（多数探测与本地回应的 ICMP 错误几乎立即可得），只有在需要等待时才注册到
  Tokio 反应器；`recv_or_error` 同时关注 `READABLE` 与 `ERROR` 就绪事件，从而在
  Linux 上正确捕获 ICMP "port unreachable"。
- **有效载荷解析**：`build.rs` 中的解码器保留字面文本（如 SNMP 的 `public` 团体名、
  NetBIOS 名称、LDAP/SSDP 头部），并把跨多行的 `"..."` 片段无分隔拼接，保证探测
  字节与 Nmap 完全一致。
- **批量大小自适应（仅 Unix）**：当 `ulimit` 低于请求的批量时按经验下调（小于平均
  批量 3000 时取半、高于默认 8000 时取 3000，否则 `ulimit-100`）；Windows 直接使用
  用户请求值。

---

# 🔌 脚本引擎

`--scripts` 有三种取值（见 `src/scripts/mod.rs`）：

- `default`：运行内嵌的默认脚本——把发现的端口以
  `nmap -vvv -p {{port}} -{{ipversion}} {{ip}}` 的格式管道进系统的 `nmap`。
- `none`：不运行任何脚本，只显示端口扫描结果。
- `custom`：读取 `~/.rustscan_scripts.toml`（可用 `directory` 字段指定脚本目录），
  并按 `tags` 匹配 `~/.rustscan_scripts/` 下可读的脚本文件。

脚本文件头部以 `#` 注释提供 TOML 元数据（`tags`、`developer`、`port`、
`ports_separator`、`call_format`）。`call_format` 中的 `{{script}}`、`{{ip}}`、
`{{port}}` 会被替换为脚本完整路径、扫描得到的 IP 与端口。示例参见
[`fixtures/.rustscan_scripts/test_script.txt`](fixtures/.rustscan_scripts/test_script.txt)。

---

# 🧪 开发与测试

```bash
cargo build              # 构建（会执行 build.rs 生成 UDP 有效载荷表）
cargo test               # 单元测试与集成测试
cargo clippy --all-targets
cargo bench              # criterion 微基准（见 benches/）
```

性能基准报告：

- [延迟 DNS 解析基准](docs/lazy-dns-benchmark.md)
- [端口排除基准](docs/port-exclusion-benchmark.md)
- [ARM 支持说明](docs/arm-support.md)

贡献前请阅读 [`contributing.md`](contributing.md) 与
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)。

---

# 📄 许可证

RustScanX 继承原项目 RustScan 的许可证，采用 **GPL-3.0-only**，详见
[`LICENSE`](LICENSE)。

---

# 🙏 再次致谢

RustScanX 的一切可能性都建立在
[RustScan](https://github.com/bee-san/RustScan) 及其贡献者的工作之上。
如果你需要官方发行、包管理器支持与完整文档，请前往原项目：

> <https://github.com/bee-san/RustScan.git>

<!--Links-->

[discord]: http://discord.skerritt.blog "原项目 Discord 频道"
[speed-1]: pictures/fast.gif "速度"
[badge-2]: https://img.shields.io/badge/Built%20with-Rust-Purple
[badge-5]: https://img.shields.io/discord/754001738184392704
