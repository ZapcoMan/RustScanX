//! 实际扫描行为的核心功能。
use crate::generated::get_parsed_data;
use crate::port_strategy::PortStrategy;
use crate::tui::println_safe;
use log::debug;

mod socket_iterator;
use socket_iterator::SocketIterator;

mod errors;
use errors::{diagnostic_error, is_descriptor_exhaustion, ScanErrors};

use colored::Colorize;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::BTreeMap;
use std::future::poll_fn;
use std::task::Poll;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr},
    num::NonZeroU8,
    sync::Arc,
    time::Duration,
};
use tokio::io::Interest;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

/// 扫描在两次轮询运行时 I/O 驱动之间（合并计数）开始或完成多少个套接字；
/// 参见 `Scanner::scan_sockets`。
///
/// 每一轮都以对操作系统选择器的一次非阻塞轮询结尾，因此这将开销
/// 保持在远低于 1% 的同时，在 Linux 上把两次轮询之间的时间控
/// 制在大约一毫秒。
const WORK_PER_TURN: usize = 128;

/// 保留生成的顺序（包括重复端口），同时移除被排除的端口。
// 把位图排除在异步轮询帧之外，后者在每次唤醒时都会运行。
#[inline(never)]
fn filter_excluded_ports(mut ports: Vec<u16>, excluded: &[u16]) -> Vec<u16> {
    if excluded.is_empty() {
        return ports;
    }

    // 在较短的端口列表上，位图设置的开销比成员检查更大。
    if ports.len() < 64 {
        ports.retain(|port| !excluded.contains(port));
        return ports;
    }

    // 完整的 u16 端口空间恰好能放入一个 8 KiB 的位图。
    let mut excluded_bits = [0_u64; 1024];
    for &port in excluded {
        excluded_bits[usize::from(port) / 64] |= 1 << (port % 64);
    }
    ports.retain(|&port| excluded_bits[usize::from(port) / 64] & (1 << (port % 64)) == 0);
    ports
}

/// UDP 有效载荷查找：端口 -> 有效载荷字节
///
/// `get_parsed_data()` 返回一个 `&'static BTreeMap<...>`，因此我们可以
/// 存储对有效载荷字节的引用而无需克隆它们。
#[doc(hidden)]
pub type UdpPayloadLookup = HashMap<u16, &'static [u8]>;

#[doc(hidden)]
pub fn build_udp_payload_lookup(udp_map: &'static BTreeMap<Vec<u16>, Vec<u8>>) -> UdpPayloadLookup {
    let mut lookup: UdpPayloadLookup = HashMap::new();

    for (ports, payload_vec) in udp_map.iter() {
        let payload: &'static [u8] = payload_vec.as_slice();
        for &port in ports.iter() {
            // 保留现有行为：如果存在重复，最后一次插入生效。
            lookup.insert(port, payload);
        }
    }

    lookup
}

/// 扫描器的类
/// IP 是 IpAddr 数据类型，是 IP 地址
/// start 与 end 是端口扫描的开始与结束位置
/// batch_size 是一次应扫描多少个端口
/// Timeout 是 RustScan 在将端口判定为关闭之前应等待的时间，类型为 Duration。
/// greppable 表示 RustScan 是否应该打印内容，还是等到最后只打印 ip 和开放端口。
///
/// # 运行时
///
/// [`Scanner::run`] 和 [`Scanner::run_with_status`] 返回的 future 使用
/// Tokio 套接字和定时器，因此必须从一个同时启用了 I/O 和时间驱动
/// 的 [Tokio](https://docs.rs/tokio) 运行时内轮询它们（例如 `#[tokio::main]`，
/// 或用 `enable_all()` 构建的运行时）。从其他执行器轮询它们会 panic。
///
/// 扫描从不 spawn 任务：每个套接字都由你 await 的那个唯一 future 驱动，
/// 因此当前线程运行时已足够（`rustscan` 二进制用的就是它），
/// 而如果你更想在多线程运行时上 spawn，这个 future 是 `Send` 的。
#[cfg(not(tarpaulin_include))]
#[derive(Debug)]
pub struct Scanner {
    ips: Vec<IpAddr>,
    batch_size: usize,
    timeout: Duration,
    tries: NonZeroU8,
    greppable: bool,
    port_strategy: PortStrategy,
    accessible: bool,
    exclude_ports: Vec<u16>,
    udp: bool,
    print_open_ports: bool,
    report_closed: bool,
    interval: Duration,
}

/// 单个套接字的结果，由 [`Scanner::run_with_status`] 返回。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortStatus {
    /// TCP 连接成功，或 UDP 目标作出了回应。
    Open(SocketAddr),
    /// 目标主动拒绝了 TCP 连接（例如用 RST）。只有在启用
    /// [`Scanner::with_closed_ports`] 时才会报告。
    Closed(SocketAddr),
}

// 允许 clippy 忽略参数过多的问题。
#[allow(clippy::too_many_arguments)]
impl Scanner {
    pub fn new(
        ips: &[IpAddr],
        batch_size: usize,
        timeout: Duration,
        tries: u8,
        greppable: bool,
        port_strategy: PortStrategy,
        accessible: bool,
        exclude_ports: Vec<u16>,
        udp: bool,
    ) -> Self {
        Self {
            batch_size,
            timeout,
            tries: NonZeroU8::new(std::cmp::max(tries, 1)).unwrap(),
            greppable,
            port_strategy,
            ips: ips.iter().map(ToOwned::to_owned).collect(),
            accessible,
            exclude_ports,
            udp,
            print_open_ports: false,
            report_closed: false,
            interval: Duration::ZERO,
        }
    }

    /// 启用 CLI 的增量式开放端口输出。
    ///
    /// 库调用者默认是安静的，并且可以检查 [`Self::run`] 返回的套接字。
    #[must_use]
    pub fn with_open_port_output(mut self) -> Self {
        self.print_open_ports = true;
        self
    }

    /// 也报告主动拒绝连接的 TCP 端口，作为 [`Self::run_with_status`]
    /// 返回的 [`PortStatus::Closed`]。
    ///
    /// 超时的端口仍被视为被过滤且不报告。
    /// UDP 扫描从不报告关闭的端口。
    #[must_use]
    pub fn with_closed_ports(mut self) -> Self {
        self.report_closed = true;
        self
    }

    /// 在扫描完一个端口（在每个地址上）之后等待 `interval`，再
    /// 扫描下一个端口，用于缓慢、低噪声的扫描。
    ///
    /// 在一个端口内，仍会并发地扫描最多 `batch_size` 个地址。零间隔
    /// （默认值）则不分担延迟地批量扫描所有套接字。
    #[must_use]
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// 以分块大小运行 scan_range
    /// 如果你想正常地运行 RustScan，这就是所用的入口点
    /// 返回所有开放的套接字。
    pub async fn run(&self) -> Vec<SocketAddr> {
        self.run_with_status()
            .await
            .into_iter()
            .filter_map(|status| match status {
                PortStatus::Open(socket) => Some(socket),
                PortStatus::Closed(_) => None,
            })
            .collect()
    }

    /// 与 [`Self::run`] 类似，但返回每一个给出确定性答案的套接字的状态：
    /// 开放套接字，以及（启用 [`Self::with_closed_ports`] 时）关闭的套接字。
    pub async fn run_with_status(&self) -> Vec<PortStatus> {
        // 每一个在途的套接字都通过这个单一 future 经由一个
        // `FuturesUnordered` 被轮询。在 Tokio 的协作预算下，这个 future
        // 会在约 128 个套接字取得进展后被迫让出，而
        // `FuturesUnordered` 然后会重新轮询其他每一个就绪的套接字，仅仅
        // 是为了让它再次返回 `Pending`。选择退出；`scan_sockets` 自己
        // 会以每轮 `WORK_PER_TURN` 个套接字的方式向运行时让出。
        tokio::task::unconstrained(self.scan()).await
    }

    async fn scan(&self) -> Vec<PortStatus> {
        let ports = filter_excluded_ports(self.port_strategy.order(), &self.exclude_ports);
        let mut found_sockets: Vec<PortStatus> = Vec::new();
        let mut errors =
            ScanErrors::new(log::log_enabled!(log::Level::Debug), self.ips.len() * 1000);

        // 只构建一次 UDP 有效载荷查找表（仅当我们在扫描 UDP 时）。
        // 这避免了把一个大 map 克隆进每一个 spawn 的 future，并把
        // 有效载荷选择从 O(n) 变为 O(1)。
        let udp_payloads: Option<Arc<UdpPayloadLookup>> = if self.udp {
            Some(Arc::new(build_udp_payload_lookup(get_parsed_data())))
        } else {
            None
        };

        debug!("Start scanning sockets. \nBatch size {}\nNumber of ip-s {}\nNumber of ports {}\nTargets all together {}\nInterval between ports {:?}",
            self.batch_size,
            self.ips.len(),
            ports.len(),
            (self.ips.len() * ports.len()),
            self.interval);

        if self.interval.is_zero() {
            let sockets = SocketIterator::new(&self.ips, &ports);
            self.scan_sockets(sockets, &udp_payloads, &mut found_sockets, &mut errors)
                .await;
        } else {
            // 每次只扫描一个端口（在每个地址上）并在
            // 转向下一个端口之前等待 `interval`。
            for (i, port) in ports.iter().enumerate() {
                if i > 0 {
                    sleep(self.interval).await;
                }
                let sockets = SocketIterator::new(&self.ips, std::slice::from_ref(port));
                self.scan_sockets(sockets, &udp_payloads, &mut found_sockets, &mut errors)
                    .await;
            }
        }

        debug!("Typical socket connection errors {:?}", errors.messages());
        debug!("Sockets found: {:?}", found_sockets);
        found_sockets
    }

    /// 扫描 `sockets` 产出的每一个套接字，最多保持 `batch_size` 个
    /// 连接尝试在途。
    ///
    /// 以最多 [`WORK_PER_TURN`] 个为一轮来开始套接字并处理完成的，并在各轮之间
    /// 让运行时轮询 I/O 并触发定时器。否则对扫描 future 的一次轮询会一直
    /// 持续到没有任何套接字就绪，这可能耗时很长：一次性开始整个大批次，
    /// 或者一连串会立即全部完成的 UDP 探测。在此期间完成的
    /// 套接字只有在轮询结束后才会被注意到，因此它们的结果会延迟，
    /// 而如果轮询比超时更久，它们的定时器会在答案被看到之前就触发。
    async fn scan_sockets(
        &self,
        mut sockets: SocketIterator<'_>,
        udp_payloads: &Option<Arc<UdpPayloadLookup>>,
        found_sockets: &mut Vec<PortStatus>,
        errors: &mut ScanErrors,
    ) {
        let mut ftrs = FuturesUnordered::new();

        loop {
            let mut work = 0;
            while work < WORK_PER_TURN {
                let mut started = false;
                if ftrs.len() < self.batch_size {
                    if let Some(socket) = sockets.next() {
                        ftrs.push(self.scan_socket(socket, udp_payloads.clone()));
                        started = true;
                        work += 1;
                    }
                }

                // 不等待地轮询一次；这会启动新的套接字。
                match poll_fn(|cx| Poll::Ready(ftrs.poll_next_unpin(cx))).await {
                    Poll::Ready(Some(result)) => {
                        self.record(result, found_sockets, errors);
                        work += 1;
                    }
                    // 没有在途的，也没有剩下可启动的。
                    Poll::Ready(None) => return,
                    // 没有完成的；只要还有空间就继续启动套接字。
                    Poll::Pending if started => {}
                    Poll::Pending => break,
                }
            }

            if work >= WORK_PER_TURN {
                tokio::task::yield_now().await;
            } else {
                // 批次已满（或已完成），并且其中每个套接字都在
                // 等待网络。
                match ftrs.next().await {
                    Some(result) => self.record(result, found_sockets, errors),
                    None => return,
                }
            }
        }
    }

    /// 记录一个套接字的结果。
    fn record(
        &self,
        result: io::Result<PortStatus>,
        found_sockets: &mut Vec<PortStatus>,
        errors: &mut ScanErrors,
    ) {
        match result {
            Ok(status) => found_sockets.push(status),
            Err(error) => errors.record(error),
        }
    }

    /// 给定一个套接字，对它扫描 self.tries 次。
    /// 将地址转换为一个 SocketAddr
    /// 处理 `<result>` 类型
    /// 当操作系统报告描述符耗尽时 panic。
    /// 其他失败会保留各自的 I/O 错误，并为调试诊断附带目标上下文。
    /// 如果没有发生错误，它在 Result 中返回端口号以表示端口是开放的。
    /// 这个函数主要处理 Result 处理的逻辑。
    /// # 示例
    ///
    /// ```compile_fail
    /// scanner.scan_socket(socket)
    /// ```
    ///
    /// 注意：`self` 必须包含 `self.ip`。
    async fn scan_socket(
        &self,
        socket: SocketAddr,
        udp_payloads: Option<Arc<UdpPayloadLookup>>,
    ) -> io::Result<PortStatus> {
        if self.udp {
            return self.scan_udp_socket(socket, udp_payloads).await;
        }

        let tries = self.tries.get();
        for nr_try in 1..=tries {
            match self.connect(socket).await {
                Ok(tcp_stream) => {
                    debug!("Connection was successful, shutting down stream {}", socket);
                    if let Err(e) = shutdown_both(tcp_stream) {
                        debug!("Shutdown stream error {}", e);
                    }
                    self.fmt_ports(socket);

                    debug!("Return Ok after {nr_try} tries");
                    return Ok(PortStatus::Open(socket));
                }
                Err(e) => {
                    // 被拒绝的连接是一个确定性答案，因此
                    // 重试它没有意义。
                    if self.report_closed && e.kind() == io::ErrorKind::ConnectionRefused {
                        self.fmt_closed_port(socket);
                        return Ok(PortStatus::Closed(socket));
                    }

                    assert!(!is_descriptor_exhaustion(&e), "Too many open files. Please reduce batch size. The default is 5000. Try -b 2500.");

                    if nr_try == tries {
                        return Err(diagnostic_error(
                            e,
                            socket.ip(),
                            log::log_enabled!(log::Level::Debug),
                        ));
                    }
                }
            };
        }
        unreachable!();
    }

    async fn scan_udp_socket(
        &self,
        socket: SocketAddr,
        udp_payloads: Option<Arc<UdpPayloadLookup>>,
    ) -> io::Result<PortStatus> {
        let payload: &[u8] = udp_payloads
            .as_ref()
            .and_then(|m| m.get(&socket.port()).copied())
            .unwrap_or(b"");

        let tries = self.tries.get();
        for _ in 1..=tries {
            match self.udp_scan(socket, payload, self.timeout).await {
                Ok(true) => return Ok(PortStatus::Open(socket)),
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }

        Err(io::Error::other(format!(
            "UDP scan timed-out for all tries on socket {socket}"
        )))
    }

    /// 对套接字执行带超时的连接
    /// # 示例
    ///
    /// ```compile_fail
    /// # use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    /// let port: u16 = 80;
    /// // ip is an IpAddr type
    /// let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    /// let socket = SocketAddr::new(ip, port);
    /// scanner.connect(socket);
    /// // returns Result which is either Ok(stream) for port is open, or Er for port is closed.
    /// // Timeout occurs after self.timeout seconds
    /// ```
    ///
    async fn connect(&self, socket: SocketAddr) -> io::Result<TcpStream> {
        timeout(self.timeout, TcpStream::connect(socket))
            .await
            .unwrap_or_else(|_elapsed| Err(timed_out()))
    }

    /// 在目标地址族的未指定地址上绑定一个非阻塞的 UDP 套接字，
    /// 以便我们可以收发数据包。
    fn udp_bind(socket: SocketAddr) -> io::Result<std::net::UdpSocket> {
        let local_addr = match socket {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };

        let udp_socket = std::net::UdpSocket::bind(local_addr)?;
        udp_socket.set_nonblocking(true)?;
        Ok(udp_socket)
    }

    /// 对指定的套接字使用一个有效载荷和一个等待时长执行一次 UDP 扫描
    /// # 示例
    ///
    /// ```compile_fail
    /// # use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    /// # use std::time::Duration;
    /// let port: u16 = 123;
    /// // ip is an IpAddr type
    /// let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    /// let socket = SocketAddr::new(ip, port);
    /// let payload = vec![0, 1, 2, 3];
    /// let wait = Duration::from_secs(1);
    /// let result = scanner.udp_scan(socket, payload, wait).await;
    /// // returns Result which is either Ok(true) if response received, or Ok(false) if timed out.
    /// // Err is returned for other I/O errors.
    async fn udp_scan(
        &self,
        socket: SocketAddr,
        payload: &[u8],
        wait: Duration,
    ) -> io::Result<bool> {
        let udp_socket = match Self::udp_bind(socket) {
            Ok(udp_socket) => udp_socket,
            Err(e) => {
                debug!("Error binding UDP socket: {e:?}");
                return Err(e);
            }
        };
        let mut buf = [0u8; 1024];

        udp_socket.connect(socket)?;

        // 发送探测并立即尝试第一次接收，就像 async-std 之前做的那样。
        // Tokio 基于就绪性的 I/O 会先等待反应器报告套接字就绪，使
        // 每次探测都额外往返事件循环，而探测几乎总能立即发送，
        // 并且在本地主机上，答案（通常是 ICMP "port unreachable"，表现为
        // 被拒绝的连接）在 send 返回时往往已经就绪。只有在确实
        // 需要等待时，套接字才会在 Tokio 上注册。
        let sent = match udp_socket.send(payload) {
            Ok(_) => true,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
            Err(e) => return Err(e),
        };
        let early = if sent {
            udp_socket.recv(&mut buf)
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        };

        let received = match early {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                let udp_socket = UdpSocket::from_std(udp_socket)?;
                if !sent {
                    udp_socket.send(payload).await?;
                }
                match timeout(wait, recv_or_error(&udp_socket, &mut buf)).await {
                    Ok(received) => received,
                    // 没有东西及时返回。
                    Err(_elapsed) => return Ok(false),
                }
            }
            early => early,
        };

        match received {
            Ok(size) => {
                debug!("Received {size} bytes");
                self.fmt_ports(socket);
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 格式化并打印端口状态
    fn fmt_ports(&self, socket: SocketAddr) {
        if self.print_open_ports && !self.greppable {
            if self.accessible {
                println_safe(format_args!("Open {socket}"));
            } else {
                println_safe(format_args!("Open {}", socket.to_string().purple()));
            }
        }
    }

    /// 打印一个关闭的端口（仅 CLI 输出，绝不以 greppable 模式输出）。
    fn fmt_closed_port(&self, socket: SocketAddr) {
        if self.print_open_ports && !self.greppable {
            if self.accessible {
                println_safe(format_args!("Closed {socket}"));
            } else {
                println_safe(format_args!("Closed {}", socket.to_string().red()));
            }
        }
    }
}

/// 在一个已连接的流被关闭之前，关闭它的两端，就像 async-std 的
/// 实现所做的那样（`TcpStream::shutdown(Shutdown::Both)`）。
///
/// Tokio 只提供异步的写端关闭，因此把套接字从反应器取回，
/// 改为同步地关闭它。
fn shutdown_both(stream: TcpStream) -> io::Result<()> {
    stream.into_std()?.shutdown(Shutdown::Both)
}

/// 在一个已连接的 UDP 套接字上等待一个数据报，或等待系统为其排队的
/// 错误：ICMP "port unreachable" 会作为被拒绝的连接上报，这就是
/// 区分关闭的 UDP 端口与被过滤端口的方式。
///
/// 在 Linux 上，单靠 `UdpSocket::recv` 做不到这一点：排队的 ICMP 错误
/// 只会 raise `EPOLLERR`，而 Tokio 不把它视为可读，因此 `recv` 会
/// 一直休眠到超时。async-io 则将 `EPOLLERR` 视为可读。
async fn recv_or_error(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let ready = socket.ready(Interest::READABLE | Interest::ERROR).await?;

        if ready.is_readable() {
            match socket.try_recv(buf) {
                // 一次虚假唤醒；再等待（除非套接字对读已关闭，
                // 那会永远唤醒我们）。
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && !ready.is_read_closed() => {}
                received => return received,
            }
        }

        if ready.is_error() {
            // 取回（并清除）排队的错误。当没有错误时 `WouldBlock` 会让
            // Tokio 清除错误就绪状态，因此这里不会空转。
            let queued = socket.try_io(Interest::ERROR, || {
                socket
                    .take_error()?
                    .map_or_else(|| Err(io::ErrorKind::WouldBlock.into()), Ok)
            });
            match queued {
                Ok(error) => return Err(error),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// 对命中超时的连接尝试所报告的错误；与 async-std 的 `io::timeout`
/// 使用的相同种类和消息。
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "future timed out")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::input::{PortRanges, ScanOrder};
    use std::collections::HashSet;

    // 这些测试从不打开套接字：它们只构建一个 `Scanner`（及其
    // future），运行一个没有套接字可扫的扫描，或检查由 build.rs
    // 生成的有效载荷表。

    fn test_scanner() -> Scanner {
        let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
        let strategy = PortStrategy::pick(&Some(PortRanges(vec![(1, 1)])), None, ScanOrder::Serial);
        Scanner::new(
            &addrs,
            1,
            Duration::from_millis(100),
            1,
            false,
            strategy,
            false,
            Vec::new(),
            false,
        )
    }

    #[test]
    fn port_exclusions_preserve_order_duplicates_and_boundaries() {
        let inputs = [
            Vec::new(),
            vec![65535, 0, 80, 443, 80, 65535, 1],
            (0..=65535).collect(),
            PortStrategy::pick(&Some(PortRanges(vec![(0, 1023)])), None, ScanOrder::Random).order(),
        ];
        let exclusions = [
            Vec::new(),
            vec![0],
            vec![0, 65535, 0, 443],
            (0..1024).collect(),
            (0..=65535).collect(),
        ];

        for ports in inputs {
            for excluded in &exclusions {
                let excluded_set: HashSet<_> = excluded.iter().copied().collect();
                let expected: Vec<u16> = ports
                    .iter()
                    .filter(|&port| !excluded_set.contains(port))
                    .copied()
                    .collect();
                assert_eq!(filter_excluded_ports(ports.clone(), excluded), expected);
            }
        }
    }

    #[test]
    fn library_scanner_is_quiet_by_default() {
        let scanner = test_scanner();

        assert!(!scanner.print_open_ports);
    }

    #[test]
    fn cli_can_enable_open_port_output() {
        let scanner = test_scanner().with_open_port_output();

        assert!(scanner.print_open_ports);
    }

    #[test]
    fn closed_ports_are_not_reported_by_default() {
        assert!(!test_scanner().report_closed);
    }

    #[test]
    fn closed_port_reporting_is_opt_in() {
        assert!(test_scanner().with_closed_ports().report_closed);
    }

    #[test]
    fn no_interval_by_default() {
        assert!(test_scanner().interval.is_zero());
    }

    #[test]
    fn with_interval_sets_the_delay_between_ports() {
        let scanner = test_scanner().with_interval(Duration::from_millis(250));

        assert_eq!(scanner.interval, Duration::from_millis(250));
    }

    /// 嵌入者可以在多线程运行时上 spawn 扫描，这需要
    /// `Send` 的 future。这里的 future 只被创建、从不被轮询，因此
    /// 不会打开任何套接字。
    #[test]
    fn scan_futures_are_send() {
        fn assert_send<T: Send>(_: &T) {}

        let scanner = test_scanner();
        assert_send(&scanner.run());
        assert_send(&scanner.run_with_status());
    }

    /// 在与 CLI 所构建同类的运行时上驱动一次扫描。每个端口
    /// 都被排除，因此扫描没有套接字可打开并立即返回。
    #[test]
    fn scan_without_sockets_completes_on_a_current_thread_runtime() {
        let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        for interval in [Duration::ZERO, Duration::from_millis(10)] {
            let scanner = Scanner::new(
                &addrs,
                10,
                Duration::from_millis(100),
                1,
                true,
                PortStrategy::Manual(vec![1, 2]),
                true,
                vec![1, 2],
                false,
            )
            .with_interval(interval);

            assert!(runtime.block_on(scanner.run_with_status()).is_empty());
        }
    }

    #[test]
    fn timeouts_are_reported_as_timed_out_errors() {
        let error = timed_out();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "future timed out");
    }

    /// 针对 https://github.com/bee-san/RustScan/issues/933 的回归测试：
    /// SNMP 公开遍历探测必须是精确的 33 字节 BER 数据包，且字面量
    /// `public` 团体名（community string）保持完好。旧的仅十六进制数字
    /// 解码会把它改成一个 28 字节的探测，代理从不回应。
    #[test]
    fn udp_snmp_probe_bytes_match_nmap() {
        let payload = get_parsed_data()
            .iter()
            .find(|(ports, _)| ports.contains(&161))
            .map(|(_, payload)| payload)
            .expect("no UDP payload registered for port 161");
        let expected: Vec<u8> = vec![
            0x30, 0x1f, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa1,
            0x12, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x07, 0x30, 0x05,
            0x06, 0x01, 0x00, 0x05, 0x00,
        ];
        assert_eq!(*payload, expected);
    }

    /// SSDP 探测跨两个带引号的片段混合了 `\xNN` 转义、`\"` 转义和字面文本：
    /// 各片段必须解码并拼接在一起，且无分隔符。
    #[test]
    fn udp_ssdp_probe_decodes_escapes_and_literal_text() {
        let payload = get_parsed_data()
            .iter()
            .find(|(ports, _)| ports.contains(&1900))
            .map(|(_, payload)| payload)
            .expect("no UDP payload registered for port 1900");
        let expected =
            b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nMX: 5\r\nST: ssdp:all\r\n\r\n"
                .to_vec();
        assert_eq!(*payload, expected);
    }
}
