//! 提供用于解析输入的 IP 地址、CIDR 或文件的函数。
use std::cell::LazyCell;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{prelude::*, BufReader};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;

use cidr_utils::cidr::{IpCidr, IpInet};
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    Resolver,
};
use log::debug;

use crate::input::Opts;
use crate::warning;

/// 将字符串解析为 IP 地址。
///
/// 会遍历所有可能的 IP 输入方式（文件或通过参数解析）。
///
/// ```rust
/// # use rustscanx::input::Opts;
/// # use rustscanx::address::parse_addresses;
/// let mut opts = Opts::default();
/// opts.addresses = vec!["192.168.0.0/30".to_owned()];
///
/// let ips = parse_addresses(&opts);
/// ```
///
/// 最后，会移除任何重复项，以避免过度扫描。
///
/// # 阻塞
///
/// 这个函数会阻塞：它读取文件并解析主机名，而 hickory 的同步
/// [`Resolver`] 会运行自己的一个 Tokio 运行时，而 Tokio 拒绝在异步上下文中
/// 销毁它。请在启动你的运行时之前（正如 `rustscanx` 二进制所做的那样），或从
/// `tokio::task::spawn_blocking` 中调用它，而不是直接从 async 代码调用。
pub fn parse_addresses(input: &Opts) -> Vec<IpAddr> {
    parse_addresses_with_resolver(input, || get_resolver(&input.resolver))
}

fn parse_addresses_with_resolver(
    input: &Opts,
    create_resolver: impl FnOnce() -> Resolver,
) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    let mut unresolved_addresses: Vec<&str> = Vec::new();
    // 大多数扫描使用字面量 IP 或 CIDR。把解析器的运行时以及
    // hosts 文件加载推迟到 DNS 回退真正需要它们的时候，然后为
    // 其余的目标和排除项复用那个解析器。
    let backup_resolver = LazyCell::new(create_resolver);
    let resolver = || &*backup_resolver;

    for address in &input.addresses {
        let parsed_ips = parse_address_with_resolver(address, &resolver);
        if !parsed_ips.is_empty() {
            ips.extend(parsed_ips);
        } else {
            unresolved_addresses.push(address);
        }
    }

    // 如果能走到这一步，那它只能是一个文件路径，或者是错误的输入。
    for file_path in unresolved_addresses {
        let file_path = Path::new(file_path);

        if !file_path.is_file() {
            warning!(
                format!("Host {file_path:?} could not be resolved."),
                input.greppable,
                input.accessible
            );

            continue;
        }

        if let Ok(x) = read_ips_from_file(file_path, &resolver) {
            ips.extend(x);
        } else {
            warning!(
                format!("Host {file_path:?} could not be resolved."),
                input.greppable,
                input.accessible
            );
        }
    }

    let excluded_cidrs = parse_excluded_networks_with_resolver(&input.exclude_addresses, &resolver);

    // 移除重复/被排除的 IP。
    let mut seen = BTreeSet::new();
    ips.retain(|ip| seen.insert(*ip) && !excluded_cidrs.iter().any(|cidr| cidr.contains(ip)));

    ips
}

/// 给定一个字符串，将其解析为主机、IP 地址或 CIDR。
///
/// 这让我们可以轻松地把文件作为主机、cidr 或 IP 传入
/// 每次你有一个可能是 IP 或主机的输入时都调用它。
///
/// 如果地址是一个域名，我们可以在本地自行解析该域名，
/// 或通过 DNS 解析器列表来解析它。
///
/// ```rust
/// # use rustscanx::address::parse_address;
/// # use hickory_resolver::Resolver;
/// let ips = parse_address("127.0.0.1", &Resolver::default().unwrap());
/// ```
pub fn parse_address(address: &str, resolver: &Resolver) -> Vec<IpAddr> {
    parse_address_with_resolver(address, &|| resolver)
}

fn parse_address_with_resolver<'a>(
    address: &str,
    resolver: &impl Fn() -> &'a Resolver,
) -> Vec<IpAddr> {
    if let Ok(addr) = IpAddr::from_str(address) {
        // `address` 是一个 IP 字符串
        vec![addr]
    } else if let Ok(net_addr) = IpInet::from_str(address) {
        // `address` 是一个 CIDR 字符串
        net_addr.network().into_iter().addresses().collect()
    } else {
        // `address` 是一个主机名或 DNS 名称
        // 尝试默认的 DNS 查找
        match format!("{address}:80").to_socket_addrs() {
            Ok(mut iter) => vec![iter.next().unwrap().ip()],
            // 默认查找没成功，因此改用专用解析器重试
            Err(_) => resolve_ips_from_host(address, resolver),
        }
    }
}

/// 使用 DNS 获取与该主机关联的 IP
fn resolve_ips_from_host<'a>(
    source: &str,
    backup_resolver: &impl Fn() -> &'a Resolver,
) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();

    if let Ok(addrs) = source.to_socket_addrs() {
        for ip in addrs {
            ips.push(ip.ip());
        }
    } else if let Ok(addrs) = backup_resolver().lookup_ip(source) {
        ips.extend(addrs.iter());
    }

    ips
}

/// 从地址列表中解析被排除的网络。
///
/// 这个函数处理三种类型的输入：
/// 1. CIDR 记法（例如 "192.168.0.0/24"）
/// 2. 单个 IP 地址（例如 "192.168.0.1"）
/// 3. 需要被解析的主机名（例如 "example.com"）
///
/// ```rust
/// # use rustscanx::address::parse_excluded_networks;
/// # use hickory_resolver::Resolver;
/// let resolver = Resolver::default().unwrap();
/// let excluded = parse_excluded_networks(&Some(vec!["192.168.0.0/24".to_owned()]), &resolver);
/// ```
pub fn parse_excluded_networks(
    exclude_addresses: &Option<Vec<String>>,
    resolver: &Resolver,
) -> Vec<IpCidr> {
    parse_excluded_networks_with_resolver(exclude_addresses, &|| resolver)
}

fn parse_excluded_networks_with_resolver<'a>(
    exclude_addresses: &Option<Vec<String>>,
    resolver: &impl Fn() -> &'a Resolver,
) -> Vec<IpCidr> {
    exclude_addresses
        .iter()
        .flatten()
        .flat_map(|addr| parse_single_excluded_address(addr, resolver))
        .collect()
}

/// 将单个地址解析为 IpCidr，处理 CIDR 记法、IP 地址和主机名。
fn parse_single_excluded_address<'a>(
    addr: &str,
    resolver: &impl Fn() -> &'a Resolver,
) -> Vec<IpCidr> {
    if let Ok(cidr) = IpCidr::from_str(addr) {
        return vec![cidr];
    }

    if let Ok(ip) = IpAddr::from_str(addr) {
        return vec![IpCidr::new_host(ip)];
    }

    resolve_ips_from_host(addr, resolver)
        .into_iter()
        .map(IpCidr::new_host)
        .collect()
}

/// 派生一个 DNS 解析器。
///
/// 1. 如果设置了 `resolver` 参数：
///     1. 假定该参数是一个路径，并尝试从中读取 IP。
///     2. 将输入解析为一个以逗号分隔的 IP 列表。
/// 2. 如果未设置 `resolver`：
///    1. 尝试从系统配置派生一个解析器（例如
///       *nix 上的 `/etc/resolv.conf`）。
///    2. 最后，构建一个基于 CloudFlare 的解析器（默认
///       行为）。
fn get_resolver(resolver: &Option<String>) -> Resolver {
    match resolver {
        Some(r) => {
            let mut config = ResolverConfig::new();
            let resolver_ips = match read_resolver_from_file(r) {
                Ok(ips) => ips,
                Err(_) => r
                    .split(',')
                    .filter_map(|r| IpAddr::from_str(r).ok())
                    .collect::<Vec<_>>(),
            };
            for ip in resolver_ips {
                config.add_name_server(NameServerConfig::new(
                    SocketAddr::new(ip, 53),
                    Protocol::Udp,
                ));
            }
            Resolver::new(config, resolver_opts()).unwrap()
        }
        None => match system_resolver() {
            Ok(resolver) => resolver,
            Err(_) => Resolver::new(ResolverConfig::cloudflare_tls(), resolver_opts()).unwrap(),
        },
    }
}

/// 在 Windows 上，当 `SystemRoot` 环境变量未设置时返回 `true`。
///
/// hickory-resolver 通过
/// `std::env::var_os("SystemRoot").expect(...)` 来定位 hosts 文件，
/// 当该变量缺失时会 panic。以最小环境启动的进程
/// （服务、计划任务、WMI）可能没有 `SystemRoot`，而在本 crate 的
/// `panic = "abort"` release 配置下，这个 panic 是致命的。
fn windows_system_root_missing() -> bool {
    cfg!(windows) && std::env::var_os("SystemRoot").is_none()
}

/// 从系统配置派生一个解析器，例如 *nix 上的 `/etc/resolv.conf`
/// 或 Windows 上的注册表。
///
/// 当这么做会在 hickory-resolver 内部 panic 时，直接返回一个错误而
/// 不去触碰系统配置（参见 [`windows_system_root_missing`]）。
fn system_resolver() -> std::io::Result<Resolver> {
    if windows_system_root_missing() {
        debug!("SystemRoot is not set; skipping system resolver configuration");
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "SystemRoot environment variable is not set",
        ));
    }

    Resolver::from_system_conf()
}

/// 在当前环境下可安全使用的解析器选项。
///
/// 当 `use_hosts_file` 被设置（默认值）时，hickory-resolver 会主动加载 hosts 文件，
/// 这会触发 [`windows_system_root_missing`] 中所描述的同样缺失-`SystemRoot` 的 panic；
/// 在那种情况下将其禁用。
fn resolver_opts() -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    if windows_system_root_missing() {
        opts.use_hosts_file = false;
    }
    opts
}

/// 解析一个包含 IP 的输入文件，用于 DNS 解析。
fn read_resolver_from_file(path: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    let ips = fs::read_to_string(path)?
        .lines()
        .filter_map(|line| IpAddr::from_str(line.trim()).ok())
        .collect();

    Ok(ips)
}

#[cfg(not(tarpaulin_include))]
/// 解析一个包含 IP 的输入文件并使用其中的 IP
fn read_ips_from_file<'a>(
    ips: &std::path::Path,
    backup_resolver: &impl Fn() -> &'a Resolver,
) -> Result<Vec<IpAddr>, std::io::Error> {
    let file = File::open(ips)?;
    let reader = BufReader::new(file);

    let mut ips: Vec<IpAddr> = Vec::new();

    for address_line in reader.lines() {
        if let Ok(address) = address_line {
            ips.extend(parse_address_with_resolver(&address, backup_resolver));
        } else {
            debug!("Line in file is not valid");
        }
    }

    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::{parse_addresses, parse_addresses_with_resolver, Opts};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn literal_targets_and_exclusions_do_not_initialize_a_resolver() {
        let opts = Opts {
            addresses: vec![
                "192.0.2.0/30".to_owned(),
                "192.0.2.2".to_owned(),
                "2001:db8::/126".to_owned(),
                "2001:db8::3".to_owned(),
            ],
            exclude_addresses: Some(vec![
                "192.0.2.0/31".to_owned(),
                "192.0.2.3".to_owned(),
                "2001:db8::/127".to_owned(),
                "2001:db8::3".to_owned(),
            ]),
            ..Default::default()
        };

        let ips = parse_addresses_with_resolver(&opts, || {
            panic!("literal targets and exclusions must not initialize DNS")
        });

        assert_eq!(
            ips,
            [
                "192.0.2.2".parse::<IpAddr>().unwrap(),
                "2001:db8::2".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn empty_targets_do_not_initialize_a_resolver() {
        assert!(parse_addresses_with_resolver(&Opts::default(), || {
            panic!("empty targets must not initialize DNS")
        })
        .is_empty());
    }

    #[test]
    fn parse_correct_addresses() {
        let opts = Opts {
            addresses: vec!["127.0.0.1".to_owned(), "192.168.0.0/30".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(192, 168, 0, 0),
                Ipv4Addr::new(192, 168, 0, 1),
                Ipv4Addr::new(192, 168, 0, 2),
                Ipv4Addr::new(192, 168, 0, 3)
            ]
        );
    }

    #[test]
    fn parse_addresses_with_address_exclusions() {
        let opts = Opts {
            addresses: vec!["192.168.0.0/30".to_owned()],
            exclude_addresses: Some(vec!["192.168.0.1".to_owned()]),
            ..Default::default()
        };
        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(192, 168, 0, 0),
                Ipv4Addr::new(192, 168, 0, 2),
                Ipv4Addr::new(192, 168, 0, 3)
            ]
        );
    }

    #[test]
    fn parse_addresses_with_cidr_exclusions() {
        let opts = Opts {
            addresses: vec!["192.168.0.0/29".to_owned()],
            exclude_addresses: Some(vec!["192.168.0.0/30".to_owned()]),
            ..Default::default()
        };
        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(192, 168, 0, 4),
                Ipv4Addr::new(192, 168, 0, 5),
                Ipv4Addr::new(192, 168, 0, 6),
                Ipv4Addr::new(192, 168, 0, 7),
            ]
        );
    }

    #[test]
    fn parse_addresses_with_incorrect_address_exclusions() {
        let opts = Opts {
            addresses: vec!["192.168.0.0/30".to_owned()],
            exclude_addresses: Some(vec!["192.168.0.1".to_owned()]),
            ..Default::default()
        };
        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(192, 168, 0, 0),
                Ipv4Addr::new(192, 168, 0, 2),
                Ipv4Addr::new(192, 168, 0, 3)
            ]
        );
    }

    #[test]
    fn parse_duplicate_cidrs() {
        let opts = Opts {
            addresses: vec!["79.98.104.0/21".to_owned(), "79.98.104.0/24".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 2_048);
    }

    #[test]
    fn parse_overspecific_cidr() {
        // 规范的 CIDR 字符串在所有主机位上都是 0，但我们希望把任何形似 CIDR 的字符串都当作 CIDR 来处理
        let opts = Opts {
            addresses: vec!["192.128.1.1/24".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 256);
    }

    #[test]
    fn parse_non_canonical_cidr_mid_block() {
        // 192.168.1.13/29：.13 = 0000 1101，掩码清掉最后 3 位 → .8 = 0000 1000
        // 网络是 192.168.1.8/29，覆盖 .8 到 .15
        let opts = Opts {
            addresses: vec!["192.168.1.13/29".to_owned()],
            ..Default::default()
        };
        let ips = parse_addresses(&opts);
        assert_eq!(
            ips,
            [
                Ipv4Addr::new(192, 168, 1, 8),
                Ipv4Addr::new(192, 168, 1, 9),
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 11),
                Ipv4Addr::new(192, 168, 1, 12),
                Ipv4Addr::new(192, 168, 1, 13),
                Ipv4Addr::new(192, 168, 1, 14),
                Ipv4Addr::new(192, 168, 1, 15),
            ]
        );
    }

    #[test]
    fn parse_non_canonical_cidr_last_in_block() {
        // 192.168.1.15/29：块中的最后一个地址，仍应解析到同一个 .8–.15 网络
        let opts = Opts {
            addresses: vec!["192.168.1.15/29".to_owned()],
            ..Default::default()
        };
        let ips = parse_addresses(&opts);
        assert_eq!(
            ips,
            [
                Ipv4Addr::new(192, 168, 1, 8),
                Ipv4Addr::new(192, 168, 1, 9),
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 11),
                Ipv4Addr::new(192, 168, 1, 12),
                Ipv4Addr::new(192, 168, 1, 13),
                Ipv4Addr::new(192, 168, 1, 14),
                Ipv4Addr::new(192, 168, 1, 15),
            ]
        );
    }

    #[test]
    fn parse_non_canonical_cidr_crosses_third_octet() {
        // 192.168.1.5/23：主机位延伸到第三个八位组
        // .1.5 在 23 位上下文下 → 网络是 192.168.0.0/23，覆盖 .0.0 到 .1.255（512 个地址）
        let opts = Opts {
            addresses: vec!["192.168.1.5/23".to_owned()],
            ..Default::default()
        };
        let ips = parse_addresses(&opts);
        assert_eq!(
            ips.first(),
            Some(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)))
        );
        assert_eq!(
            ips.last(),
            Some(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)))
        );
        assert_eq!(ips.len(), 512);
    }

    #[test]
    fn parse_non_canonical_cidr_slash30() {
        // 10.0.0.7/30：.7 = 0000 0111，掩码清掉最后 2 位 → .4 = 0000 0100
        // 网络是 10.0.0.4/30，覆盖 .4 到 .7
        let opts = Opts {
            addresses: vec!["10.0.0.7/30".to_owned()],
            ..Default::default()
        };
        let ips = parse_addresses(&opts);
        assert_eq!(
            ips,
            [
                Ipv4Addr::new(10, 0, 0, 4),
                Ipv4Addr::new(10, 0, 0, 5),
                Ipv4Addr::new(10, 0, 0, 6),
                Ipv4Addr::new(10, 0, 0, 7),
            ]
        );
    }
}
