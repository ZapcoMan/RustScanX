#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::if_not_else, clippy::non_ascii_literal)]

use rustscanx::benchmark::{Benchmark, NamedTimer};
use rustscanx::input::{self, Config, Opts, ScriptsRequired};
use rustscanx::port_strategy::PortStrategy;
use rustscanx::scanner::{PortStatus, Scanner};
use rustscanx::scripts::{init_scripts, Script, ScriptFile};
use rustscanx::tui::println_safe;
use rustscanx::{detail, funny_opening, output, warning};

use colorful::{Color, Colorful};
use std::collections::HashMap;
use std::net::IpAddr;
use std::string::ToString;
use std::time::Duration;

use rustscanx::address::parse_addresses;

extern crate colorful;
extern crate dirs;

// Ubuntu 上的平均值
#[cfg(unix)]
const DEFAULT_FILE_DESCRIPTORS_LIMIT: usize = 8000;
// 基于实验得出的最安全批量大小
#[cfg(unix)]
const AVERAGE_BATCH_SIZE: usize = 3000;

#[macro_use]
extern crate log;

#[cfg(not(tarpaulin_include))]
#[allow(clippy::too_many_lines)]
/// 使用 Rust 实现更快的 Nmap 扫描
/// 如果你在寻找真正的扫描逻辑，请查看 Scanner 模块
fn main() {
    #[cfg(not(unix))]
    let _ = ansi_term::enable_ansi_support();

    env_logger::init();
    let mut benchmarks = Benchmark::init();
    let mut rustscan_bench = NamedTimer::start("RustScan");

    let mut opts: Opts = Opts::read();
    let config = Config::read(opts.config_path.clone());
    opts.merge(&config);

    if let Err(message) = opts.validate_platform() {
        eprintln!("error: {message}");
        std::process::exit(2);
    }

    debug!("Main() `opts` arguments are {opts:?}");

    let scripts_to_run: Vec<ScriptFile> = match init_scripts(&opts.scripts) {
        Ok(scripts_to_run) => scripts_to_run,
        Err(e) => {
            warning!(
                format!("Initiating scripts failed!\n{e}"),
                opts.greppable,
                opts.accessible
            );
            std::process::exit(1);
        }
    };

    debug!("Scripts initialized {scripts_to_run:?}");

    if !opts.greppable && !opts.accessible && !opts.no_banner {
        print_opening(&opts);
    }

    let ips: Vec<IpAddr> = parse_addresses(&opts);

    if ips.is_empty() {
        warning!(
            "No IPs could be resolved, aborting scan.",
            opts.greppable,
            opts.accessible
        );
        std::process::exit(1);
    }

    let batch_size = effective_batch_size(&opts);
    debug!("Effective batch size: {batch_size}");

    let mut scanner = Scanner::new(
        &ips,
        batch_size,
        Duration::from_millis(opts.timeout.into()),
        opts.tries,
        opts.greppable,
        PortStrategy::pick(&opts.range, opts.ports, opts.scan_order),
        opts.accessible,
        opts.exclude_ports.unwrap_or_default(),
        opts.udp,
    )
    .with_open_port_output();
    if opts.closed {
        scanner = scanner.with_closed_ports();
    }
    if opts.interval > 0 {
        scanner = scanner.with_interval(Duration::from_millis(opts.interval));
    }
    debug!("Scanner finished building: {scanner:?}");

    let mut portscan_bench = NamedTimer::start("Portscan");
    let scan_result = match run_scan(&scanner) {
        Ok(scan_result) => scan_result,
        Err(e) => {
            eprintln!("error: could not start the scan: {e}");
            std::process::exit(1);
        }
    };
    portscan_bench.end();
    benchmarks.push(portscan_bench);

    let mut ports_per_ip: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    let mut closed_ports_per_ip: HashMap<IpAddr, Vec<u16>> = HashMap::new();

    for status in scan_result {
        let (map, socket) = match status {
            PortStatus::Open(socket) => (&mut ports_per_ip, socket),
            PortStatus::Closed(socket) => (&mut closed_ports_per_ip, socket),
        };
        map.entry(socket.ip()).or_default().push(socket.port());
    }

    for ip in ips {
        if ports_per_ip.contains_key(&ip) {
            continue;
        }

        // 如果执行到这里，说明 HashMap 中没找到这个 IP，
        // 意味着扫描没有为它找到任何开放端口。

        let x = format!("Looks like I didn't find any open ports for {:?}. This is usually caused by a high batch size.
        \n*I used {} batch size, consider lowering it with {} or a comfortable number for your system.
        \n Alternatively, increase the timeout if your ping is high. Rustscan -t 2000 for 2000 milliseconds (2s) timeout.\n",
        ip,
        batch_size,
        "'rustscan -b <batch_size> -a <ip address>'");
        warning!(x, opts.greppable, opts.accessible);
    }

    let mut script_bench = NamedTimer::start("Scripts");
    for (ip, ports) in &ports_per_ip {
        let vec_str_ports: Vec<String> = ports.iter().map(ToString::to_string).collect();

        // nmap 的端口写法是 80,443。以逗号分隔且无空格。
        let ports_str = vec_str_ports.join(",");

        // 如果 scripts 选项为 none，则不会启动任何脚本
        if opts.greppable || opts.scripts == ScriptsRequired::None {
            println_safe(format_args!("{ip} -> [{ports_str}]"));
            continue;
        }
        detail!("Starting Script(s)", opts.greppable, opts.accessible);

        // 根据脚本配置文件的 tags 字段，运行我们查找并解析到的所有脚本。
        for script_f in &scripts_to_run {
            // 只克隆正在运行的那个脚本，而不是为每个 IP 克隆整个列表。
            let mut script_f = script_f.clone();
            // 这部分允许我们向 Script 的 call_format 添加命令行参数，将它们追加到命令末尾。
            if !opts.command.is_empty() {
                let user_extra_args = &opts.command.join(" ");
                debug!("Extra args vec {user_extra_args:?}");
                if script_f.call_format.is_some() {
                    let mut call_f = script_f.call_format.unwrap();
                    call_f.push(' ');
                    call_f.push_str(user_extra_args);
                    output!(
                        format!("Running script {:?} on ip {}\nDepending on the complexity of the script, results may take some time to appear.", call_f, &ip),
                        opts.greppable,
                        opts.accessible
                    );
                    debug!("Call format {call_f}");
                    script_f.call_format = Some(call_f);
                }
            }

            // 使用来自 ScriptFile 的参数以及 ip-ports 来构建脚本。
            let script = Script::build(
                script_f.path,
                *ip,
                ports.clone(),
                script_f.port,
                script_f.ports_separator,
                script_f.tags,
                script_f.call_format,
            );
            match script.run() {
                Ok(script_result) => {
                    detail!(script_result.clone(), opts.greppable, opts.accessible);
                }
                Err(e) => {
                    warning!(&format!("Error {e}"), opts.greppable, opts.accessible);
                }
            }
        }
    }

    // 关闭的端口只会被列出；绝不会针对它们运行脚本。
    if opts.closed {
        println_safe(format_args!("closed ports:"));
        for (ip, ports) in &closed_ports_per_ip {
            let ports_str = ports
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            println_safe(format_args!("{ip} -> [{ports_str}]"));
        }
    }

    // 要使用运行时基准测试，请按如下方式运行进程：RUST_LOG=info ./rustscan
    script_bench.end();
    benchmarks.push(script_bench);
    rustscan_bench.end();
    benchmarks.push(rustscan_bench);
    debug!("Benchmarks raw {benchmarks:?}");
    info!("{}", benchmarks.summary());
}

/// 确定扫描器实际使用的批量大小。
///
/// Unix 系统可能会根据进程的文件描述符限额来降低所请求的批量
/// 大小。其他平台（包括 Windows）则使用用户显式请求的批量
/// 大小。
fn effective_batch_size(opts: &Opts) -> usize {
    #[cfg(unix)]
    {
        infer_batch_size(opts, adjust_ulimit_size(opts))
    }

    #[cfg(not(unix))]
    {
        opts.batch_size
    }
}

/// 在当前线程（current-thread）的 Tokio 运行时上将扫描运行至完成。
///
/// 扫描器从单个 future 驱动每一个套接字，从不 spawn 任务，因此它能利用的只有一个
/// 线程：当前线程运行时在调用线程上运行扫描、I/O 驱动和定时器，
/// 而没多线程运行时那些工作线程和跨线程唤醒。
///
/// 运行时只在扫描期间存在。地址解析
/// （阻塞式 DNS 查询和文件读取）在运行时创建之前完成，因此它
/// 绝不会拖慢扫描，而脚本在运行时销毁之后才运行。
fn run_scan(scanner: &Scanner) -> std::io::Result<Vec<PortStatus>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    Ok(runtime.block_on(scanner.run_with_status()))
}

/// 打印 RustScan 的开场标题
#[allow(clippy::items_after_statements, clippy::needless_raw_string_hashes)]
fn print_opening(opts: &Opts) {
    debug!("Printing opening");
    let s = r#".----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner."#;

    println_safe(format_args!("{}", s.gradient(Color::Green).bold()));
    let info = r#"________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------"#;
    println_safe(format_args!("{}", info.gradient(Color::Yellow).bold()));
    funny_opening!();

    let config_path = opts
        .config_path
        .clone()
        .unwrap_or_else(input::default_config_path);

    detail!(
        format!("The config file is expected to be at {config_path:?}"),
        opts.greppable,
        opts.accessible
    );

    if opts.config_path.is_none() {
        let old_config_path = input::old_default_config_path();
        detail!(
            format!(
                "For backwards compatibility, the config file may also be at {old_config_path:?}"
            ),
            opts.greppable,
            opts.accessible
        );
    }
}

#[cfg(unix)]
fn adjust_ulimit_size(opts: &Opts) -> usize {
    use rlimit::Resource;
    use std::convert::TryInto;

    if let Some(limit) = opts.ulimit {
        let limit = limit as u64;
        if Resource::NOFILE.set(limit, limit).is_ok() {
            detail!(
                format!("Automatically increasing ulimit value to {limit}."),
                opts.greppable,
                opts.accessible
            );
        } else {
            warning!(
                "ERROR. Failed to set ulimit value.",
                opts.greppable,
                opts.accessible
            );
        }
    }

    let (soft, _) = Resource::NOFILE.get().unwrap();
    // 在 32 位目标上，软限额（例如 RLIM_INFINITY）可能无法放入
    // usize。此时回退到保守的默认值而不是 usize::MAX，
    // 后者会跳过 infer_batch_size 中所有的批量大小调整。
    soft.try_into().unwrap_or(DEFAULT_FILE_DESCRIPTORS_LIMIT)
}

#[cfg(unix)]
fn infer_batch_size(opts: &Opts, ulimit: usize) -> usize {
    let mut batch_size = opts.batch_size;

    // 当 ulimit 值低于期望的批量大小时调整批量大小
    if ulimit < batch_size {
        warning!("File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers",
            opts.greppable, opts.accessible
        );

        // 当操作系统支持像 8000 这样高酌文件限额，但用户
        // 选择了高于此值的批量大小时，我们应该把它降低到
        // 一个更小的值。
        if ulimit < AVERAGE_BATCH_SIZE {
            // ulimit 小于平均批量大小
            // 用户的 ulimit 一定非常小
            // 将批量大小降为 ulimit 的一半
            warning!("Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. ", opts.greppable, opts.accessible);
            info!("Halving batch_size because ulimit is smaller than average batch size");
            batch_size = ulimit / 2;
        } else if ulimit > DEFAULT_FILE_DESCRIPTORS_LIMIT {
            info!("Batch size is now average batch size");
            batch_size = AVERAGE_BATCH_SIZE;
        } else {
            batch_size = ulimit - 100;
        }
    }
    // 当 ulimit 高于批量大小时，告知用户批量大小是可以提升的，
    // 除非用户自己指定了 ulimit。
    else if ulimit + 2 > batch_size && (opts.ulimit.is_none()) {
        detail!(format!("File limit higher than batch size. Can increase speed by increasing batch size '-b {}'.", ulimit - 100),
        opts.greppable, opts.accessible);
    }

    batch_size
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::effective_batch_size;
    #[cfg(unix)]
    use super::{adjust_ulimit_size, infer_batch_size};
    use super::{print_opening, Opts};

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered() {
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 120);

        assert!(batch_size < opts.batch_size);
    }

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered_average_size() {
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 9_000);

        assert_eq!(batch_size, 3_000);
    }
    #[test]
    #[cfg(unix)]
    fn batch_size_equals_ulimit_lowered() {
        // 因为 ulimit 和批量大小相同，批量大小会被降低
        // 到 ULIMIT - 100
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 5_000);

        assert_eq!(batch_size, 4_900);
    }
    #[test]
    #[cfg(unix)]
    fn batch_size_adjusted_2000() {
        // ulimit == batch_size
        let opts = Opts {
            batch_size: 50_000,
            ulimit: Some(2_000),
            ..Default::default()
        };
        let batch_size = adjust_ulimit_size(&opts);

        assert_eq!(batch_size, 2_000);
    }

    #[test]
    #[cfg(unix)]
    fn test_high_ulimit_no_greppable_mode() {
        let opts = Opts {
            batch_size: 10,
            greppable: false,
            ..Default::default()
        };

        let batch_size = infer_batch_size(&opts, 1_000_000);

        assert_eq!(batch_size, opts.batch_size);
    }

    #[test]
    fn test_print_opening_no_panic() {
        let opts = Opts::default();
        // print opening 不应该 panic
        print_opening(&opts);
    }

    #[test]
    #[cfg(windows)]
    fn windows_batch_size_uses_requested_value() {
        let opts = Opts {
            batch_size: 50,
            ..Default::default()
        };

        assert_eq!(effective_batch_size(&opts), 50);
    }

    #[test]
    #[cfg(windows)]
    fn windows_batch_size_preserves_large_requested_value() {
        let opts = Opts {
            batch_size: 12_345,
            ..Default::default()
        };

        assert_eq!(effective_batch_size(&opts), 12_345);
    }

    #[test]
    #[cfg(windows)]
    fn windows_batch_size_preserves_single_connection() {
        let opts = Opts {
            batch_size: 1,
            ..Default::default()
        };

        assert_eq!(effective_batch_size(&opts), 1);
    }
}
