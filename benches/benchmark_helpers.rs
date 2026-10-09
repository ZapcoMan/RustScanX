use criterion::{criterion_group, criterion_main, Criterion};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::net::IpAddr;
use std::time::Duration;
use RustScanX::generated::get_parsed_data;
use RustScanX::input::{Opts, PortRanges, ScanOrder};
use RustScanX::port_strategy::PortStrategy;
use RustScanX::scanner::{build_udp_payload_lookup, Scanner};

fn bench_address() {
    let _addrs = ["127.0.0.1".parse::<IpAddr>().unwrap()];
}

fn bench_port_strategy() {
    let range = PortRanges(vec![(1, 1_000)]);
    let _strategy = PortStrategy::pick(&Some(range.clone()), None, ScanOrder::Serial);
}

fn bench_address_parsing() {
    let opts = Opts {
        addresses: vec![
            "127.0.0.1".to_owned(),
            "10.2.0.1".to_owned(),
            "192.168.0.0/24".to_owned(),
        ],
        exclude_addresses: Some(vec![
            "10.0.0.0/8".to_owned(),
            "172.16.0.0/12".to_owned(),
            "192.168.0.0/16".to_owned(),
            "172.16.0.1".to_owned(),
        ]),
        ..Default::default()
    };
    let _ips = RustScanX::address::parse_addresses(&opts);
}

// 复现旧的 UDP 有效载荷选择行为：
// 遍历整个 UDP 有效载荷 map，找到端口列表包含 `port` 的最后一个有效载荷。
fn old_payload_for_port(udp_map: &'static BTreeMap<Vec<u16>, Vec<u8>>, port: u16) -> &'static [u8] {
    let mut payload: &'static [u8] = b"";
    for (ports, value) in udp_map.iter() {
        if ports.contains(&port) {
            payload = value.as_slice();
        }
    }
    payload
}

fn criterion_benchmark(c: &mut Criterion) {
    // 基准测试辅助函数
    c.bench_function("parse address", |b| b.iter(bench_address));

    c.bench_function("port strategy", |b| b.iter(bench_port_strategy));

    let mut address_group = c.benchmark_group("address parsing");
    address_group.measurement_time(Duration::from_secs(10));
    address_group.bench_function("parse addresses with exclusions", |b| {
        b.iter(bench_address_parsing)
    });
    address_group.finish();

    // 在不打开套接字的情况下考验生产环境的端口准备逻辑。扫描器
    // 没有目标地址，且运行时的构建不被计入计时。
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut preparation = c.benchmark_group("port preparation");
    preparation.sample_size(20);
    preparation.warm_up_time(Duration::from_millis(500));
    preparation.measurement_time(Duration::from_secs(2));
    for (port_count, excluded_count) in [
        (1, 1),
        (16, 4),
        (64, 1),
        (64, 4096),
        (4096, 0),
        (4096, 64),
        (4096, 4096),
        (65535, 0),
        (65535, 4),
        (65535, 64),
        (65535, 1024),
        (65535, 4096),
    ] {
        let scanner = Scanner::new(
            &[],
            500,
            Duration::from_millis(100),
            1,
            true,
            PortStrategy::Manual((1..=port_count).collect()),
            true,
            (0..excluded_count)
                .map(|i| (i * 13 % 65536) as u16)
                .collect(),
            false,
        );
        preparation.bench_function(
            format!("{port_count} ports, {excluded_count} exclusions"),
            |b| b.iter(|| black_box(runtime.block_on(black_box(&scanner).run_with_status()))),
        );
    }
    preparation.finish();

    // UDP 有效载荷查找微基准：对比旧的遍历 payload map 线性扫描
    // 与预计算的端口 -> 有效载荷查找。不涉及套接字。
    let udp_map = get_parsed_data();
    let lookup = build_udp_payload_lookup(udp_map);
    let ports: Vec<u16> = (1..=4096).collect();

    c.bench_function("udp payload lookup/old scan map 1..4096", |b| {
        b.iter(|| {
            for &p in ports.iter() {
                let payload = old_payload_for_port(black_box(udp_map), black_box(p));
                black_box(payload);
            }
        })
    });

    c.bench_function("udp payload lookup/new hashmap 1..4096", |b| {
        b.iter(|| {
            for &p in ports.iter() {
                let payload = lookup.get(&p).copied().unwrap_or(b"");
                black_box(payload);
            }
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
