//! RustScanX 是一个现代化端口扫描器，本 crate 对外暴露了它的内部功能。
//!
//! RustScanX 基于原项目
//! [RustScan](https://github.com/bee-san/RustScan) 二次开发而来，并向原项目致敬。
//!
//! ## 示例：针对 localhost 执行一次扫描
//!
//! 核心扫描行为由
//! [`Scanner`](crate::scanner::Scanner) 管理，而它又需要一个
//! [`PortStrategy`](crate::port_strategy::PortStrategy)。
//!
//! 扫描器是异步的，运行在 [Tokio](https://docs.rs/tokio) 上：
//! 在启用了 I/O 与时间驱动的 Tokio 运行时中 await
//! [`Scanner::run`](crate::scanner::Scanner::run)。它从不 spawn 任务，因此
//! 当前线程（current-thread）运行时已足够（详见
//! [`Scanner`](crate::scanner::Scanner)）。
//!
//! 这个示例会被编译，但永远不会被测试套件执行。
//!
//! ```no_run
//! use std::{net::IpAddr, time::Duration};
//!
//! use RustScanX::input::{PortRanges, ScanOrder};
//! use RustScanX::port_strategy::PortStrategy;
//! use RustScanX::scanner::Scanner;
//!
//! fn main() {
//!     let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
//!     let range = PortRanges(vec![(1, 1_000)]);
//!     let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random); // 可以是 serial、random 或 manual https://github.com/RustScan/RustScan/blob/master/src/port_strategy/mod.rs
//!     let scanner = Scanner::new(
//!         &addrs, // 要扫描的地址
//!         10, // batch_size 是一次应扫描多少个端口
//!         Duration::from_millis(100), // Timeout 是 RustScan 在将端口判定为关闭之前应等待的时间，类型为 Duration。
//!         1, // Tries，RustScan 应该重试多少次？
//!         true, // greppable 表示 RustScan 是否应该打印内容，还是等到最后只打印 ip
//!         strategy, // 所使用的端口策略
//!         true, // accessible，输出是否应符合无障碍（A11Y）规范？
//!         vec![9000], // RustScan 应该排除哪些端口？
//!         false, // 这是一次 UDP 扫描吗？
//!     );
//!
//!     // 在异步上下文中（例如 `#[tokio::main]`），这行代码
//!     // 就等同于 `scanner.run().await`。
//!     let runtime = tokio::runtime::Builder::new_current_thread()
//!         .enable_all()
//!         .build()
//!         .unwrap();
//!     let scan_result = runtime.block_on(scanner.run());
//!
//!     println!("{:?}", scan_result);
//! }
//! ```
#![allow(clippy::needless_doctest_main)]

pub mod tui;

pub mod input;

pub mod scanner;

pub mod port_strategy;

pub mod benchmark;

pub mod scripts;

pub mod address;

pub mod generated;
