//! 提供用于捕获扫描计时信息的功能。
//!
//! # 用法
//!
//! ```rust
//! // 初始化 Benchmark 向量
//! # use rustscanx::benchmark::{Benchmark, NamedTimer};
//! # use log::info;
//! let mut bm = Benchmark::init();
//! // 以某个名称启动命名计时器
//! let mut example_bench = NamedTimer::start("Example Bench");
//! // 停止命名计时器
//! example_bench.end();
//! // 将命名计时器添加到 Benchmarks
//! bm.push(example_bench);
//! // 打印基准测试摘要
//! info!("{}", bm.summary());
//! ```
use std::time::Instant;

/// 一个 Benchmark 结构体，用于持有带有名称、开始与结束 Instant 的 NamedTimer，
#[derive(Debug)]
pub struct Benchmark {
    named_timers: Vec<NamedTimer>,
}

impl Benchmark {
    pub fn init() -> Self {
        Self {
            named_timers: Vec::new(),
        }
    }
    pub fn push(&mut self, timer: NamedTimer) {
        self.named_timers.push(timer);
    }

    /// 基准测试摘要会拆解这个向量，
    /// 以相同的方式格式化每个元素，并返回
    /// 一个包含所有可用信息的单一 String，
    /// 便于打印
    pub fn summary(&self) -> String {
        let mut summary = String::from("\nRustScan Benchmark Summary");

        for timer in &self.named_timers {
            if let Some(start) = timer.start {
                if let Some(end) = timer.end {
                    let runtime_secs = end.saturating_duration_since(start).as_secs_f32();
                    summary.push_str(&format!("\n{0: <10} | {1: <10}s", timer.name, runtime_secs));
                }
            }
        }
        summary
    }
}

/// NamedTimer 的目的是为某个特定的计时器持有一个名称、
/// 开始 Instant 和结束 Instant。
/// 给定的名称会展示在基准测试摘要中，
/// 开始和结束的 Instant 会用于计算运行时间。
#[derive(Debug)]
pub struct NamedTimer {
    name: &'static str,
    start: Option<Instant>,
    end: Option<Instant>,
}

impl NamedTimer {
    pub fn start(name: &'static str) -> Self {
        Self {
            name,
            start: Some(Instant::now()),
            end: None,
        }
    }
    pub fn end(&mut self) {
        self.end = Some(Instant::now());
    }
}

#[test]
fn benchmark() {
    let mut benchmarks = Benchmark::init();
    let mut test_timer = NamedTimer::start("test");
    std::thread::sleep(std::time::Duration::from_millis(100));
    test_timer.end();
    benchmarks.push(test_timer);
    benchmarks.push(NamedTimer::start("only_start"));
    assert!(benchmarks
        .summary()
        .contains("\nRustScan Benchmark Summary\ntest       | 0."));
    assert!(!benchmarks.summary().contains("only_start"));
}
