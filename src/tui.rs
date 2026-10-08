//! 扫描期间终端输出的工具函数。

use std::io::Write;

/// 向 stdout 打印一行，且永不 panic。
///
/// 当向 stdout 写入失败时 `println!` 会 panic，而在 `panic = "abort"` 的
/// release 配置下这是致命的。这包括当下游消费者（例如 `rustscan -g ... | head`）
/// 关闭管道时产生的 `BrokenPipe` 错误，因此在发生这种情况时，进程会安静地退出。
/// 其他输出错误会在退出前报告到 stderr。
///
/// 所有面向用户的输出都应通过此函数（`warning!`、`detail!`、`output!` 和
/// `funny_opening!` 宏已经如此），而不是 `println!`。
pub fn println_safe(args: std::fmt::Arguments<'_>) {
    match writeln!(std::io::stdout().lock(), "{args}") {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
            // 管道的读取端已经消失；没有可打印的对象了
            std::process::exit(0);
        }
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "rustscanx: failed writing to stdout: {e}"
            );
            std::process::exit(1);
        }
    }
}

/// RustScan 的终端用户界面（TUI）模块
/// 定义要使用的宏
#[macro_export]
macro_rules! warning {
    ($name:expr) => {
        $crate::tui::println_safe(format_args!(
            "{} {}",
            ansi_term::Colour::Red.bold().paint("[!]"),
            $name
        ));
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // 如果不是 greppable 则打印，否则没有 else 分支，因此不打印。
        if !$greppable {
            if $accessible {
                // 不要打印 ASCII 艺术
                $crate::tui::println_safe(format_args!("{}", $name));
            } else {
                $crate::tui::println_safe(format_args!(
                    "{} {}",
                    ansi_term::Colour::Red.bold().paint("[!]"),
                    $name
                ));
            }
        }
    };
}

#[macro_export]
macro_rules! detail {
    ($name:expr) => {
        $crate::tui::println_safe(format_args!(
            "{} {}",
            ansi_term::Colour::Blue.bold().paint("[~]"),
            $name
        ));
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // 如果不是 greppable 则打印，否则没有 else 分支，因此不打印。
        if !$greppable {
            if $accessible {
                // 不要打印 ASCII 艺术
                $crate::tui::println_safe(format_args!("{}", $name));
            } else {
                $crate::tui::println_safe(format_args!(
                    "{} {}",
                    ansi_term::Colour::Blue.bold().paint("[~]"),
                    $name
                ));
            }
        }
    };
}

#[macro_export]
macro_rules! output {
    ($name:expr) => {
        $crate::tui::println_safe(format_args!(
            "{} {}",
            ansi_term::Colour::RGB(0, 255, 9).bold().paint("[>]"),
            $name
        ));
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // 如果不是 greppable 则打印，否则没有 else 分支，因此不打印。
        if !$greppable {
            if $accessible {
                // 不要打印 ASCII 艺术
                $crate::tui::println_safe(format_args!("{}", $name));
            } else {
                $crate::tui::println_safe(format_args!(
                    "{} {}",
                    ansi_term::Colour::RGB(0, 255, 9).bold().paint("[>]"),
                    $name
                ));
            }
        }
    };
}

#[macro_export]
macro_rules! funny_opening {
    // 打印一句有趣的话/开场白
    () => {
        use rand::seq::IndexedRandom;
        let quotes = vec![
            "Nmap? More like slowmap.🐢",
            "🌍HACK THE PLANET🌍",
            "Real hackers hack time ⌛",
            "Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan",
            "😵 https://admin.tryhackme.com",
            "0day was here ♥",
            "I don't always scan ports, but when I do, I prefer RustScan.",
            "RustScan: Where scanning meets swagging. 😎",
            "To scan or not to scan? That is the question.",
            "RustScan: Because guessing isn't hacking.",
            "Scanning ports like it's my full-time job. Wait, it is.",
            "Open ports, closed hearts.",
            "I scanned my computer so many times, it thinks we're dating.",
            "Port scanning: Making networking exciting since... whenever.",
            "You miss 100% of the ports you don't scan. - RustScan",
            "Breaking and entering... into the world of open ports.",
            "TCP handshake? More like a friendly high-five!",
            "Scanning ports: The virtual equivalent of knocking on doors.",
            "RustScan: Making sure 'closed' isn't just a state of mind.",
            "RustScan: allowing you to send UDP packets into the void 1200x faster than NMAP",
            "Port scanning: Because every port has a story to tell.",
            "I scanned ports so fast, even my computer was surprised.",
            "Scanning ports faster than you can say 'SYN ACK'",
            "RustScan: Where '404 Not Found' meets '200 OK'.",
            "RustScan: Exploring the digital landscape, one IP at a time.",
            "TreadStone was here 🚀",
            "With RustScan, I scan ports so fast, even my firewall gets whiplash 💨",
            "Scanning ports so fast, even the internet got a speeding ticket!",
        ];
        let random_quote = quotes.choose(&mut rand::rng()).unwrap();

        $crate::tui::println_safe(format_args!("{}\n", random_quote));
    };
}
