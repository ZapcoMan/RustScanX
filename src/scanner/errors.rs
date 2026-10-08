use std::{collections::HashSet, fmt, io, net::IpAddr};

/// 保持操作系统错误及其目标不变，直到诊断需要格式化时为止。
#[derive(Debug)]
struct ScanError {
    ip: IpAddr,
    error: io::Error,
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.error, self.ip)
    }
}

impl std::error::Error for ScanError {}

/// 保留常规的 I/O 结果布局；只有诊断需要目标的上下文。
pub(super) fn diagnostic_error(error: io::Error, ip: IpAddr, enabled: bool) -> io::Error {
    if enabled {
        io::Error::other(ScanError { ip, error })
    } else {
        error
    }
}

pub(super) struct ScanErrors {
    enabled: bool,
    limit: usize,
    messages: HashSet<String>,
}

impl ScanErrors {
    pub(super) fn new(enabled: bool, limit: usize) -> Self {
        Self {
            enabled,
            limit,
            messages: HashSet::new(),
        }
    }

    pub(super) fn record(&mut self, failure: io::Error) {
        if self.enabled && self.messages.len() < self.limit {
            self.messages.insert(failure.to_string());
        }
    }

    pub(super) fn messages(&self) -> &HashSet<String> {
        &self.messages
    }
}

/// 在不分配内存也不解读操作系统消息的情况下检测描述符耗尽。
#[cfg(unix)]
pub(super) fn is_descriptor_exhaustion(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE))
}

#[cfg(windows)]
pub(super) fn is_descriptor_exhaustion(error: &io::Error) -> bool {
    error.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEMFILE)
}

// 对于没有 Unix 或 Winsock 错误码的目标，保留之前的回退方案。
#[cfg(not(any(unix, windows)))]
pub(super) fn is_descriptor_exhaustion(error: &io::Error) -> bool {
    error
        .to_string()
        .to_lowercase()
        .contains("too many open files")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fmt, net::SocketAddr};

    #[derive(Debug)]
    struct MustNotFormat;

    impl fmt::Display for MustNotFormat {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("discarded diagnostics must not format errors")
        }
    }

    impl std::error::Error for MustNotFormat {}

    fn failure(error: io::Error) -> io::Error {
        diagnostic_error(error, "127.0.0.1".parse().unwrap(), true)
    }

    #[test]
    fn disabled_diagnostics_do_not_format_errors() {
        let mut errors = ScanErrors::new(false, 1000);
        errors.record(diagnostic_error(
            io::Error::other(MustNotFormat),
            "127.0.0.1".parse().unwrap(),
            false,
        ));
        assert!(errors.messages().is_empty());
    }

    #[test]
    fn disabled_diagnostics_preserve_the_original_os_error() {
        let original = io::Error::from_raw_os_error(123);
        let error = diagnostic_error(original, "127.0.0.1".parse().unwrap(), false);
        assert_eq!(error.raw_os_error(), Some(123));
    }

    #[test]
    fn full_diagnostics_do_not_format_more_errors() {
        let mut errors = ScanErrors::new(true, 1);
        errors.record(failure(io::ErrorKind::ConnectionRefused.into()));
        errors.record(failure(io::Error::other(MustNotFormat)));
        assert_eq!(errors.messages().len(), 1);
    }

    #[test]
    fn enabled_diagnostics_keep_error_details_and_deduplicate_per_ip() {
        let mut errors = ScanErrors::new(true, 1000);
        for port in [80, 443] {
            errors.record(diagnostic_error(
                io::Error::other("test socket error"),
                SocketAddr::from(([127, 0, 0, 1], port)).ip(),
                true,
            ));
        }
        assert_eq!(errors.messages().len(), 1);
        assert!(errors.messages().contains("test socket error 127.0.0.1"));
    }

    #[cfg(unix)]
    #[test]
    fn detects_unix_descriptor_limits_by_code() {
        for code in [libc::EMFILE, libc::ENFILE] {
            assert!(is_descriptor_exhaustion(&io::Error::from_raw_os_error(
                code
            )));
        }
        assert!(!is_descriptor_exhaustion(&io::Error::from_raw_os_error(
            libc::ECONNREFUSED
        )));
    }

    #[cfg(windows)]
    #[test]
    fn detects_winsock_descriptor_limits_by_code() {
        use windows_sys::Win32::Networking::WinSock::{WSAECONNREFUSED, WSAEMFILE};
        assert!(is_descriptor_exhaustion(&io::Error::from_raw_os_error(
            WSAEMFILE
        )));
        assert!(!is_descriptor_exhaustion(&io::Error::from_raw_os_error(
            WSAECONNREFUSED
        )));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn descriptor_check_never_formats_an_error() {
        assert!(!is_descriptor_exhaustion(&io::Error::other(MustNotFormat)));
    }
}
