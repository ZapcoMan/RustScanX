use itertools::{iproduct, Product};
use std::iter::FusedIterator;
use std::net::{IpAddr, SocketAddr};
use std::slice;

/// 一个迭代器，接收一组 IP 和端口，并为每个 IP/端口对返回一个
/// [`SocketAddr`]，直到所有组合被遍历完为止。
///
/// 这个迭代器的目标是在*不*分配一个大型中间缓冲区的情况下
/// 遍历每个 IP 与端口的组合——否则就得提前把每个对
/// 物化成一个 `Vec<SocketAddr>`。
///
/// # 顺序
///
/// 在 `product_it` 内部，IP/端口的顺序被有意地反转：我们希望
/// `iproduct!` 在推进到下一个端口之前，先遍历*某个端口的所有 IP*
/// （"固定端口，遍历所有 IP，然后推进端口"）。
///
/// # 示例
///
/// `SocketIterator` 位于一个私有模块中，因此这个示例不会作为
/// doctest 运行；`goes_through_every_ip_port_combination` 检查相同的顺序。
///
/// ```ignore
/// # use std::net::IpAddr;
/// let ips = [
///     "127.0.0.1".parse::<IpAddr>().unwrap(),
///     "192.168.0.1".parse::<IpAddr>().unwrap(),
/// ];
/// let ports = [80u16, 443];
///
/// let mut it = SocketIterator::new(&ips, &ports);
/// assert_eq!(it.next(), Some("127.0.0.1:80".parse().unwrap()));
/// assert_eq!(it.next(), Some("192.168.0.1:80".parse().unwrap()));
/// assert_eq!(it.next(), Some("127.0.0.1:443".parse().unwrap()));
/// assert_eq!(it.next(), Some("192.168.0.1:443".parse().unwrap()));
/// assert_eq!(it.next(), None);
/// ```
#[derive(Clone)]
pub struct SocketIterator<'s> {
    // 不使用装箱：迭代器直接拥有具体的 slice 迭代器。
    // 这让 `SocketIterator` 无需分配，也让 `Clone` 同样零成本。
    product_it: Product<slice::Iter<'s, u16>, slice::Iter<'s, IpAddr>>,
}

impl<'s> SocketIterator<'s> {
    pub fn new(ips: &'s [IpAddr], ports: &'s [u16]) -> Self {
        Self {
            // `iproduct!` 会对每个参数调用 `.into_iter()`；`slice::Iter`
            // 本身已经是迭代器，因此这是一个空操作（不分配内存）。
            product_it: iproduct!(ports.iter(), ips.iter()),
        }
    }
}

impl Iterator for SocketIterator<'_> {
    type Item = SocketAddr;

    /// 返回下一个套接字，当所有组合都遍历完时返回 `None`。
    /// 在端口推进之前，每个 IP 都与同一个端口配对。
    fn next(&mut self) -> Option<Self::Item> {
        self.product_it
            .next()
            .map(|(port, ip)| SocketAddr::new(*ip, *port))
    }

    // 委托 size hint，以便 `collect()` 这样的调用者能预先为缓冲区分配大小。
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.product_it.size_hint()
    }
}

// `Product` 和 `slice::Iter` 都是 fused 的，因此我们也是。
impl FusedIterator for SocketIterator<'_> {}

#[cfg(test)]
mod tests {
    use super::SocketIterator;
    use std::net::{IpAddr, SocketAddr};

    #[test]
    fn goes_through_every_ip_port_combination() {
        let addrs = vec![
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "192.168.0.1".parse::<IpAddr>().unwrap(),
        ];
        let ports: Vec<u16> = vec![22, 80, 443];
        let mut it = SocketIterator::new(&addrs, &ports);

        assert_eq!(Some(SocketAddr::new(addrs[0], ports[0])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[0])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[0], ports[1])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[1])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[0], ports[2])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[2])), it.next());
        assert_eq!(None, it.next());
    }

    #[test]
    fn size_hint_is_exact() {
        let addrs = ["127.0.0.1".parse::<IpAddr>().unwrap()];
        let ports: Vec<u16> = vec![22, 80, 443];
        let mut it = SocketIterator::new(&addrs, &ports);

        assert_eq!(it.size_hint(), (3, Some(3)));
        it.next();
        assert_eq!(it.size_hint(), (2, Some(2)));
    }

    #[test]
    fn clone_resumes_independently() {
        let addrs = [
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "192.168.0.1".parse::<IpAddr>().unwrap(),
        ];
        let ports: Vec<u16> = vec![22, 80];

        let mut a = SocketIterator::new(&addrs, &ports);
        assert_eq!(a.next(), Some(SocketAddr::new(addrs[0], ports[0])));
        let b = a.clone(); // b 从 a 当前的位置开始

        // 2 个 IP x 2 个端口 = 4 个套接字，其中一个在克隆前已被消耗。
        let rest = [
            SocketAddr::new(addrs[1], ports[0]),
            SocketAddr::new(addrs[0], ports[1]),
            SocketAddr::new(addrs[1], ports[1]),
        ];
        assert_eq!(a.collect::<Vec<_>>(), rest);
        assert_eq!(b.collect::<Vec<_>>(), rest);
    }

    #[test]
    fn empty_inputs_yield_nothing() {
        let addrs = ["127.0.0.1".parse::<IpAddr>().unwrap()];
        let ports = [22u16];

        for mut it in [
            SocketIterator::new(&[], &ports),
            SocketIterator::new(&addrs, &[]),
        ] {
            assert_eq!(it.size_hint(), (0, Some(0)));
            assert_eq!(it.next(), None);
            // 保持耗尽状态，正如 `FusedIterator` 实现所承诺的那样。
            assert_eq!(it.next(), None);
        }
    }
}
