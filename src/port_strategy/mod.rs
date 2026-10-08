//! 提供了一种专门用于端口扫描配置选项的方式。
mod range_iterator;
use crate::input::{PortRanges, ScanOrder};
use rand::rng;
use rand::seq::SliceRandom;
use range_iterator::RangeIterator;

/// 表示端口扫描的选项。
///
/// 目前这些选项都涉及范围，但在未来
/// 它还会包含自定义的端口列表。
#[derive(Debug)]
pub enum PortStrategy {
    Manual(Vec<u16>),
    Serial(SerialRange),
    Random(RandomRange),
}

impl PortStrategy {
    pub fn pick(range: &Option<PortRanges>, ports: Option<Vec<u16>>, order: ScanOrder) -> Self {
        match order {
            ScanOrder::Serial if ports.is_none() => {
                let port_ranges = range.as_ref().unwrap();
                PortStrategy::Serial(SerialRange {
                    range: port_ranges.0.clone(),
                })
            }
            ScanOrder::Random if ports.is_none() => {
                let port_ranges = range.as_ref().unwrap();
                PortStrategy::Random(RandomRange {
                    range: port_ranges.0.clone(),
                })
            }
            ScanOrder::Serial => PortStrategy::Manual(ports.unwrap()),
            ScanOrder::Random => {
                let mut rng = rng();
                let mut ports = ports.unwrap();
                ports.shuffle(&mut rng);
                PortStrategy::Manual(ports)
            }
        }
    }

    pub fn order(&self) -> Vec<u16> {
        match self {
            PortStrategy::Manual(ports) => ports.clone(),
            PortStrategy::Serial(range) => range.generate(),
            PortStrategy::Random(range) => range.generate(),
        }
    }
}

/// 与端口策略关联的 trait。每个 PortStrategy 都必须能
/// 为后续的端口扫描生成一个顺序。
trait RangeOrder {
    fn generate(&self) -> Vec<u16>;
}

/// 正如其名，SerialRange 总会生成一个按
/// 升序排列的向量。
#[derive(Debug)]
pub struct SerialRange {
    range: Vec<(u16, u16)>,
}

impl RangeOrder for SerialRange {
    fn generate(&self) -> Vec<u16> {
        RangeIterator::new_serial(&self.range).collect()
    }
}

/// 正如其名，RandomRange 总会生成一个顺序随机的向量。
/// 这个向量的构建遵循 LCG 算法。
#[derive(Debug)]
pub struct RandomRange {
    range: Vec<(u16, u16)>,
}

impl RangeOrder for RandomRange {
    // 目前使用 RangeIterator 和生成一个范围 + 打乱向量
    // 几乎是一样的。它的优势会在我们需要
    // 为不同的 IP 生成不同范围而又不存储
    // 实际向量时体现出来。
    //
    // RangeIterator 的另一个好处是，它总是生成一个数组内元素
    // 之间保持一定距离的范围。由于算法的工作方式，
    // 端口号彼此相邻的可能性很小。
    fn generate(&self) -> Vec<u16> {
        RangeIterator::new_random(&self.range).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::PortStrategy;
    use crate::input::{PortRanges, ScanOrder};
    use std::collections::HashSet;

    fn expected_ports_from_ranges(input: &[(u16, u16)]) -> Vec<u16> {
        let mut s = HashSet::new();
        for &(start, end) in input {
            for p in start..=end {
                s.insert(p);
            }
        }
        let mut v: Vec<u16> = s.into_iter().collect();
        v.sort_unstable();
        v
    }
    #[test]
    fn serial_strategy_with_range() {
        let ranges = PortRanges(vec![(1u16, 10u16), (20u16, 30u16), (100u16, 110u16)]);
        let strategy = PortStrategy::pick(&Some(ranges.clone()), None, ScanOrder::Serial);
        let result = strategy.order();
        let expected = expected_ports_from_ranges(&ranges.0);

        assert_eq!(expected, result);
    }
    #[test]
    fn random_strategy_with_range() {
        let ranges = PortRanges(vec![(1u16, 10u16), (20u16, 30u16), (100u16, 110u16)]);
        let strategy = PortStrategy::pick(&Some(ranges.clone()), None, ScanOrder::Random);
        let mut result = strategy.order();
        let expected = expected_ports_from_ranges(&ranges.0);

        assert_ne!(expected, result);
        result.sort_unstable();

        assert_eq!(expected, result);
    }

    #[test]
    fn serial_strategy_with_ports() {
        let strategy = PortStrategy::pick(&None, Some(vec![80, 443]), ScanOrder::Serial);
        let result = strategy.order();
        assert_eq!(vec![80, 443], result);
    }

    #[test]
    fn random_strategy_with_ports() {
        let strategy = PortStrategy::pick(&None, Some((1..10).collect()), ScanOrder::Random);
        let mut result = strategy.order();
        let expected = (1..10).collect::<Vec<u16>>();
        assert_ne!(expected, result);

        result.sort_unstable();
        assert_eq!(expected, result);
    }
}
