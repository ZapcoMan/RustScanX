use gcd::Gcd;
use rand::RngExt;
use std::convert::TryInto;

/// 以两种模式从一组（可能重叠的）闭区间 `u16` 范围中产出端口：
///
/// **随机化（Randomized）** — 由 `RangeIterator::new_random` 创建：
///    - 算法使用加法同余步长 `x_{i+1} = (x_i + step) % N`
///      生成索引 `0..N-1` 的一个排列。
///    - 选择 `step` 使得 `gcd(step, N) == 1`，以确保该序列是一个
///      全长循环（每个索引恰好访问一次）。
///    - `x_0`（存储为 `normalized_first_pick` 的种子）在 `0..N` 内
///      均匀选取。
///
///      更多信息：<https://en.wikipedia.org/wiki/Linear_congruential_generator>
///
/// **串行（Serial）** — `RangeIterator::new_serial`：
///     按**原始输入顺序**遍历输入范围，并在第一次遇到某个端口时产出它。
///     重复的端口（来自重叠的范围）会借助一张 65_536 项的 "seen"
///     表被跳过。
pub struct RangeIterator {
    active: bool,
    total: u32,
    normalized_first_pick: u32,
    normalized_pick: u32,
    step: u32,
    ranges: Vec<(u32, u32)>,
    prefix: Vec<u32>,
    serial_itr: Option<Box<dyn Iterator<Item = u16>>>,
    /// 一旦 `port` 被产出，`seen[port]` 就为 true（仅串行模式）。
    serial_seen: Option<Vec<bool>>,
}

impl RangeIterator {
    /// 构造一个随机化迭代器（LCG 排列）。
    ///
    /// 前置条件：
    /// - `input` 必须至少包含一个 `(u16,u16)`
    ///   且每一对都必须满足 `start <= end`。
    pub fn new_random(input: &[(u16, u16)]) -> Self {
        // 归一化并合并为 (start, len) 的 u32 对
        // 示例：[(10,12),(11,15)] -> 合并后 [(10,6)]
        let mut ranges: Vec<(u32, u32)> = input
            .iter()
            .map(|(s, e)| {
                let start = *s as u32;
                let end_excl = (*e as u32) + 1; // 将闭区间 -> 转为开区间
                (start, end_excl)
            })
            .collect();

        ranges.sort_unstable_by_key(|&(s, _)| s);

        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
        if !ranges.is_empty() {
            let mut iter = ranges.into_iter();
            let (mut cur_s, mut cur_end) = iter.next().unwrap(); // cur_end 为开区间
            for (s, end_excl) in iter {
                if s <= cur_end {
                    // 重叠/相邻 -> 扩展
                    if end_excl > cur_end {
                        cur_end = end_excl;
                    }
                } else {
                    // 将不相交的段作为 (start, len) 推入
                    merged.push((cur_s, cur_end - cur_s)); // len = 开区间 - 起点
                    cur_s = s;
                    cur_end = end_excl;
                }
            }
            merged.push((cur_s, cur_end - cur_s));
        }
        // 构建前缀和（prefix[0] = 0；prefix.len() == merged.len() + 1）
        let prefix = merged.iter().fold(vec![0u32], |mut acc, (_, len)| {
            let last = acc.last().unwrap();
            acc.push(last.saturating_add(*len));
            acc
        });

        // 由前置条件（input.len() >= 1）保证 total > 0
        let total = *prefix.last().unwrap();

        // 选择步长和种子
        let step = pick_random_coprime(total);
        let mut rng = rand::rng();
        let first = rng.random_range(0..total);

        Self {
            active: true,
            total,
            normalized_first_pick: first,
            normalized_pick: first,
            step,
            ranges: merged,
            prefix,
            serial_itr: None,
            serial_seen: None,
        }
    }

    /// 构造一个串行迭代器，按原始输入顺序产出端口，
    /// 跳过重复项。去重借助一张 seen 表就地完成。
    ///
    /// 前置条件：
    /// - `input` 必须至少包含一个 `(u16,u16)`，且每一对都必须满足 `start <= end`。
    pub fn new_serial(input: &[(u16, u16)]) -> Self {
        // 构建一个按 *输入顺序*（start..=end）产出端口的串行迭代器。
        // 这里我们把合并后的 ranges/prefix 留空（串行模式不需要它们）。
        let input = input.to_vec();
        let serial_itr = input.into_iter().flat_map(|(start, end)| start..=end);

        let serial_itr_boxed: Box<dyn Iterator<Item = u16>> = Box::new(serial_itr);
        // 每个可能的端口一项（0..=65535）。
        let seen = vec![false; usize::from(u16::MAX) + 1];

        Self {
            active: true,
            total: 0,
            normalized_first_pick: 0,
            normalized_pick: 0,
            step: 0,
            ranges: Vec::new(),
            prefix: Vec::new(),
            serial_itr: Some(serial_itr_boxed),
            serial_seen: Some(seen),
        }
    }
}
impl Iterator for RangeIterator {
    type Item = u16;

    /// 将迭代器向前推进一个端口。
    ///
    /// 1. 读取当前的归一化索引 `cur`。
    /// 2. 计算 `next = (cur + step) % total` 并更新 `normalized_pick`。
    /// 3. 如果 `next == normalized_first_pick`，标记 `active = false`（我们完成了循环）。
    /// 4. 通过前缀数组把返回的索引 `cur` 映射到合并后的范围：
    ///    - 找到满足 `prefix[idx] <= cur < prefix[idx+1]` 的范围索引 `idx`，
    ///    - offset = `cur - prefix[idx]`，
    ///    - port = `ranges[idx].0 + offset`。
    /// 5. 返回 `port as u16`。
    ///
    fn next(&mut self) -> Option<Self::Item> {
        if !self.active {
            return None;
        }

        // 串行迭代器快路径：保持原始输入顺序但跳过重复项。
        if let (Some(it), Some(seen)) = (self.serial_itr.as_mut(), self.serial_seen.as_mut()) {
            for p in it.by_ref() {
                // 只在第一次看到某个端口时产出它。
                if !std::mem::replace(&mut seen[usize::from(p)], true) {
                    return Some(p);
                }
                // 否则跳过重复项并继续
            }
            // 串行迭代器已耗尽：丢弃它并标记为非活动
            self.serial_itr = None;
            self.serial_seen = None;
            self.active = false;
            return None;
        }

        // 随机化（LCG）路径
        let cur = self.normalized_pick;
        let next = (cur + self.step) % self.total;

        // 如果 next 等于原始种子，那么在返回 cur 之后我们就完成了循环
        if next == self.normalized_first_pick {
            self.active = false;
        }

        self.normalized_pick = next;

        // 使用 prefix + ranges（二分查找）将 cur 映射为端口
        let mut lo: usize = 0;
        let mut hi: usize = self.ranges.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.prefix[mid + 1] > cur {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        let idx = lo;
        let offset = cur - self.prefix[idx];
        let (start, _len) = self.ranges[idx];
        let port = (start + offset)
            .try_into()
            .expect("Could not convert u32 to u16");
        Some(port)
    }
}

/// 两个随机整数互质的概率约为 61%，因此我们可以放心地
/// 选取一个随机数并测试它。以防我们运气不好、在 10 次尝试后
/// 仍未挑到一个互质的数，我们就直接返回 "end - 1"，它
/// 保证是互质的，但不会提供理想的随机化。
///
/// 我们在 "lower_range" 和 "upper_range" 之间选取，因为太靠近
/// 边界的值——在本例中即 "start" 和 "end" 参数——也会
/// 提供不理想的随机化，如上段所述。
fn pick_random_coprime(end: u32) -> u32 {
    let range_boundary = end / 4;
    let lower_range = range_boundary;
    let upper_range = end - range_boundary;
    let mut rng = rand::rng();
    let mut candidate = rng.random_range(lower_range..upper_range);

    for _ in 0..10 {
        if end.gcd(candidate) == 1 {
            return candidate;
        }
        candidate = rng.random_range(lower_range..upper_range);
    }

    end - 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // 辅助函数：收集、排序并返回由随机化 RangeIterator 产出的端口
    fn generate_sorted_from_ranges_random(input: &[(u16, u16)]) -> Vec<u16> {
        let mut it = RangeIterator::new_random(input);
        let mut v: Vec<u16> = it.by_ref().collect();
        v.sort_unstable();
        v
    }

    // 辅助函数：收集、排序并返回由串行 RangeIterator 产出的端口
    fn generate_sorted_from_ranges_serial(input: &[(u16, u16)]) -> Vec<u16> {
        let mut it = RangeIterator::new_serial(input);
        let mut v: Vec<u16> = it.by_ref().collect();
        v.sort_unstable();
        v
    }

    // 从输入范围（闭区间）构建期望的、已排序的唯一端口
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
    fn random_range_iterator_test() {
        // 较小的不相交范围
        let input = &[(1u16, 10u16), (20u16, 30u16), (100u16, 110u16)];
        let result = generate_sorted_from_ranges_random(input);
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);

        // 较大的不相交范围
        let input = &[(1u16, 100u16), (200u16, 500u16)];
        let result = generate_sorted_from_ranges_random(input);
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);

        // 重叠且相邻
        let input = &[(10u16, 20u16), (15u16, 25u16), (26u16, 30u16)];
        let result = generate_sorted_from_ranges_random(input);
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);

        // 接近整个域（开销大）：我们只断言长度与相等
        let input = &[(1u16, 65_535u16)];
        let result = generate_sorted_from_ranges_random(input);
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected.len(), result.len());
        assert_eq!(expected, result);

        // 多个不相交范围 - 检查去重与覆盖
        let input = &[(50u16, 100u16), (1000u16, 2000u16), (30000u16, 30010u16)];
        let result = generate_sorted_from_ranges_random(input);
        let set_len = result.iter().copied().collect::<HashSet<u16>>().len();
        assert_eq!(set_len, result.len());
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);
    }

    #[test]
    fn serial_range_iterator_test() {
        // 串行应保持输入顺序的语义，但这里我们只通过排序结果并与期望集合
        // 比较来断言覆盖（无重复）。

        // 较小的不相交范围
        let input = &[(1u16, 10u16), (20u16, 30u16), (100u16, 110u16)];
        let result = generate_sorted_from_ranges_serial(input);
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);

        // 重叠且相邻
        let input = &[(10u16, 20u16), (15u16, 25u16), (26u16, 30u16)];
        let result = generate_sorted_from_ranges_serial(input);
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);

        // 多个不相交范围
        let input = &[(50u16, 100u16), (1000u16, 2000u16), (30000u16, 30010u16)];
        let result = generate_sorted_from_ranges_serial(input);
        let set_len = result.iter().copied().collect::<HashSet<u16>>().len();
        assert_eq!(set_len, result.len());
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);

        // 所有可能的输入
        let input = &[(u16::MIN, u16::MAX)];
        let result = generate_sorted_from_ranges_serial(input);
        let set_len = result.iter().copied().collect::<HashSet<u16>>().len();
        assert_eq!(set_len, result.len());
        let expected = expected_ports_from_ranges(input);
        assert_eq!(expected, result);
    }
}
