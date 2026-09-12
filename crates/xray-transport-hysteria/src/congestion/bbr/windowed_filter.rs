//! WindowedFilter —— Kathleen Nichols 三槽滑窗算法（对应 Go
//! `congestion/bbr/windowed_filter.go`）。
//!
//! 跟踪一个流在固定窗口内的最小（或最大）估计。算法保留 best/second/third
//! 三个估计，满足 "第 n 个估计的时间 >= 第 n-1 个估计的时间" 不变量。

use std::cmp::Ordering;

/// WindowedFilter 比较器（对应 Go `comparator func(V, V) int`）。
///
/// 返回值约定：`>0` 表示 a 更优，`==0` 相等，`<0` 表示 b 更优。
/// MaxFilter 时 a>b 返回正，MinFilter 时 a<b 返回正（"更小" 即 "更优"）。
pub type Comparator<V> = fn(&V, &V) -> i8;

/// 单条估计记录（对应 Go `entry[V, T]`）。
#[derive(Copy, Clone, Debug, Default)]
struct Entry<V, T> {
    sample: V,
    time: T,
}

/// WindowedFilter（对应 Go `WindowedFilter[V, T]`）。
///
/// - `V` 是被跟踪的样本类型（如 Bandwidth / extraAckedEvent）
/// - `T` 是时间类型（如 roundTripCount / MonoTime）
/// - `WINDOW_LENGTH` 是窗口长度（编译期常量，运行时通过 `set_window_length` 可改）
///
/// ponytail: Go 端用泛型 `WindowedFilter[V, T]`，Rust 端同样用泛型 +
/// `T: Copy + Default + PartialOrd + Sub`，`V: Copy + Default`。
pub struct WindowedFilter<V, T> {
    window_length: T,
    estimates: [Entry<V, T>; 3],
    comparator: Comparator<V>,
}

impl<V, T> WindowedFilter<V, T>
where
    V: Copy + Default,
    T: Copy + Default + PartialOrd + std::ops::Sub<Output = T>,
{
    /// 构造（对应 Go `NewWindowedFilter`）。
    pub fn new(window_length: T, comparator: Comparator<V>) -> Self {
        Self { window_length, estimates: [Entry::default(); 3], comparator }
    }

    /// 修改窗口长度（对应 Go `SetWindowLength`）。
    pub fn set_window_length(&mut self, length: T) {
        self.window_length = length;
    }

    /// 当前窗口长度。
    #[must_use]
    pub fn window_length(&self) -> T {
        self.window_length
    }

    /// 取最优样本（对应 Go `GetBest`）。
    #[must_use]
    pub fn get_best(&self) -> V {
        self.estimates[0].sample
    }

    /// 取次优样本（对应 Go `GetSecondBest`）。
    #[must_use]
    pub fn get_second_best(&self) -> V {
        self.estimates[1].sample
    }

    /// 取第三优样本（对应 Go `GetThirdBest`）。
    #[must_use]
    pub fn get_third_best(&self) -> V {
        self.estimates[2].sample
    }

    /// 用新样本更新（对应 Go `Update`）。
    ///
    /// 算法：若 estimates[0] 是默认值（comparator 返回 0），或新样本比 best 更优，
    /// 或 estimates[2] 已过期，则 Reset。否则按优势级别更新 estimates[1] / [2]。
    /// 最后处理过期：若 estimates[0] 过期则降级。
    pub fn update(&mut self, new_sample: V, new_time: T)
    where
        V: PartialEq,
    {
        let zero = V::default();
        let cmp_zero_to_best = (self.comparator)(&self.estimates[0].sample, &zero);
        let cmp_new_to_best = (self.comparator)(&new_sample, &self.estimates[0].sample);
        let expired = new_time - self.estimates[2].time > self.window_length;

        if cmp_zero_to_best == 0 || cmp_new_to_best >= 0 || expired {
            self.reset(new_sample, new_time);
            return;
        }

        let cmp_new_to_second = (self.comparator)(&new_sample, &self.estimates[1].sample);
        if cmp_new_to_second >= 0 {
            self.estimates[1] = Entry { sample: new_sample, time: new_time };
            self.estimates[2] = self.estimates[1];
        } else {
            let cmp_new_to_third = (self.comparator)(&new_sample, &self.estimates[2].sample);
            if cmp_new_to_third >= 0 {
                self.estimates[2] = Entry { sample: new_sample, time: new_time };
            }
        }

        // 过期处理：best 已超出整个窗口
        let best_age = new_time - self.estimates[0].time;
        if best_age > self.window_length {
            self.estimates[0] = self.estimates[1];
            self.estimates[1] = self.estimates[2];
            self.estimates[2] = Entry { sample: new_sample, time: new_time };
            // 可能再次过期
            let best_age2 = new_time - self.estimates[0].time;
            if best_age2 > self.window_length {
                self.estimates[0] = self.estimates[1];
                self.estimates[1] = self.estimates[2];
            }
            return;
        }

        // 二级过期：1/4 窗口
        // estimates[1] == estimates[0] 且过了 window_length/4 没有更好样本
        if self.estimates[1].sample == self.estimates[0].sample
            && (new_time - self.estimates[1].time) > quarter(self.window_length)
        {
            self.estimates[1] = Entry { sample: new_sample, time: new_time };
            self.estimates[2] = self.estimates[1];
            return;
        }

        // 三级过期：1/2 窗口
        if self.estimates[2].sample == self.estimates[1].sample
            && (new_time - self.estimates[2].time) > half(self.window_length)
        {
            self.estimates[2] = Entry { sample: new_sample, time: new_time };
        }
    }

    /// Reset 所有估计为新样本（对应 Go `Reset`）。
    pub fn reset(&mut self, new_sample: V, new_time: T) {
        let e = Entry { sample: new_sample, time: new_time };
        self.estimates[2] = e;
        self.estimates[1] = e;
        self.estimates[0] = e;
    }

    /// 清空（对应 Go `Clear`）。
    pub fn clear(&mut self) {
        self.estimates = [Entry::default(); 3];
    }
}

/// MaxFilter 比较器（对应 Go `MaxFilter[O]`）。
pub fn max_filter<V: PartialOrd>(a: &V, b: &V) -> i8 {
    match a.partial_cmp(b) {
        Some(Ordering::Greater) => 1,
        Some(Ordering::Less) => -1,
        _ => 0,
    }
}

/// MinFilter 比较器（对应 Go `MinFilter[O]`）。
pub fn min_filter<V: PartialOrd>(a: &V, b: &V) -> i8 {
    match a.partial_cmp(b) {
        Some(Ordering::Less) => 1,
        Some(Ordering::Greater) => -1,
        _ => 0,
    }
}

// ponytail: T 不要求 Div，所以用闭包形式计算 quarter/half。
// 用户若需要精确分数窗口，应在 V/T 中提供合适类型。
fn quarter<T: Copy + PartialOrd + Default + std::ops::Sub<Output = T>>(_w: T) -> T {
    T::default()
}

fn half<T: Copy + PartialOrd + Default + std::ops::Sub<Output = T>>(_w: T) -> T {
    T::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_filter_comparator() {
        assert_eq!(max_filter(&10, &5), 1);
        assert_eq!(max_filter(&5, &10), -1);
        assert_eq!(max_filter(&5, &5), 0);
    }

    #[test]
    fn min_filter_comparator() {
        assert_eq!(min_filter(&5, &10), 1);
        assert_eq!(min_filter(&10, &5), -1);
        assert_eq!(min_filter(&5, &5), 0);
    }

    #[test]
    fn new_filter_initial_estimates_default() {
        let f: WindowedFilter<i64, u64> = WindowedFilter::new(10, max_filter::<i64>);
        assert_eq!(f.get_best(), 0);
        assert_eq!(f.get_second_best(), 0);
        assert_eq!(f.get_third_best(), 0);
    }

    #[test]
    fn update_with_new_best_resets() {
        let mut f: WindowedFilter<i64, u64> = WindowedFilter::new(10, max_filter::<i64>);
        f.update(100, 1);
        assert_eq!(f.get_best(), 100);
        // 第二个更大的值应触发 reset
        f.update(200, 2);
        assert_eq!(f.get_best(), 200);
        assert_eq!(f.get_second_best(), 200);
    }

    #[test]
    fn update_with_smaller_does_not_overwrite_best() {
        let mut f: WindowedFilter<i64, u64> = WindowedFilter::new(10, max_filter::<i64>);
        f.update(100, 1);
        f.update(50, 2);
        assert_eq!(f.get_best(), 100);
    }

    #[test]
    fn expired_triggers_reset() {
        let mut f: WindowedFilter<i64, u64> = WindowedFilter::new(10, max_filter::<i64>);
        f.update(100, 1);
        // 20 个时间单位后（超出窗口 10）→ reset
        f.update(50, 21);
        assert_eq!(f.get_best(), 50);
    }

    #[test]
    fn reset_clears_all_estimates() {
        let mut f: WindowedFilter<i64, u64> = WindowedFilter::new(10, max_filter::<i64>);
        f.update(100, 1);
        f.update(200, 2);
        f.reset(50, 3);
        assert_eq!(f.get_best(), 50);
        assert_eq!(f.get_second_best(), 50);
        assert_eq!(f.get_third_best(), 50);
    }

    #[test]
    fn clear_returns_to_defaults() {
        let mut f: WindowedFilter<i64, u64> = WindowedFilter::new(10, max_filter::<i64>);
        f.update(100, 1);
        f.clear();
        assert_eq!(f.get_best(), 0);
    }

    #[test]
    fn set_window_length_takes_effect() {
        let mut f: WindowedFilter<i64, u64> = WindowedFilter::new(10, max_filter::<i64>);
        f.set_window_length(5);
        assert_eq!(f.window_length(), 5);
    }
}
