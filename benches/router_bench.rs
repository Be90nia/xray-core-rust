//! Router 条件匹配性能基准测试
//!
//! 测量路由规则匹配延迟，对应 Go xray-core 的 router 热路径。
//! 直接 benchmark MemoryPortList.contains()，这是 PortMatcherCondition 的核心。

use criterion::{Criterion, criterion_group, criterion_main};
use xray_common::net::port::{MemoryPortList, Port, PortRange};

/// 端口匹配：命中路径
fn bench_port_match(c: &mut Criterion) {
    let ranges: Vec<PortRange> =
        (80..90).map(|p| PortRange::new(Port::new(p), Port::new(p))).collect();
    let list = MemoryPortList::new(ranges);
    let hit_port = Port::new(85);

    c.bench_function("port_list_contains_10_ports_hit", |b| b.iter(|| list.contains(hit_port)));
}

/// 端口不匹配的快速路径
fn bench_port_miss(c: &mut Criterion) {
    let ranges: Vec<PortRange> =
        (80..90).map(|p| PortRange::new(Port::new(p), Port::new(p))).collect();
    let list = MemoryPortList::new(ranges);
    let miss_port = Port::new(443);

    c.bench_function("port_list_contains_10_ports_miss", |b| b.iter(|| list.contains(miss_port)));
}

/// 端口范围匹配（单个大范围）
fn bench_port_range_match(c: &mut Criterion) {
    let ranges = vec![PortRange::new(Port::new(1000), Port::new(2000))];
    let list = MemoryPortList::new(ranges);
    let hit_port = Port::new(1500);

    c.bench_function("port_range_contains_hit", |b| b.iter(|| list.contains(hit_port)));
}

criterion_group!(benches, bench_port_match, bench_port_miss, bench_port_range_match,);
criterion_main!(benches);
