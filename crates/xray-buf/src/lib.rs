// 数据面分配纪律（P0 护栏，见本 crate clippy.toml）：测试编译单元统一豁免，
// 断言扁平化属测试便利；生产代码禁令不受影响。
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod alloc;
pub mod buffer;
pub mod copy;
pub mod io;
pub mod multi;
pub mod pipe;
pub mod reader;
pub mod readv;
pub mod timeout;
pub mod writer;
