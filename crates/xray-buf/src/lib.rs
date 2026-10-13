#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))]
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
// 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
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
