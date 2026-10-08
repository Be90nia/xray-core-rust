// async-trait 展开对 trait 脱糖方法加 #[must_use]（其 expand.rs:69），clippy 1.99 起
// 将 Pin<Box<dyn Future>> 判为已 must_use → double_must_use 误报；宏行为非本 crate 可控。
#![allow(clippy::double_must_use)]

pub mod client;
pub mod frame;
pub mod handler;
pub mod reader;
pub mod session;
pub mod worker;
pub mod writer;
