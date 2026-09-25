//! naive DialFn 构造（与其它 outbound `make_*_dial_fn` 模式一致）。

use std::sync::Arc;

use xray_app_dispatcher::default::{DialFn, PinFuture};
use xray_common::net::destination::Destination;

use crate::{dial::dial_naive, uri::NaiveConfig};

/// 构造 naive 拨号闭包：`dest`（最终目标）→ 经 naive 隧道建立的连接。
pub fn make_naive_dial_fn(config: NaiveConfig) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = config.clone();
        let target_host = dest.address().to_string();
        let target_port = dest.port().value();
        Box::pin(async move { dial_naive(&config, &target_host, target_port).await })
            as PinFuture<Result<Box<dyn xray_transport::connection::Connection>, String>>
    })
}
