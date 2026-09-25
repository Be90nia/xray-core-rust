//! Fuzz VLESS 入站请求头帧解析（`xray-proxy-vless` encoding/server.rs，
//! 对应 Go `DecodeRequestHeader`：version/UUID/addons(JSON)/command/port/address）。
//!
//! Validator stub 对任意 UUID 放行（返回固定用户），使变异输入能穿越认证
//! 到达 addons JSON 与 address 解析这两个真正的深解析面。isfb 分支按输入
//! 首字节奇偶切换，两条首包路径（17B 预读 vs 纯流式）都被覆盖。

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use tokio::runtime::Builder;
use xray_common::protocol::ID;
use xray_common::uuid::UUID;
use xray_proxy_vless::account::MemoryAccount;
use xray_proxy_vless::encoding::server::decode_request_header;
use xray_proxy_vless::error::Result;
use xray_proxy_vless::validator::{MemoryUser, Validator};

/// 任意 UUID 均放行的 stub（fuzz 专用，非生产路径）。
struct AcceptAll;

impl Validator for AcceptAll {
    fn get(&self, _id: &UUID) -> Option<MemoryUser> {
        let account = MemoryAccount {
            id: ID::new(UUID::new()),
            flow: String::new(),
            encryption: "none".to_string(),
            xor_mode: 0,
            seconds: 0,
            padding: String::new(),
            reverse: None,
            testpre: 0,
            testseed: Vec::new(),
        };
        Some(MemoryUser::new("fuzz", 0, account))
    }

    fn add(&self, _user: MemoryUser) -> Result<()> {
        Ok(())
    }

    fn del(&self, _email: &str) -> Result<()> {
        Ok(())
    }

    fn get_by_email(&self, _email: &str) -> Option<MemoryUser> {
        None
    }

    fn get_all(&self) -> Vec<MemoryUser> {
        Vec::new()
    }

    fn get_count(&self) -> i64 {
        0
    }

    fn get_uuid_count(&self) -> i64 {
        0
    }
}

fuzz_target!(|data: &[u8]| {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        let isfb = data.len() >= 17 && data[0] & 1 == 1;
        let (mut first, body) = if isfb {
            (Some(data[..17].to_vec()), &data[17..])
        } else {
            (None, data)
        };
        let mut reader = Cursor::new(body);
        let validator = AcceptAll;
        // Err 属预期 fuzz 结果（格式非法即报错），不 panic
        let _ = decode_request_header(isfb, &mut first, &mut reader, &validator).await;
    });
});
