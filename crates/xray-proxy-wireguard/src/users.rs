//! WireGuard 动态用户（peer 热插）管理。
//!
//! 对应 Go `proxy/wireguard/server.go:137-207` 的 `AddUser` / `RemoveUser` /
//! `GetUser` / `GetUserByAddr`（`users sync.Map` + `dev.IpcSet` 热插），以及
//! `xray api inbound_user_add/remove`（`app/proxyman/command`）的 wireguard 分支。
//!
//! ## Go 语义对照
//!
//! | Go | 本模块 |
//! |----|--------|
//! | `s.dev == nil` → `"too early"` | driver 槽为空 → [`WgError::Driver`] "too early" |
//! | `peer.Pub == s.pub` → `"invalid public key"` | [`WgUserRegistry::add_user`] 自检 |
//! | `dev.IpcSet("public_key=…\nreplace_allowed_ips=true\n…")` | [`WgDriver::add_peer`] 同公钥原位替换 |
//! | `dev.IpcSet("public_key=…\nremove=true\n")` | [`WgDriver::remove_peer`] |
//! | `users.Store/Delete`（key=Pub） | `users: Vec<WgUser>` 按 public_key 幂等 upsert |
//! | `RemoveUser` 查无此 email → 静默 `nil` | [`WgUserRegistry::remove_user`] 返回 `Ok(())` |

use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use parking_lot::Mutex as ParkMutex;
use xray_app_dispatcher::default::DialFn;
use xray_app_proxyman::{
    command::{
        InboundHandlerWithUserManager, MemoryUser as ProxyMemoryUser,
        UserManager as ProxyUserManager,
    },
    error::ProxymanError,
    inbound::{InboundHandler as ProxyInboundHandler, PinFuture},
};
use xray_proto::xray::app::proxyman::ReceiverConfig;

use crate::{
    config::{DeviceConfig, PeerConfig},
    driver::WgDriver,
    error::{Result, WgError},
    peer::shared_peer,
};

/// driver 句柄槽（与 `crate::inbound::WireguardInboundHandler::driver` 同一 Arc）。
pub type DriverSlot = Arc<ParkMutex<Option<Arc<WgDriver>>>>;

/// 动态用户记录——Go `users sync.Map` 值（`protocol.MemoryUser` + `MemoryAccount`）合体。
#[derive(Clone)]
pub struct WgUser {
    /// 用户邮箱（RemoveUser/GetUser 按 email 查找）。
    pub email: String,
    /// 用户等级。
    pub level: u32,
    /// 对端配置（public_key / allowed_ips / pre_shared_key / keep_alive）。
    pub peer: PeerConfig,
    /// 已注入 driver peer 表的会话。
    pub session: crate::peer::SharedPeer,
}

/// WireGuard 用户注册表——`AddUser`/`RemoveUser` 的真实实现。
///
/// 持有 DeviceConfig 克隆（动态构造 [`crate::peer::PeerSession`] 需要 secret_key 等）
/// 与 driver 句柄槽；用户表按 public_key（忽略大小写，等价 Go 32 字节 Pub）幂等。
pub struct WgUserRegistry {
    device: DeviceConfig,
    /// 本端公钥 hex（"invalid public key" 自检，Go server.go:144-146）。
    server_pub_hex: String,
    driver: DriverSlot,
    users: ParkMutex<Vec<WgUser>>,
    /// 动态 peer 会话 index 单调递增（boringtun 会话唯一标识）。
    next_index: AtomicU32,
}

impl WgUserRegistry {
    /// 构造注册表（推导本端公钥，Go NewServer `curve25519.ScalarBaseMult` 对应物）。
    ///
    /// # Errors
    ///
    /// - [`WgError::InvalidConfig`]：secret_key 不是 64 hex 字符。
    pub fn new(device: DeviceConfig, driver: DriverSlot) -> Result<Self> {
        let server_pub_hex = crate::tunnel::public_key_from_secret(&device.secret_key)?;
        Ok(Self {
            device,
            server_pub_hex,
            driver,
            users: ParkMutex::new(Vec::new()),
            next_index: AtomicU32::new(0),
        })
    }

    /// 添加 / 更新动态 peer 用户（对应 Go `Server.AddUser`，server.go:137-165）。
    ///
    /// - 同公钥再次添加 = 幂等替换（Go `IpcSet replace_allowed_ips=true` + `users.Store`）：更新
    ///   allowed_ips/psk/keepalive/email，会话原位重建。
    /// - 与本端公钥相同 → "invalid public key"。
    /// - 会话构造失败（非法公钥/PSK hex）在此报错，不改动现有表。
    ///
    /// # Errors
    ///
    /// - [`WgError::Driver`]：driver 未初始化（Go "too early"）。
    /// - [`WgError::InvalidConfig`]：公钥等于本端公钥，或公钥/PSK 非法 hex。
    pub fn add_user(&self, email: impl Into<String>, level: u32, peer: PeerConfig) -> Result<()> {
        // Go server.go:144-146：禁止添加本端自身公钥
        if peer.public_key.eq_ignore_ascii_case(&self.server_pub_hex) {
            return Err(WgError::InvalidConfig(
                "invalid public key: peer public key equals local public key".into(),
            ));
        }
        // Go server.go:140-142：dev 未初始化 → "too early"
        let driver = self
            .driver
            .lock()
            .clone()
            .ok_or_else(|| WgError::Driver("too early: device not initialized".into()))?;
        let index = self.next_index.fetch_add(1, Ordering::Relaxed);
        let session = shared_peer(&self.device, &peer, index)?;
        let cidrs = peer.allowed_ips.iter().filter_map(|s| s.parse().ok()).collect();
        driver.add_peer(Arc::clone(&session), cidrs);
        let user = WgUser { email: email.into(), level, peer, session };
        let pub_hex = user.peer.public_key.clone();
        let mut users = self.users.lock();
        match users.iter().position(|u| u.peer.public_key.eq_ignore_ascii_case(&pub_hex)) {
            Some(i) => users[i] = user,
            None => users.push(user),
        }
        Ok(())
    }

    /// 按 email 移除（对应 Go `Server.RemoveUser`，server.go:167-182）。
    ///
    /// 查无此 email 静默成功（Go 直接返回 nil）。
    ///
    /// # Errors
    ///
    /// - [`WgError::Driver`]：driver 未初始化（Go "too early" 先于 email 查找）。
    pub fn remove_user(&self, email: &str) -> Result<()> {
        let driver = self
            .driver
            .lock()
            .clone()
            .ok_or_else(|| WgError::Driver("too early: device not initialized".into()))?;
        let target =
            self.users.lock().iter().find(|u| u.email == email).map(|u| u.peer.public_key.clone());
        let Some(pub_hex) = target else {
            return Ok(());
        };
        driver.remove_peer(&pub_hex);
        self.users.lock().retain(|u| !u.peer.public_key.eq_ignore_ascii_case(&pub_hex));
        Ok(())
    }

    /// 按 email 查找（对应 Go `Server.GetUser`，线性扫描）。
    #[must_use]
    pub fn get_user(&self, email: &str) -> Option<WgUser> {
        self.users.lock().iter().find(|u| u.email == email).cloned()
    }

    /// 按 allowed_ips 命中源地址查找（对应 Go `Server.GetUserByAddr`）。
    #[must_use]
    pub fn get_user_by_addr(&self, addr: IpAddr) -> Option<WgUser> {
        let dest = to_smoltcp_addr(addr);
        self.users
            .lock()
            .iter()
            .find(|u| {
                u.peer
                    .allowed_ips
                    .iter()
                    .filter_map(|s| s.parse::<smoltcp::wire::IpCidr>().ok())
                    .any(|cidr| cidr.contains_addr(&dest))
            })
            .cloned()
    }

    /// 全部用户快照。
    #[must_use]
    pub fn list_users(&self) -> Vec<WgUser> {
        self.users.lock().clone()
    }

    /// 用户数。
    #[must_use]
    pub fn users_count(&self) -> usize {
        self.users.lock().len()
    }
}

/// [`std::net::IpAddr`] → smoltcp [`smoltcp::wire::IpAddress`]（与 inbound.rs 共用逻辑）。
#[allow(clippy::incompatible_msrv)] // 存量清零批次：incompatible_msrv
fn to_smoltcp_addr(addr: IpAddr) -> smoltcp::wire::IpAddress {
    match addr {
        IpAddr::V4(v4) => {
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_octets(v4.octets()))
        },
        IpAddr::V6(v6) => {
            smoltcp::wire::IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from_octets(v6.octets()))
        },
    }
}

// ===== proxyman 接线（xray api inbound_user_add/remove 的 wireguard 分支）=====

/// proxyman [`ProxyUserManager`] 实现——email 视角操作动态用户表。
///
/// `add_user` 无法支持：Go 路径 `AddUserOperation.ApplyInbound` 依赖
/// `user.ToMemoryUser()` 解码 `wireguard.Account`（public_key/allowed_ips），
/// 而 Rust proxyman [`ProxyMemoryUser`] 不携带 account 载荷（见
/// `xray-app-proxyman/src/command/mod.rs` 的 from_proto，仅 email+level）。
/// 此时构造不出 WG peer——对应 Go `ToMemoryUser` 解码失败路径，显式报错。
/// 原生带 peer 参数的入口是 [`WgUserRegistry::add_user`]。
impl ProxyUserManager for WgUserRegistry {
    fn add_user(&self, user: ProxyMemoryUser) -> std::result::Result<(), ProxymanError> {
        Err(ProxymanError::UserParse(format!(
            "wireguard add_user requires wireguard Account (public_key/allowed_ips); \
             proxyman MemoryUser carries no account payload (email={})",
            user.email
        )))
    }

    fn remove_user(&self, email: &str) -> std::result::Result<(), ProxymanError> {
        WgUserRegistry::remove_user(self, email).map_err(|e| ProxymanError::Other(e.to_string()))
    }

    fn get_user(&self, email: &str) -> Option<ProxyMemoryUser> {
        WgUserRegistry::get_user(self, email)
            .map(|u| ProxyMemoryUser { email: u.email, level: u.level })
    }

    fn list_users(&self) -> Vec<ProxyMemoryUser> {
        WgUserRegistry::list_users(self)
            .into_iter()
            .map(|u| ProxyMemoryUser { email: u.email, level: u.level })
            .collect()
    }
}

/// proxyman 入站 handler 适配——委托到 xray-features [`crate::inbound::WireguardInboundHandler`]
/// 的同步 `do_start` /
/// `do_close`。
impl ProxyInboundHandler for crate::inbound::WireguardInboundHandler {
    fn tag(&self) -> &str {
        <Self as xray_features::inbound::InboundHandler>::tag(self)
    }

    fn start(&self) -> PinFuture<std::result::Result<(), ProxymanError>> {
        let result = crate::inbound::WireguardInboundHandler::do_start(self)
            .map_err(|e| ProxymanError::Other(e.to_string()));
        Box::pin(async move { result })
    }

    fn close(&self) -> PinFuture<std::result::Result<(), ProxymanError>> {
        let result = crate::inbound::WireguardInboundHandler::do_close(self)
            .map_err(|e| ProxymanError::Other(e.to_string()));
        Box::pin(async move { result })
    }

    fn receiver_settings(&self) -> Option<&ReceiverConfig> {
        None
    }

    fn proxy_type_url(&self) -> &str {
        "xray.proxy.wireguard.DeviceConfig"
    }
}

/// 暴露 wireguard 分支的 UserManager（Go `p.(proxy.UserManager)` 两步断言对应物）。
impl InboundHandlerWithUserManager for crate::inbound::WireguardInboundHandler {
    fn user_manager(&self) -> Option<&dyn ProxyUserManager> {
        Some(self.user_registry() as &dyn ProxyUserManager)
    }
}

mod tests {
    use xray_common::net::{
        address::Address, destination::Destination, network::Network, port::Port,
    };

    use super::*;
    use crate::{driver::WgTransport, peer::SharedPeer};
    #[allow(dead_code)] // 存量清零批次
    fn make_keypair(seed: u8) -> (String, String) {
        use boringtun::x25519::{PublicKey, StaticSecret};
        let secret_bytes = [seed; 32];
        let public = PublicKey::from(&StaticSecret::from(secret_bytes));
        (hex::encode(secret_bytes), hex::encode(public.as_bytes()))
    }

    /// Dialed 假传输 driver（不跑 main_loop，无需真实 socket）。
    #[allow(dead_code)] // 存量清零批次
    fn test_driver(device: &DeviceConfig, static_pub: &str) -> DriverSlot {
        let peer: SharedPeer = shared_peer(
            device,
            &PeerConfig { public_key: static_pub.into(), ..Default::default() },
            0,
        )
        .expect("static peer");
        let dest = Destination::new(
            Address::from_ipv4_bytes([203, 0, 113, 1]),
            Port::new(51820),
            Network::UDP,
        );
        let dialer: DialFn = Arc::new(|_| Box::pin(async { Err("unused".to_string()) }));
        let ns = Arc::new(tokio::sync::Mutex::new(crate::netstack::WgNetStack::new(
            &[smoltcp::wire::IpCidr::new(
                smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)),
                32,
            )],
            1420,
        )));
        let driver = WgDriver::with_transport(
            vec![peer],
            vec![vec![]],
            WgTransport::Dialed(Arc::new(crate::driver::DialedUdp::new(dialer, dest))),
            ns,
        );
        Arc::new(ParkMutex::new(Some(Arc::new(driver))))
    }
    #[allow(dead_code)] // 存量清零批次
    fn make_registry() -> (WgUserRegistry, String, String, String) {
        let (sec_s, pub_s) = make_keypair(0x22);
        let (_, pub_static) = make_keypair(0x11);
        let (_, pub_dyn) = make_keypair(0x33);
        let device = DeviceConfig { secret_key: sec_s, ..Default::default() };
        let driver = test_driver(&device, &pub_static);
        let registry = WgUserRegistry::new(device, driver).expect("registry");
        (registry, pub_s, pub_static, pub_dyn)
    }
    #[allow(dead_code)] // 存量清零批次
    fn peer_cfg(pub_key: String, allowed: &str) -> PeerConfig {
        PeerConfig { public_key: pub_key, allowed_ips: vec![allowed.into()], ..Default::default() }
    }

    // ===== Go server.go:137-165 AddUser 语义 =====

    #[test]
    fn add_user_hot_plugs_peer_and_is_queryable() {
        let (registry, _pub_s, _pub_static, pub_dyn) = make_registry();
        registry.add_user("alice@x.com", 2, peer_cfg(pub_dyn.clone(), "10.0.2.0/24")).expect("add");
        assert_eq!(registry.users_count(), 1);
        // 已注入 driver peer 表（静态 1 + 动态 1）
        assert_eq!(registry.driver.lock().as_ref().expect("driver").peer_count(), 2);

        let u = registry.get_user("alice@x.com").expect("found");
        assert_eq!(u.level, 2);
        assert_eq!(u.peer.public_key, pub_dyn);
        // GetUserByAddr：allowed_ips 命中 / 未命中
        assert!(registry.get_user_by_addr("10.0.2.7".parse().unwrap()).is_some());
        assert!(registry.get_user_by_addr("10.0.3.7".parse().unwrap()).is_none());
    }

    #[test]
    fn add_user_same_public_key_replaces_idempotently() {
        // Go IpcSet replace_allowed_ips=true + users.Store：同 pub 覆盖（含 email）
        let (registry, _pub_s, _pub_static, pub_dyn) = make_registry();
        registry.add_user("old@x.com", 0, peer_cfg(pub_dyn.clone(), "10.0.2.0/24")).expect("add");
        registry
            .add_user("new@x.com", 5, peer_cfg(pub_dyn.to_uppercase(), "10.0.9.0/24"))
            .expect("re-add");
        assert_eq!(registry.users_count(), 1, "同公钥幂等替换");
        let u = registry.get_user("new@x.com").expect("replaced email");
        assert_eq!(u.level, 5);
        assert!(registry.get_user("old@x.com").is_none(), "旧 email 被覆盖");
        assert_eq!(registry.driver.lock().as_ref().unwrap().peer_count(), 2, "driver 表仍 1+1");
    }

    #[test]
    fn add_user_with_local_public_key_rejected() {
        // Go server.go:144-146 "invalid public key"
        let (registry, pub_s, _pub_static, _pub_dyn) = make_registry();
        let err = registry.add_user("self@x.com", 0, peer_cfg(pub_s, "10.0.0.0/24")).unwrap_err();
        assert!(err.to_string().contains("invalid public key"), "got: {err}");
        assert_eq!(registry.users_count(), 0);
    }

    #[test]
    fn add_user_invalid_public_key_hex_rejected_without_table_change() {
        let (registry, _pub_s, _pub_static, _pub_dyn) = make_registry();
        let err =
            registry.add_user("bad@x.com", 0, peer_cfg("zz".into(), "10.0.2.0/24")).unwrap_err();
        assert!(err.to_string().contains("public_key"), "got: {err}");
        assert_eq!(registry.users_count(), 0, "失败不改动现有表");
    }

    #[test]
    fn add_user_before_driver_ready_is_too_early() {
        // Go server.go:140-142 dev == nil → "too early"
        let (sec_s, _pub_s) = make_keypair(0x22);
        let (_, pub_dyn) = make_keypair(0x33);
        let device = DeviceConfig { secret_key: sec_s, ..Default::default() };
        let empty_slot: DriverSlot = Arc::new(ParkMutex::new(None));
        let registry = WgUserRegistry::new(device, empty_slot).expect("registry");
        let err =
            registry.add_user("a@x.com", 0, peer_cfg(pub_dyn.clone(), "10.0.2.0/24")).unwrap_err();
        assert!(err.to_string().contains("too early"), "got: {err}");
        let err = registry.remove_user("a@x.com").unwrap_err();
        assert!(err.to_string().contains("too early"), "got: {err}");
    }

    // ===== Go server.go:167-182 RemoveUser 语义 =====

    #[test]
    fn remove_user_unknown_email_is_silent_ok() {
        let (registry, _pub_s, _pub_static, _pub_dyn) = make_registry();
        registry.remove_user("ghost@x.com").expect("Go 静默语义：查无此 email 不报错");
    }

    #[test]
    fn remove_user_drops_peer_from_driver_table() {
        let (registry, _pub_s, _pub_static, pub_dyn) = make_registry();
        registry.add_user("alice@x.com", 0, peer_cfg(pub_dyn, "10.0.2.0/24")).expect("add");
        assert_eq!(registry.driver.lock().as_ref().unwrap().peer_count(), 2);
        registry.remove_user("alice@x.com").expect("remove");
        assert_eq!(registry.users_count(), 0);
        assert!(registry.get_user("alice@x.com").is_none());
        assert_eq!(registry.driver.lock().as_ref().unwrap().peer_count(), 1, "driver 表同步收缩");
    }

    // ===== proxyman UserManager 接线 =====

    #[test]
    fn proxyman_add_user_requires_account_payload() {
        // Rust proxyman MemoryUser 无 account 载荷——对应 Go ToMemoryUser 解码失败
        let (registry, _pub_s, _pub_static, _pub_dyn) = make_registry();
        let err = ProxyUserManager::add_user(
            &registry,
            ProxyMemoryUser { email: "a@x.com".into(), level: 0 },
        )
        .expect_err("无公钥不可构造 WG peer");
        assert!(matches!(err, ProxymanError::UserParse(_)), "got: {err}");
    }

    #[test]
    fn proxyman_remove_and_get_delegate_to_native_table() {
        let (registry, _pub_s, _pub_static, pub_dyn) = make_registry();
        registry.add_user("alice@x.com", 3, peer_cfg(pub_dyn, "10.0.2.0/24")).expect("native add");
        // trait 视角 get/list
        let u = ProxyUserManager::get_user(&registry, "alice@x.com").expect("found");
        assert_eq!(u.email, "alice@x.com");
        assert_eq!(u.level, 3);
        assert_eq!(ProxyUserManager::list_users(&registry).len(), 1);
        // trait 视角 remove（email 定位 → driver peer 同步移除）
        ProxyUserManager::remove_user(&registry, "alice@x.com").expect("remove");
        assert!(ProxyUserManager::get_user(&registry, "alice@x.com").is_none());
        assert_eq!(registry.driver.lock().as_ref().unwrap().peer_count(), 1);
    }
}
