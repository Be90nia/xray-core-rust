//! 测试支持：可编程假 DNS 客户端（bd 2yj2/czwu 验收）。
//!
//! 记录每次 `lookup_ip` 的查询参数（域名 + v4/v6 使能位），按脚本依次返回
//! 结果；脚本耗尽后返回 `EmptyResponse`。与真实 `DnsClient`（DefaultDnsFeature /
//! dns app）一致按 `IpOption` 过滤家族。全局 `DNS_CLIENT` 是进程级槽位，
//! 使用方须持 [`FAKE_DNS_LOCK`] 串行设置/还原。

use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use xray_features::dns::{DnsClient, DnsError, IpOption};

/// 全局 fake DNS 串行锁：`set_dns_client` 是进程级槽位，并行测试互踩。
pub(crate) static FAKE_DNS_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Default)]
pub(crate) struct FakeDns {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    /// 每次查询记录 (domain, ipv4_enable, ipv6_enable)。
    seen: Mutex<Vec<(String, bool, bool)>>,
    /// 脚本化结果：依次弹出；耗尽后返回 EmptyResponse。
    results: Mutex<Vec<Result<Vec<IpAddr>, DnsError>>>,
}

impl FakeDns {
    /// 便捷构造：每项是一轮查询的应答 IP 列表。
    pub(crate) fn ips(script: Vec<Vec<IpAddr>>) -> Self {
        Self {
            inner: Arc::new(Inner {
                seen: Mutex::new(Vec::new()),
                results: Mutex::new(script.into_iter().map(Ok).collect()),
            }),
        }
    }

    /// 查询记录快照（供断言）。
    pub(crate) fn seen(&self) -> Vec<(String, bool, bool)> {
        self.inner.seen.lock().clone()
    }

    /// 查询次数（供缓存断言）。
    pub(crate) fn query_count(&self) -> usize {
        self.inner.seen.lock().len()
    }
}

#[async_trait::async_trait]
impl DnsClient for FakeDns {
    async fn lookup_ip(
        &self,
        domain: &str,
        option: IpOption,
    ) -> Result<(Vec<IpAddr>, u32), DnsError> {
        self.inner
            .seen
            .lock()
            .push((domain.to_string(), option.ipv4_enable, option.ipv6_enable));
        let result = {
            let mut results = self.inner.results.lock();
            if results.is_empty() { None } else { Some(results.remove(0)) }
        };
        // 真实 DnsClient（DefaultDnsFeature / dns app）按 IPOption 过滤家族；
        // fake 保真同款，否则 Use* 策略测试会随机拿到未请求的家族。
        match result {
            Some(Ok(mut ips)) => {
                ips.retain(|ip| {
                    (ip.is_ipv4() && option.ipv4_enable)
                        || (ip.is_ipv6() && option.ipv6_enable)
                });
                if ips.is_empty() {
                    Err(DnsError::EmptyResponse)
                } else {
                    Ok((ips, xray_features::dns::DEFAULT_TTL))
                }
            }
            Some(Err(e)) => Err(e),
            None => Err(DnsError::EmptyResponse),
        }
    }
}

/// 挂载 fake DNS（须持 [`FAKE_DNS_LOCK`]）。
pub(crate) fn install(fake: &FakeDns) {
    xray_transport::system_dialer::set_dns_client(Some(
        Arc::new(fake.clone()) as Arc<dyn DnsClient>
    ));
}

/// 卸载 fake DNS（须持 [`FAKE_DNS_LOCK`]）。
pub(crate) fn uninstall() {
    xray_transport::system_dialer::set_dns_client(None);
}
