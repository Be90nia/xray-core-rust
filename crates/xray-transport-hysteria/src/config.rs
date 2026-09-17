//! Hysteria 协议常量 + padding 生成器 + Status 枚举（对应 Go `config.go`）。
//!
//! Go 源：`transport/internet/hysteria/config.go`。

use std::sync::OnceLock;

use rand::Rng;

// ===== HTTP/3 错误码（HTTP/3 ErrCode） =====

/// HTTP/3 `ErrCodeNoError`（对应 Go `closeErrCodeOK = 0x100`）。
pub const CLOSE_ERR_CODE_OK: u64 = 0x100;

/// HTTP/3 `ErrCodeGeneralProtocolError`（对应 Go `closeErrCodeProtocolError = 0x101`）。
pub const CLOSE_ERR_CODE_PROTOCOL_ERROR: u64 = 0x101;

// ===== HTTP 头部常量 =====

/// HTTP Host（对应 Go `URLHost = "hysteria"`）。
pub const URLHost: &str = "hysteria";

/// HTTP 路径（对应 Go `URLPath = "/auth"`）。
pub const URLPath: &str = "/auth";

/// 请求头：鉴权 token（对应 Go `RequestHeaderAuth = "Hysteria-Auth"`）。
pub const RequestHeaderAuth: &str = "Hysteria-Auth";

/// 响应头：是否启用 UDP（对应 Go `ResponseHeaderUDPEnabled = "Hysteria-UDP"`）。
pub const ResponseHeaderUDPEnabled: &str = "Hysteria-UDP";

/// 公共头：Brutal 下行带宽（对应 Go `CommonHeaderCCRX = "Hysteria-CC-RX"`）。
pub const CommonHeaderCCRX: &str = "Hysteria-CC-RX";

/// 公共头：padding（对应 Go `CommonHeaderPadding = "Hysteria-Padding"`）。
pub const CommonHeaderPadding: &str = "Hysteria-Padding";

// ===== Frame Type / 容量 =====

/// 鉴权 OK 的 HTTP 状态码（对应 Go `StatusAuthOK = 233`）。
pub const StatusAuthOK: u16 = 233;

/// TCP 请求 frame type（对应 Go `FrameTypeTCPRequest = 0x401`）。
pub const FrameTypeTCPRequest: u64 = 0x401;

/// QUIC datagram 最大字节数（对应 Go `MaxDatagramFrameSize = 1200`）。
pub const MaxDatagramFrameSize: usize = 1200;

/// UDP session channel 缓冲大小（对应 Go `udpMessageChanSize = 1024`）。
pub const UDP_MESSAGE_CHAN_SIZE: usize = 1024;

/// 空闲清理间隔（对应 Go `idleCleanupInterval = 1 * time.Second`）。
pub const IDLE_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Padding 字符表（对应 Go `paddingChars`）。
const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

// ===== Padding 范围（lazy 常量，对应 Go 包级 `var`） =====

/// padding 配置范围（对应 Go `padding{Min, Max int}`）。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Padding {
    /// 最小长度（含）。
    pub min: usize,
    /// 最大长度（含）。
    pub max: usize,
}

impl Padding {
    /// 构造 padding 范围。
    #[must_use]
    pub const fn new(min: usize, max: usize) -> Self {
        Self { min, max }
    }

    /// 生成长度在 `[min, max]` 内的随机 padding 字符串（对应 Go `padding.String()`）。
    ///
    /// Go 的 `rand.Intn(n)` 返回 `[0, n)`；这里 `min + [0, max-min]` 等价 `[min, max]`。
    #[must_use]
    pub fn generate(&self) -> String {
        debug_assert!(self.max >= self.min, "padding max < min");
        let mut rng = rand::rng();
        let n = self.min + rng.random_range(0..=(self.max - self.min));
        let mut bs = vec![0u8; n];
        rng.fill(&mut bs[..]);
        let mut out = String::with_capacity(n);
        for b in bs {
            // ponytail: 用单字节模运算从 PADDING_CHARS 选字符，等价于 Go `rand.Intn(len)`。
            let idx = (b as usize) % PADDING_CHARS.len();
            out.push(PADDING_CHARS[idx] as char);
        }
        out
    }
}

/// 鉴权请求 padding 范围（对应 Go `AuthRequestPadding = padding{256, 2048}`）。
pub static AuthRequestPadding: LazyPadding = LazyPadding::new(Padding::new(256, 2048));

/// 鉴权响应 padding 范围（对应 Go `AuthResponsePadding = padding{256, 2048}`）。
pub static AuthResponsePadding: LazyPadding = LazyPadding::new(Padding::new(256, 2048));

/// TCP 请求 padding 范围（对应 Go `TcpRequestPadding = padding{64, 512}`）。
pub static TcpRequestPadding: LazyPadding = LazyPadding::new(Padding::new(64, 512));

/// TCP 响应 padding 范围（对应 Go `TcpResponsePadding = padding{128, 1024}`）。
pub static TcpResponsePadding: LazyPadding = LazyPadding::new(Padding::new(128, 1024));

/// 静态 Padding 包装器，避免 `const fn` 中初始化 `OnceLock`。
///
/// 调用 `.get()` 拿到 `Padding` 值。
pub struct LazyPadding {
    inner: OnceLock<Padding>,
    value: Padding,
}

impl LazyPadding {
    /// 包裹一个 Padding 值。
    #[must_use]
    pub const fn new(value: Padding) -> Self {
        Self { inner: OnceLock::new(), value }
    }

    /// 取出内部 Padding 值（拷贝）。
    #[must_use]
    pub fn get(&self) -> Padding {
        *self.inner.get_or_init(|| self.value)
    }
}

// ===== Status 枚举（对应 Go `type status int`） =====

/// 客户端状态（对应 Go `status`：StatusNull / StatusActive / StatusInactive）。
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum Status {
    /// 未建立。
    #[default]
    Null = 0,
    /// 已建立且活跃。
    Active = 1,
    /// 已关闭或失败，需 reset。
    Inactive = 2,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_go() {
        assert_eq!(CLOSE_ERR_CODE_OK, 0x100);
        assert_eq!(CLOSE_ERR_CODE_PROTOCOL_ERROR, 0x101);
        assert_eq!(URLHost, "hysteria");
        assert_eq!(URLPath, "/auth");
        assert_eq!(RequestHeaderAuth, "Hysteria-Auth");
        assert_eq!(ResponseHeaderUDPEnabled, "Hysteria-UDP");
        assert_eq!(CommonHeaderCCRX, "Hysteria-CC-RX");
        assert_eq!(CommonHeaderPadding, "Hysteria-Padding");
        assert_eq!(StatusAuthOK, 233);
        assert_eq!(FrameTypeTCPRequest, 0x401);
        assert_eq!(MaxDatagramFrameSize, 1200);
        assert_eq!(UDP_MESSAGE_CHAN_SIZE, 1024);
        assert_eq!(IDLE_CLEANUP_INTERVAL, std::time::Duration::from_secs(1));
    }

    #[test]
    fn padding_lengths_in_range() {
        let cases = [
            (AuthRequestPadding.get(), 256, 2048),
            (AuthResponsePadding.get(), 256, 2048),
            (TcpRequestPadding.get(), 64, 512),
            (TcpResponsePadding.get(), 128, 1024),
        ];
        for (p, lo, hi) in cases {
            for _ in 0..32 {
                let s = p.generate();
                assert!(
                    s.len() >= lo && s.len() <= hi,
                    "padding len {} out of [{}, {}]",
                    s.len(),
                    lo,
                    hi
                );
                assert!(s.bytes().all(|b| PADDING_CHARS.contains(&b)));
            }
        }
    }

    #[test]
    fn padding_equal_min_max_returns_exact_size() {
        let p = Padding::new(100, 100);
        for _ in 0..16 {
            assert_eq!(p.generate().len(), 100);
        }
    }

    #[test]
    fn padding_char_distribution_covers_alphabet() {
        // 大量样本下应该出现所有字符（避免模偏置灾难）。
        let p = Padding::new(0, 4000);
        // ponytail: 至少看到 50 个不同字符（共 62 个）即视为分布正常；
        // 多轮采样消除「随机长度恰好很小」的单样本偶现（实测单轮 0.1% 概率塌）。
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let s = p.generate();
            for c in s.chars() {
                seen.insert(c);
            }
        }
        assert!(
            seen.len() >= 50,
            "padding char distribution skewed: only {} distinct chars",
            seen.len()
        );
    }

    #[test]
    fn status_default_is_null() {
        assert_eq!(Status::default(), Status::Null);
    }

    #[test]
    fn status_repr_matches_go_iota() {
        assert_eq!(Status::Null as i32, 0);
        assert_eq!(Status::Active as i32, 1);
        assert_eq!(Status::Inactive as i32, 2);
    }
}
