//! SplitHTTP HTTP/1.1 connection handling —— Rust 在 hyper 抽象下不需要 H1Conn。
//!
//! # Go 原版 vs Rust 简化
//!
//! Go `transport/internet/splithttp/h1_conn.go` (19 行) 定义了 `H1Conn` struct：
//!
//! ```go
//! type H1Conn struct {
//!     UnreadedResponsesCount int
//!     RespBufReader          *bufio.Reader
//!     net.Conn
//! }
//! ```
//!
//! 用途：HTTP/1.1 raw upload conn pool 中包装 `net.Conn`，用 `bufio.Reader` 缓冲
//! 响应读取（避免每个 `Read` 系统调用），同时跟踪未读响应数（pool 复用判断）。
//!
//! # Rust 不需要的理由
//!
//! hyper 1.x 已经在内部完整处理 HTTP/1.1 连接管理：
//!
//! - **响应 buffer**：hyper 自带 `BufReader` 等价机制，不需要应用层包装
//! - **连接池**：`hyper-util::client::legacy::Client` 内置 H1/H2 连接池
//!   （`pool_idle_timeout` / `pool_max_idle_per_host` 配置）
//! - **chunked transfer**：hyper 自动处理 chunked encoding
//! - **未读响应跟踪**：hyper 内部 state machine 管理，不需要手动 count
//!
//! Go 的 uploadRawPool（H1 上传连接池）是为了绕过 Go 标准库 `http.Client` 在 H1
//! keep-alive 上的限制（连接复用前必须 drain）。hyper 没有这个限制。
//!
//! 因此 Rust 端 H1Conn + uploadRawPool + UnreadedResponsesCount 全部不需要，
//! [`crate::client::DefaultDialerClient`] 直接用 hyper-util Client 统一处理 H1/H2。
