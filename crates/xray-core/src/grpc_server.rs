//! # gRPC 服务器
//!
//! 基于 tonic 的 gRPC 服务器，用于 Commander API。
//! 对应 Go `google.golang.org/grpc.Server`。
//!
//! ## 设计
//!
//! tonic 的 `add_service` 需要类型化 `Service<Request<Body>> + NamedService + Clone`，
//! 这些 trait 不 dyn-compatible（有 associated types），无法存入 `Vec<Box<dyn ...>>`。
//! 因此采用闭包构建模式：调用方在闭包内用具体类型注册 service。
//!
//! ## 使用
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! serve_grpc("127.0.0.1:8080", |server| {
//!     server.add_service(stats_server).add_service(router_server)
//! })
//! .await?;
//! # Ok(())
//! # }
//! ```

use std::{error::Error, net::SocketAddr};

use tonic::transport::{Server, server::Router};

/// 启动 gRPC 服务器。
///
/// `register` 闭包接收 `Server`，调用 `add_service` 注册各 tonic-generated
/// service（`*Server<T>`），返回 `Router`。
///
/// 阻塞当前 async task 直到服务器停止。
///
/// # 错误
///
/// - 地址解析失败
/// - tonic transport 错误（端口被占用等）
pub async fn serve_grpc<F>(addr: &str, register: F) -> Result<(), Box<dyn Error + Send + Sync>>
where
    F: FnOnce(Server) -> Router,
{
    let socket_addr: SocketAddr =
        addr.parse().map_err(|e| format!("invalid gRPC listen address `{addr}`: {e}"))?;

    tracing::info!("gRPC server listening on {socket_addr}");

    let router = register(Server::builder());
    router.serve(socket_addr).await?;
    Ok(())
}

/// 在后台 tokio task 中启动 gRPC 服务器。
///
/// 返回 `JoinHandle`，可用于等待服务器停止。
///
/// # 错误
///
/// 如果地址解析失败，立即返回错误（不 spawn task）。
#[allow(clippy::type_complexity)] // 返回类型即 spawn 句柄形态
pub fn spawn_grpc<F>(
    addr: &str,
    register: F,
) -> Result<
    tokio::task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>>,
    Box<dyn Error + Send + Sync>,
>
where
    F: FnOnce(Server) -> Router + Send + 'static,
{
    let socket_addr: SocketAddr =
        addr.parse().map_err(|e| format!("invalid gRPC listen address `{addr}`: {e}"))?;

    tracing::info!("gRPC server (background) will listen on {socket_addr}");

    Ok(tokio::spawn(async move {
        let router = register(Server::builder());
        router.serve(socket_addr).await?;
        Ok(())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_address_returns_error() {
        // 地址解析在闭包调用前发生，闭包不会被调用
        // 用一个 panic 闭包确保不会到达
        assert!(spawn_grpc("not-a-valid-addr", |_| unreachable!()).is_err());
    }

    #[tokio::test]
    async fn serve_grpc_invalid_addr_errors() {
        assert!(serve_grpc("bad-addr", |_| unreachable!()).await.is_err());
    }
}
