//! gRPC API 客户端封装。
//!
//! 通过 tonic dial 连接 commander gRPC server，提供四个 service client：
//! - HandlerServiceClient（add/remove inbound/outbound + 用户管理）
//! - StatsServiceClient（stats/stats-query/sys-stats + 在线用户）
//! - RoutingServiceClient（add/remove rule + balancer）
//! - LoggerServiceClient（restart-logger）

use std::time::Duration;

use tonic::transport::{Channel, Endpoint};

use crate::error::CliError;

/// gRPC 连接封装，持有 tonic Channel 和超时设置。
pub struct ApiClient {
    channel: Channel,
    timeout: Duration,
}

impl ApiClient {
    /// 连接到 gRPC server。
    ///
    /// `addr` 格式为 `host:port`（如 `127.0.0.1:8080`）。
    /// `timeout_secs` 为连接和请求超时秒数。
    pub async fn connect(addr: &str, timeout_secs: u64) -> Result<Self, CliError> {
        let endpoint = Endpoint::from_shared(format!("http://{addr}"))
            .map_err(|e| CliError::ApiConnectionFailed(format!("invalid endpoint: {e}")))?
            .timeout(Duration::from_secs(timeout_secs))
            .connect_timeout(Duration::from_secs(timeout_secs));

        let channel = endpoint.connect().await.map_err(|e| {
            CliError::ApiConnectionFailed(format!("failed to connect to {addr}: {e}"))
        })?;

        Ok(Self { channel, timeout: Duration::from_secs(timeout_secs) })
    }

    /// 创建 HandlerService client（proxyman command）。
    pub fn handler_client(
        &self,
    ) -> xray_proto::xray::app::proxyman::command::handler_service_client::HandlerServiceClient<
        Channel,
    > {
        xray_proto::xray::app::proxyman::command::handler_service_client::HandlerServiceClient::new(
            self.channel.clone(),
        )
    }

    /// 创建 StatsService client（stats command）。
    pub fn stats_client(
        &self,
    ) -> xray_proto::xray::app::stats::command::stats_service_client::StatsServiceClient<Channel>
    {
        xray_proto::xray::app::stats::command::stats_service_client::StatsServiceClient::new(
            self.channel.clone(),
        )
    }

    /// 创建 RoutingService client（router command）。
    pub fn routing_client(
        &self,
    ) -> xray_proto::xray::app::router::command::routing_service_client::RoutingServiceClient<Channel>
    {
        xray_proto::xray::app::router::command::routing_service_client::RoutingServiceClient::new(
            self.channel.clone(),
        )
    }

    /// 创建 LoggerService client（log command：restart-logger）。
    pub fn logger_client(
        &self,
    ) -> xray_proto::xray::app::log::command::logger_service_client::LoggerServiceClient<Channel>
    {
        xray_proto::xray::app::log::command::logger_service_client::LoggerServiceClient::new(
            self.channel.clone(),
        )
    }

    /// 返回请求超时时长。
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}
