pub mod server;

use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService,
    session::local::LocalSessionManager,
};
use server::SvsMcpServer;
use std::sync::Arc;
use crate::cert_store::CertStore;

/// 构建 MCP Streamable HTTP 服务，挂载到 axum `/mcp` 路径
pub fn build_mcp_service(
    store: Arc<CertStore>,
) -> StreamableHttpService<SvsMcpServer, LocalSessionManager> {
    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false); // Reason: stateless 模式适合本地 mock 场景，无需维护 session 状态
    StreamableHttpService::new(
        move || Ok(SvsMcpServer::new(store.clone())),
        Default::default(),
        config,
    )
}
