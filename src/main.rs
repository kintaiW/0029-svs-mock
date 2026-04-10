mod cert_store;
mod config;
mod error;
mod routes;
mod service;

use cert_store::CertStore;
use config::AppConfig;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 加载配置
    let config = AppConfig::load()?;

    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(&config.server.log_level)
        .init();

    let port = config.server.port;

    // 构建证书/密钥仓库
    let store = Arc::new(CertStore::from_config(&config)?);
    info!(
        "CertStore 已加载：根证书 {}个，签名密钥 {}个，加密密钥 {}个",
        store.trusted_roots.len(),
        store.signing_keys.len(),
        store.enc_keys.len(),
    );

    // 构建路由
    let app = routes::build_router(store);

    let addr = format!("0.0.0.0:{}", port);
    info!("SVS Mock 启动，监听 {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
