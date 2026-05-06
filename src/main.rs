mod cert_store;
mod config;
mod error;
mod mcp;
mod proto;
mod routes;
mod service;

use cert_store::CertStore;
use clap::{Parser, ValueEnum};
use config::AppConfig;
use std::sync::Arc;
use tracing::info;

#[derive(Parser)]
#[command(version, about = "SVS Mock — GM/T 0029-2014 Signature Verification Server")]
struct Cli {
    /// 运行模式：rest（仅 REST API）、mcp（仅 MCP Server）、both（默认，同时启动）
    #[arg(long, default_value = "both")]
    mode: Mode,
}

#[derive(Clone, ValueEnum)]
enum Mode {
    Rest,
    Mcp,
    Both,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config = AppConfig::load()?;

    tracing_subscriber::fmt()
        .with_env_filter(&config.server.log_level)
        .init();

    info!("{} v{} starting", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    let port = config.server.port;
    let store = Arc::new(CertStore::from_config(&config)?);
    info!(
        "CertStore 已加载：根证书 {}个，签名密钥 {}个，加密密钥 {}个",
        store.trusted_roots.len(),
        store.signing_keys.len(),
        store.enc_keys.len(),
    );

    let mut router = axum::Router::new();

    match cli.mode {
        Mode::Rest => {
            info!("模式：REST only");
            router = router.merge(routes::build_router(store));
        }
        Mode::Mcp => {
            info!("模式：MCP only（/mcp）");
            let mcp_svc = mcp::build_mcp_service(store);
            router = router.nest_service("/mcp", mcp_svc);
        }
        Mode::Both => {
            info!("模式：REST + MCP（/mcp）");
            let mcp_svc = mcp::build_mcp_service(store.clone());
            router = router
                .merge(routes::build_router(store))
                .nest_service("/mcp", mcp_svc);
        }
    }

    let addr = format!("0.0.0.0:{}", port);
    info!("SVS Mock 启动，监听 {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}
