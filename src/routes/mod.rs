pub mod cert;
pub mod digest;
pub mod envelope;
pub mod sign;
pub mod verify;
pub mod stub;

use axum::Router;
use std::sync::Arc;
use crate::cert_store::CertStore;

/// 构建完整路由表
pub fn build_router(store: Arc<CertStore>) -> Router {
    Router::new()
        // 通用证书接口
        .merge(cert::router(store.clone()))
        // 摘要接口
        .merge(digest::router(store.clone()))
        // 数字信封接口
        .merge(envelope::router(store.clone()))
        // 签名接口
        .merge(sign::router(store.clone()))
        // 验签接口
        .merge(verify::router(store.clone()))
        // 多包 stub 接口
        .merge(stub::router())
}
