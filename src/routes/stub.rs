/// 多包接口 stub（12个）
/// 全部返回 ERR_INTERNAL(0x0400000e = 67108878)，表示不支持多包模式
use axum::{routing::post, Json, Router};
use serde_json::Value;
use crate::error::resp_err;
use crate::error::ERR_INTERNAL;

async fn stub_handler() -> Json<Value> {
    Json(resp_err(ERR_INTERNAL))
}

pub fn router() -> Router {
    Router::new()
        .route("/SignDataInit",               post(stub_handler))
        .route("/SignDataUpdate",             post(stub_handler))
        .route("/SignDataFinal",              post(stub_handler))
        .route("/VerifySignedDataInit",       post(stub_handler))
        .route("/VerifySignedDataUpdate",     post(stub_handler))
        .route("/VerifySignedDataFinal",      post(stub_handler))
        .route("/SignMessageInit",            post(stub_handler))
        .route("/SignMessageUpdate",          post(stub_handler))
        .route("/SignMessageFinal",           post(stub_handler))
        .route("/VerifySignedMessageInit",    post(stub_handler))
        .route("/VerifySignedMessageUpdate",  post(stub_handler))
        .route("/VerifySignedMessageFinal",   post(stub_handler))
}
