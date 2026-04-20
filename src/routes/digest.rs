/// Digest（SM3 摘要）路由
use axum::{extract::State, routing::post, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use std::sync::Arc;

use crate::cert_store::CertStore;
use crate::error::*;
use crate::proto::{Payload, Reply};
use crate::service::crypto_ops;

#[derive(Deserialize)]
struct DigestReq {
    /// 算法标识，仅支持 SGD_SM3 (0x00000001 = 1)
    #[serde(rename = "algId")]
    alg_id: u32,
    /// 待摘要数据 base64
    #[serde(rename = "inData")]
    in_data: String,
    /// 可选：SM2 公钥 SubjectPublicKeyInfo DER base64（用于计算 Z 值）
    #[serde(rename = "publicKey", default)]
    public_key: Option<String>,
    /// 可选：userId base64（默认使用 DEFAULT_ID）
    #[serde(rename = "userId", default)]
    user_id: Option<String>,
}

const SGD_SM3: u32 = 0x00000001;

async fn digest(
    State(_store): State<Arc<CertStore>>,
    Payload(req, wire): Payload<DigestReq>,
) -> Reply {
    if req.alg_id != SGD_SM3 {
        return Reply(resp_err(ERR_ALG_ID), wire);
    }

    if req.in_data.is_empty() {
        return Reply(resp_err(ERR_PARAM), wire);
    }
    let data = match B64.decode(&req.in_data) {
        Ok(d) => d,
        Err(_) => return Reply(resp_err(ERR_PARAM), wire),
    };

    let pk_der = if let Some(pk_b64) = &req.public_key {
        match B64.decode(pk_b64) {
            Ok(d) => Some(d),
            Err(_) => return Reply(resp_err(ERR_PARAM), wire),
        }
    } else {
        None
    };

    let uid = if let Some(uid_b64) = &req.user_id {
        match B64.decode(uid_b64) {
            Ok(d) => Some(d),
            Err(_) => return Reply(resp_err(ERR_PARAM), wire),
        }
    } else {
        None
    };

    match crypto_ops::sm3_digest(&data, pk_der.as_deref(), uid.as_deref()) {
        Ok(hash) => Reply(resp_ok_with(serde_json::json!({
            "digest": B64.encode(&hash)
        })), wire),
        Err(code) => Reply(resp_err(code), wire),
    }
}

pub fn router(store: Arc<CertStore>) -> Router {
    Router::new()
        .route("/Digest", post(digest))
        .with_state(store)
}
