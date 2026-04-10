/// Digest（SM3 摘要）路由
use axum::{extract::State, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

use crate::cert_store::CertStore;
use crate::error::*;
use crate::service::crypto_ops;

#[derive(Deserialize)]
struct DigestReq {
    /// 算法标识，仅支持 SGD_SM3 (0x00000001)
    #[serde(rename = "algID")]
    alg_id: u32,
    /// 待摘要数据 base64
    #[serde(rename = "inData")]
    in_data: String,
    /// 可选：SM2 公钥 SubjectPublicKeyInfo DER base64（用于计算 Z 值）
    #[serde(rename = "publicKey", default)]
    public_key: Option<String>,
    /// 可选：userId base64（默认使用 DEFAULT_ID）
    #[serde(rename = "userID", default)]
    user_id: Option<String>,
}

const SGD_SM3: u32 = 0x00000001;

async fn digest(
    State(_store): State<Arc<CertStore>>,
    Json(req): Json<DigestReq>,
) -> Json<Value> {
    if req.alg_id != SGD_SM3 {
        return Json(resp_err(ERR_ALG_ID));
    }

    let data = match B64.decode(&req.in_data) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_PARAM)),
    };

    // 解析可选公钥和 userId
    let pk_der = if let Some(pk_b64) = &req.public_key {
        match B64.decode(pk_b64) {
            Ok(d) => Some(d),
            Err(_) => return Json(resp_err(ERR_PARAM)),
        }
    } else {
        None
    };

    let uid = if let Some(uid_b64) = &req.user_id {
        match B64.decode(uid_b64) {
            Ok(d) => Some(d),
            Err(_) => return Json(resp_err(ERR_PARAM)),
        }
    } else {
        None
    };

    let digest_result = crypto_ops::sm3_digest(
        &data,
        pk_der.as_deref(),
        uid.as_deref(),
    );

    match digest_result {
        Ok(hash) => Json(resp_ok_with(serde_json::json!({
            "hashData": B64.encode(&hash)
        }))),
        Err(code) => Json(resp_err(code)),
    }
}

pub fn router(store: Arc<CertStore>) -> Router {
    Router::new()
        .route("/Digest", post(digest))
        .with_state(store)
}
