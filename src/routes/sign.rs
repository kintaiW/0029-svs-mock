/// SignData / SignMessage 路由
use axum::{extract::State, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use der::Decode;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use x509_cert::Certificate;

use crate::cert_store::CertStore;
use crate::error::*;
use crate::service::{cms_ops, crypto_ops};

const SGD_SM3_SM2: u32 = 0x00020201; // 签名算法标识

#[derive(Deserialize)]
struct SignDataReq {
    #[serde(rename = "keyIndex")]
    key_index: u32,
    /// PIN 码
    #[serde(rename = "keyValue")]
    key_value: String,
    #[serde(rename = "algID", default)]
    alg_id: Option<u32>,
    /// 待签名数据 base64
    #[serde(rename = "inData")]
    in_data: String,
    #[serde(rename = "inDataLen", default)]
    _in_data_len: Option<u32>,
}

#[derive(Deserialize)]
struct SignMessageReq {
    #[serde(rename = "keyIndex")]
    key_index: u32,
    #[serde(rename = "keyValue")]
    key_value: String,
    /// 待签名原文 base64
    #[serde(rename = "inData")]
    in_data: String,
    /// 是否包含原文（0=不包含，1=包含）
    #[serde(rename = "signatureType", default)]
    signature_type: u32,
    /// 是否包含证书链（0=不包含，1=包含）
    #[serde(rename = "certType", default)]
    cert_type: u32,
}

async fn sign_data(
    State(store): State<Arc<CertStore>>,
    Json(req): Json<SignDataReq>,
) -> Json<Value> {
    // 验证算法标识（允许缺省，默认为 SM2withSM3）
    if let Some(alg) = req.alg_id {
        if alg != SGD_SM3_SM2 {
            return Json(resp_err(ERR_ALG_ID));
        }
    }

    // 验证 keyIndex 和 PIN
    let key_cfg = match store.signing_keys.get(&req.key_index) {
        Some(k) => k,
        None => return Json(resp_err(ERR_KEY_INDEX)),
    };
    if key_cfg.pin != req.key_value {
        return Json(resp_err(ERR_KEY_AUTH));
    }

    let data = match B64.decode(&req.in_data) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_PARAM)),
    };

    match crypto_ops::sm2_sign(&key_cfg.private_key, &data) {
        Ok(sig) => Json(resp_ok_with(serde_json::json!({
            "signData": B64.encode(&sig)
        }))),
        Err(code) => Json(resp_err(code)),
    }
}

async fn sign_message(
    State(store): State<Arc<CertStore>>,
    Json(req): Json<SignMessageReq>,
) -> Json<Value> {
    // 验证 keyIndex 和 PIN
    let key_cfg = match store.signing_keys.get(&req.key_index) {
        Some(k) => k,
        None => return Json(resp_err(ERR_KEY_INDEX)),
    };
    if key_cfg.pin != req.key_value {
        return Json(resp_err(ERR_KEY_AUTH));
    }

    let data = match B64.decode(&req.in_data) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_PARAM)),
    };

    // 解码签名证书
    let cert_der = match B64.decode(&key_cfg.cert) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_CERT_DECODE)),
    };

    // signatureType=0 表示不附原文（detached），1 表示附原文
    let detached = req.signature_type == 0;
    // certType=1 表示附证书
    let include_cert = req.cert_type == 1;

    match cms_ops::sign_message(&key_cfg.private_key, &cert_der, &data, detached, include_cert) {
        Ok(cms_der) => Json(resp_ok_with(serde_json::json!({
            "signData": B64.encode(&cms_der)
        }))),
        Err(code) => Json(resp_err(code)),
    }
}

pub fn router(store: Arc<CertStore>) -> Router {
    Router::new()
        .route("/SignData",    post(sign_data))
        .route("/SignMessage", post(sign_message))
        .with_state(store)
}
