/// envelopeEnc / envelopeDec（数字信封）路由
use axum::{extract::State, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use der::Decode;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use x509_cert::Certificate;

use crate::cert_store::CertStore;
use crate::error::*;
use crate::service::crypto_ops;

#[derive(Deserialize)]
struct EnvelopeEncReq {
    /// 加密证书唯一标识（subject base64 或 SN hex）
    #[serde(rename = "certID")]
    cert_id: String,
    /// 待加密数据 base64
    #[serde(rename = "inData")]
    in_data: String,
}

#[derive(Deserialize)]
struct EnvelopeDecReq {
    /// 加密密钥索引
    #[serde(rename = "keyIndex")]
    key_index: u32,
    /// 数字信封密文（分字段传输，与真实设备一致）
    #[serde(rename = "encryptedKey")]
    encrypted_key: String,       // SM2 加密后的 SM4 密钥 base64
    #[serde(rename = "encryptedData")]
    encrypted_data: String,      // SM4-CBC 加密后的密文 base64
    #[serde(rename = "iv")]
    iv: String,                  // SM4-CBC IV base64
}

async fn envelope_enc(
    State(store): State<Arc<CertStore>>,
    Json(req): Json<EnvelopeEncReq>,
) -> Json<Value> {
    // 查找加密证书
    let cert_der = match store.find_cert(&req.cert_id) {
        Some(d) => d.clone(),
        None => return Json(resp_err(ERR_CERT_ID)),
    };

    let data = match B64.decode(&req.in_data) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_PARAM)),
    };

    // 提取证书公钥
    let cert = match Certificate::from_der(&cert_der) {
        Ok(c) => c,
        Err(_) => return Json(resp_err(ERR_CERT_DECODE)),
    };
    let pub_point = cert.tbs_certificate.subject_public_key_info
        .subject_public_key.raw_bytes();

    match crypto_ops::envelope_enc(pub_point, &data) {
        Ok((enc_key, enc_data, iv)) => Json(resp_ok_with(serde_json::json!({
            "encryptedKey":  B64.encode(&enc_key),
            "encryptedData": B64.encode(&enc_data),
            "iv":            B64.encode(&iv),
        }))),
        Err(code) => Json(resp_err(code)),
    }
}

async fn envelope_dec(
    State(store): State<Arc<CertStore>>,
    Json(req): Json<EnvelopeDecReq>,
) -> Json<Value> {
    // 查找加密密钥
    let enc_key_cfg = match store.enc_keys.get(&req.key_index) {
        Some(k) => k,
        None => return Json(resp_err(ERR_KEY_INDEX)),
    };

    let encrypted_key = match B64.decode(&req.encrypted_key) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_PARAM)),
    };
    let encrypted_data = match B64.decode(&req.encrypted_data) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_PARAM)),
    };
    let iv = match B64.decode(&req.iv) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_PARAM)),
    };

    match crypto_ops::envelope_dec(&enc_key_cfg.private_key, &encrypted_key, &encrypted_data, &iv) {
        Ok(plain) => Json(resp_ok_with(serde_json::json!({
            "outData": B64.encode(&plain)
        }))),
        Err(code) => Json(resp_err(code)),
    }
}

pub fn router(store: Arc<CertStore>) -> Router {
    Router::new()
        .route("/envelopeEnc", post(envelope_enc))
        .route("/envelopeDec", post(envelope_dec))
        .with_state(store)
}
