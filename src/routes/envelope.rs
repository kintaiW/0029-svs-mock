/// envelopeEnc / envelopeDec（数字信封）路由
use axum::{extract::State, routing::post, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use der::Decode;
use serde::Deserialize;
use std::sync::Arc;
use x509_cert::Certificate;

use crate::cert_store::CertStore;
use crate::error::*;
use crate::proto::{Payload, Reply};
use crate::service::crypto_ops;

#[derive(Deserialize)]
struct EnvelopeEncReq {
    /// 加密证书唯一标识（subject base64 或 SN hex）
    #[serde(rename = "certID")]
    cert_id: String,
    /// 待加密数据 base64
    data: String,
}

#[derive(Deserialize)]
struct EnvelopeDecReq {
    /// 加密证书唯一标识，用于反查私钥
    #[serde(rename = "certID")]
    cert_id: String,
    /// 数字信封密文：base64(JSON{encryptedKey, encryptedData, iv})
    #[serde(rename = "envelopedData")]
    enveloped_data: String,
}

async fn envelope_enc(
    State(store): State<Arc<CertStore>>,
    Payload(req, wire): Payload<EnvelopeEncReq>,
) -> Reply {
    let cert_der = match store.find_cert(&req.cert_id) {
        Some(d) => d.clone(),
        None => return Reply(resp_err(ERR_CERT_ID), wire),
    };

    if req.data.is_empty() {
        return Reply(resp_err(ERR_PARAM), wire);
    }
    let data = match B64.decode(&req.data) {
        Ok(d) => d,
        Err(_) => return Reply(resp_err(ERR_PARAM), wire),
    };

    let cert = match Certificate::from_der(&cert_der) {
        Ok(c) => c,
        Err(_) => return Reply(resp_err(ERR_CERT_DECODE), wire),
    };
    let pub_point = cert.tbs_certificate.subject_public_key_info
        .subject_public_key.raw_bytes();

    match crypto_ops::envelope_enc(pub_point, &data) {
        Ok((enc_key, enc_data, iv)) => {
            // 三件套打包为 JSON 再 base64，供 Dec 端解包
            let inner = serde_json::json!({
                "encryptedKey":  B64.encode(&enc_key),
                "encryptedData": B64.encode(&enc_data),
                "iv":            B64.encode(&iv),
            });
            let enveloped = B64.encode(inner.to_string().as_bytes());
            Reply(resp_ok_with(serde_json::json!({ "envelopedData": enveloped })), wire)
        }
        Err(code) => Reply(resp_err(code), wire),
    }
}

async fn envelope_dec(
    State(store): State<Arc<CertStore>>,
    Payload(req, wire): Payload<EnvelopeDecReq>,
) -> Reply {
    // 按 certID 反查加密私钥
    let enc_key_cfg = match store.find_enc_key_by_cert_id(&req.cert_id) {
        Some(k) => k.clone(),
        None => return Reply(resp_err(ERR_CERT_ID), wire),
    };

    // 解包 envelopedData：base64 → JSON → 三字段
    let env_json_bytes = match B64.decode(&req.enveloped_data) {
        Ok(b) => b,
        Err(_) => return Reply(resp_err(ERR_PARAM), wire),
    };
    let env: serde_json::Value = match serde_json::from_slice(&env_json_bytes) {
        Ok(v) => v,
        Err(_) => return Reply(resp_err(ERR_DATA_FORMAT), wire),
    };

    let get_b64 = |key: &str| -> Option<Vec<u8>> {
        env.get(key)?.as_str().and_then(|s| B64.decode(s).ok())
    };
    let encrypted_key  = match get_b64("encryptedKey")  { Some(v) => v, None => return Reply(resp_err(ERR_DATA_FORMAT), wire) };
    let encrypted_data = match get_b64("encryptedData") { Some(v) => v, None => return Reply(resp_err(ERR_DATA_FORMAT), wire) };
    let iv             = match get_b64("iv")             { Some(v) => v, None => return Reply(resp_err(ERR_DATA_FORMAT), wire) };

    match crypto_ops::envelope_dec(&enc_key_cfg.private_key, &encrypted_key, &encrypted_data, &iv) {
        Ok(plain) => Reply(resp_ok_with(serde_json::json!({ "data": B64.encode(&plain) })), wire),
        Err(code) => Reply(resp_err(code), wire),
    }
}

pub fn router(store: Arc<CertStore>) -> Router {
    Router::new()
        .route("/envelopeEnc", post(envelope_enc))
        .route("/envelopeDec", post(envelope_dec))
        .with_state(store)
}
