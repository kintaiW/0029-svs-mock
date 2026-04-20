/// SignData / SignMessage 路由
use axum::{extract::State, routing::post, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use std::sync::Arc;

use crate::cert_store::CertStore;
use crate::error::*;
use crate::proto::{Payload, Reply};
use crate::service::{cms_ops, crypto_ops};

const SGD_SM3_SM2: u32 = 0x00020201;

#[derive(Deserialize)]
struct SignDataReq {
    #[serde(rename = "keyIndex")]
    key_index: u32,
    /// PIN 码
    #[serde(rename = "keyValue")]
    key_value: String,
    /// 签名算法标识（允许缺省，默认为 SM3withSM2）
    #[serde(rename = "signMethod", default)]
    sign_method: Option<u32>,
    /// 待签名数据 base64
    #[serde(rename = "inData")]
    in_data: String,
    #[serde(rename = "inDataLen", default)]
    in_data_len: Option<u32>,
}

#[derive(Deserialize)]
struct SignMessageReq {
    #[serde(rename = "keyIndex")]
    key_index: u32,
    #[serde(rename = "keyValue")]
    key_value: String,
    #[serde(rename = "inData")]
    in_data: String,
    #[serde(rename = "inDataLen", default)]
    _in_data_len: Option<u32>,
    #[serde(rename = "signMethod", default)]
    _sign_method: Option<u32>,
    /// originalText=TRUE 表示附原文（不分离），FALSE 表示分离签名
    #[serde(rename = "originalText", default)]
    original_text: Option<String>,
    /// certificateChain=TRUE 表示附证书
    #[serde(rename = "certificateChain", default)]
    certificate_chain: Option<String>,
    // 以下字段读后忽略
    #[serde(rename = "hashFlag", default)]
    _hash_flag: Option<String>,
    #[serde(rename = "crl", default)]
    _crl: Option<String>,
    #[serde(rename = "authenticationAttributes", default)]
    _auth_attrs: Option<String>,
}

async fn sign_data(
    State(store): State<Arc<CertStore>>,
    Payload(req, wire): Payload<SignDataReq>,
) -> Reply {
    if let Some(alg) = req.sign_method {
        if alg != SGD_SM3_SM2 {
            return Reply(resp_err(ERR_ALG_ID), wire);
        }
    }

    let key_cfg = match store.signing_keys.get(&req.key_index) {
        Some(k) => k,
        None => return Reply(resp_err(ERR_KEY_INDEX), wire),
    };
    if key_cfg.pin != req.key_value {
        return Reply(resp_err(ERR_KEY_AUTH), wire);
    }

    if req.in_data.is_empty() {
        return Reply(resp_err(ERR_PARAM), wire);
    }
    let data = match B64.decode(&req.in_data) {
        Ok(d) => d,
        Err(_) => return Reply(resp_err(ERR_PARAM), wire),
    };

    // Validate inDataLen when caller provides it (0 = not provided / skip check)
    if let Some(len) = req.in_data_len {
        if len > 0 && len as usize != data.len() {
            return Reply(resp_err(ERR_PARAM), wire);
        }
    }

    match crypto_ops::sm2_sign(&key_cfg.private_key, &data) {
        Ok(sig) => Reply(resp_ok_with(serde_json::json!({
            "signature": B64.encode(&sig)
        })), wire),
        Err(code) => Reply(resp_err(code), wire),
    }
}

async fn sign_message(
    State(store): State<Arc<CertStore>>,
    Payload(req, wire): Payload<SignMessageReq>,
) -> Reply {
    let key_cfg = match store.signing_keys.get(&req.key_index) {
        Some(k) => k,
        None => return Reply(resp_err(ERR_KEY_INDEX), wire),
    };
    if key_cfg.pin != req.key_value {
        return Reply(resp_err(ERR_KEY_AUTH), wire);
    }

    let data = match B64.decode(&req.in_data) {
        Ok(d) => d,
        Err(_) => return Reply(resp_err(ERR_PARAM), wire),
    };

    let cert_der = match B64.decode(&key_cfg.cert) {
        Ok(d) => d,
        Err(_) => return Reply(resp_err(ERR_CERT_DECODE), wire),
    };

    // originalText=TRUE → 附原文（非分离签名）；缺省/FALSE → 分离签名
    let detached = req.original_text.as_deref() != Some("TRUE");
    // certificateChain=TRUE → 附证书
    let include_cert = req.certificate_chain.as_deref() == Some("TRUE");

    match cms_ops::sign_message(&key_cfg.private_key, &cert_der, &data, detached, include_cert) {
        Ok(cms_der) => Reply(resp_ok_with(serde_json::json!({
            "signedMessage": B64.encode(&cms_der)
        })), wire),
        Err(code) => Reply(resp_err(code), wire),
    }
}

pub fn router(store: Arc<CertStore>) -> Router {
    Router::new()
        .route("/SignData",    post(sign_data))
        .route("/SignMessage", post(sign_message))
        .with_state(store)
}
