/// VerifySignedData / VerifySignedMessage 路由
use axum::{extract::State, routing::post, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use der::Decode;
use serde::Deserialize;
use std::sync::Arc;
use x509_cert::Certificate;

use crate::cert_store::CertStore;
use crate::error::*;
use crate::proto::{Payload, Reply};
use crate::service::{cert_ops, cms_ops, crypto_ops};

#[derive(Deserialize)]
struct VerifySignedDataReq {
    /// 证书定位方式：1=直接传 cert，2=传 certSN（hex）
    #[serde(rename = "type", default)]
    verify_type: Option<u32>,
    /// 签名者证书 DER base64（verify_type=1 或缺省时使用）
    #[serde(default)]
    cert: Option<String>,
    /// 证书序列号 hex（verify_type=2 时使用）
    #[serde(rename = "certSN", default)]
    cert_sn: Option<String>,
    /// 原始数据 base64
    #[serde(rename = "inData")]
    in_data: String,
    #[serde(rename = "inDataLen", default)]
    _in_data_len: Option<u32>,
    /// SM2 DER 格式签名 base64
    signature: String,
    /// 是否验证证书有效性（0=不验，1=验）
    #[serde(rename = "verifyLevel", default)]
    verify_level: u32,
}

#[derive(Deserialize)]
struct VerifySignedMessageReq {
    /// CMS SignedData DER base64
    #[serde(rename = "signedMessage")]
    signed_message: String,
    /// 分离签名时的原文 base64（可选，detached 模式必须传入）
    #[serde(rename = "inData", default)]
    in_data: Option<String>,
    #[serde(rename = "inDataLen", default)]
    _in_data_len: Option<u32>,
    // 以下布尔标志读后忽略
    #[serde(rename = "hashFlag", default)]
    _hash_flag: Option<String>,
    #[serde(rename = "originalText", default)]
    _original_text: Option<String>,
    #[serde(rename = "certificateChain", default)]
    _cert_chain: Option<String>,
    #[serde(rename = "crl", default)]
    _crl: Option<String>,
    #[serde(rename = "authenticationAttributes", default)]
    _auth_attrs: Option<String>,
}

async fn verify_signed_data(
    State(store): State<Arc<CertStore>>,
    Payload(req, wire): Payload<VerifySignedDataReq>,
) -> Reply {
    // 按 verify_type 确定证书 DER
    let cert_der = match req.verify_type.unwrap_or(1) {
        2 => {
            // 用 certSN hex 查库
            let sn = match &req.cert_sn {
                Some(s) => s,
                None => return Reply(resp_err(ERR_PARAM), wire),
            };
            match store.find_cert(sn) {
                Some(d) => d.clone(),
                None => return Reply(resp_err(ERR_CERT_INVALID), wire),
            }
        }
        _ => {
            // 直接解码传入的 cert 字段
            let b64 = match &req.cert {
                Some(s) => s,
                None => return Reply(resp_err(ERR_PARAM), wire),
            };
            match B64.decode(b64) {
                Ok(d) => d,
                Err(_) => return Reply(resp_err(ERR_CERT_DECODE), wire),
            }
        }
    };

    let data = match B64.decode(&req.in_data) {
        Ok(d) => d,
        Err(_) => return Reply(resp_err(ERR_PARAM), wire),
    };
    let sig = match B64.decode(&req.signature) {
        Ok(d) => d,
        Err(_) => return Reply(resp_err(ERR_PARAM), wire),
    };

    let cert = match Certificate::from_der(&cert_der) {
        Ok(c) => c,
        Err(_) => return Reply(resp_err(ERR_CERT_DECODE), wire),
    };
    let pub_point = cert.tbs_certificate.subject_public_key_info
        .subject_public_key.raw_bytes();

    if let Err(code) = crypto_ops::sm2_verify(pub_point, &data, &sig) {
        return Reply(resp_err(code), wire);
    }

    if req.verify_level >= 1 {
        let code = cert_ops::validate_cert(&cert_der, &store);
        if code != GM_SUCCESS {
            return Reply(resp_err(code), wire);
        }
    }

    Reply(resp_ok(), wire)
}

async fn verify_signed_message(
    State(store): State<Arc<CertStore>>,
    Payload(req, wire): Payload<VerifySignedMessageReq>,
) -> Reply {
    let cms_der = match B64.decode(&req.signed_message) {
        Ok(d) => d,
        Err(_) => return Reply(resp_err(ERR_PARAM), wire),
    };

    // 解码 inData（分离签名时需要）
    let in_data_bytes = match &req.in_data {
        Some(s) if !s.is_empty() => match B64.decode(s) {
            Ok(d) => Some(d),
            Err(_) => return Reply(resp_err(ERR_PARAM), wire),
        },
        _ => None,
    };

    let all_certs = store.all_cert_ders();
    let fallback: Vec<&[u8]> = all_certs.iter().map(|v| v.as_slice()).collect();
    match cms_ops::verify_signed_message(&cms_der, in_data_bytes.as_deref(), &fallback) {
        Ok((_content, signer_cert_der)) => {
            let code = cert_ops::validate_cert(&signer_cert_der, &store);
            if code != GM_SUCCESS {
                return Reply(resp_err(code), wire);
            }
            Reply(resp_ok(), wire)
        }
        Err(code) => Reply(resp_err(code), wire),
    }
}

pub fn router(store: Arc<CertStore>) -> Router {
    Router::new()
        .route("/VerifySignedData",    post(verify_signed_data))
        .route("/VerifySignedMessage", post(verify_signed_message))
        .with_state(store)
}
