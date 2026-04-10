/// VerifySignedData / VerifySignedMessage 路由
use axum::{extract::State, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use der::Decode;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use x509_cert::Certificate;

use crate::cert_store::CertStore;
use crate::error::*;
use crate::service::{cert_ops, cms_ops, crypto_ops};

#[derive(Deserialize)]
struct VerifySignedDataReq {
    /// 签名者证书 DER base64（用于取公钥）
    #[serde(rename = "certContent")]
    cert_content: String,
    /// 原始数据 base64
    #[serde(rename = "inData")]
    in_data: String,
    /// SM2 DER 格式签名 base64
    #[serde(rename = "signData")]
    sign_data: String,
    /// 是否验证证书有效性（0=不验，1=验）
    #[serde(rename = "verifyFlag", default)]
    verify_flag: u32,
}

#[derive(Deserialize)]
struct VerifySignedMessageReq {
    /// CMS SignedData DER base64
    #[serde(rename = "signData")]
    sign_data: String,
    /// 分离签名时的原文 base64（可选）
    #[serde(rename = "inData", default)]
    in_data: Option<String>,
}

async fn verify_signed_data(
    State(store): State<Arc<CertStore>>,
    Json(req): Json<VerifySignedDataReq>,
) -> Json<Value> {
    let cert_der = match B64.decode(&req.cert_content) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_CERT_DECODE)),
    };
    let data = match B64.decode(&req.in_data) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_PARAM)),
    };
    let sig = match B64.decode(&req.sign_data) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_PARAM)),
    };

    // 提取公钥
    let cert = match Certificate::from_der(&cert_der) {
        Ok(c) => c,
        Err(_) => return Json(resp_err(ERR_CERT_DECODE)),
    };
    let pub_point = cert.tbs_certificate.subject_public_key_info
        .subject_public_key.raw_bytes();

    // 验证签名
    if let Err(code) = crypto_ops::sm2_verify(pub_point, &data, &sig) {
        return Json(resp_err(code));
    }

    // 可选证书有效性验证
    if req.verify_flag == 1 {
        let code = cert_ops::validate_cert(&cert_der, &store);
        if code != GM_SUCCESS {
            return Json(resp_err(code));
        }
    }

    Json(resp_ok())
}

async fn verify_signed_message(
    State(store): State<Arc<CertStore>>,
    Json(req): Json<VerifySignedMessageReq>,
) -> Json<Value> {
    let cms_der = match B64.decode(&req.sign_data) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_PARAM)),
    };

    match cms_ops::verify_signed_message(&cms_der) {
        Ok((content, signer_cert_der)) => {
            // 验证签名者证书有效性
            let code = cert_ops::validate_cert(&signer_cert_der, &store);
            if code != GM_SUCCESS {
                return Json(resp_err(code));
            }
            // 返回原文和签名者证书
            Json(resp_ok_with(serde_json::json!({
                "outData":  B64.encode(&content),
                "certContent": B64.encode(&signer_cert_der),
            })))
        }
        Err(code) => Json(resp_err(code)),
    }
}

pub fn router(store: Arc<CertStore>) -> Router {
    Router::new()
        .route("/VerifySignedData",    post(verify_signed_data))
        .route("/VerifySignedMessage", post(verify_signed_message))
        .with_state(store)
}
