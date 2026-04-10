/// ExportCert / ValidateCert / ParseCert 路由
use axum::{extract::State, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

use crate::cert_store::CertStore;
use crate::error::*;
use crate::service::cert_ops;

#[derive(Deserialize)]
struct ExportCertReq {
    /// 证书唯一标识（subject base64 或 SN hex）
    #[serde(rename = "certID")]
    cert_id: String,
}

#[derive(Deserialize)]
struct ValidateCertReq {
    /// 待验证证书 DER base64
    #[serde(rename = "certContent")]
    cert_content: String,
    /// 忽略 ocsp/crl 相关字段，仅检查有效期和信任锚
    #[serde(rename = "verifyLevel", default)]
    _verify_level: Option<u32>,
}

#[derive(Deserialize)]
struct ParseCertReq {
    /// 证书 DER base64
    #[serde(rename = "certContent")]
    cert_content: String,
    /// 解析类型（见规范 infoType 常量）
    #[serde(rename = "infoType")]
    info_type: u32,
}

async fn export_cert(
    State(store): State<Arc<CertStore>>,
    Json(req): Json<ExportCertReq>,
) -> Json<Value> {
    match store.find_cert(&req.cert_id) {
        Some(der) => Json(resp_ok_with(serde_json::json!({
            "certContent": B64.encode(der)
        }))),
        None => Json(resp_err(ERR_CERT_INVALID)),
    }
}

async fn validate_cert(
    State(store): State<Arc<CertStore>>,
    Json(req): Json<ValidateCertReq>,
) -> Json<Value> {
    let der = match B64.decode(&req.cert_content) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_CERT_DECODE)),
    };
    let code = cert_ops::validate_cert(&der, &store);
    if code == GM_SUCCESS {
        // state=1 表示证书有效（与真实设备一致）
        Json(resp_ok_with(serde_json::json!({ "state": 1 })))
    } else {
        Json(resp_err(code))
    }
}

async fn parse_cert(
    State(_store): State<Arc<CertStore>>,
    Json(req): Json<ParseCertReq>,
) -> Json<Value> {
    let der = match B64.decode(&req.cert_content) {
        Ok(d) => d,
        Err(_) => return Json(resp_err(ERR_CERT_DECODE)),
    };
    match cert_ops::parse_cert(&der, req.info_type) {
        Ok(mut data) => {
            data["respValue"] = serde_json::json!(GM_SUCCESS);
            Json(data)
        }
        Err(code) => Json(resp_err(code)),
    }
}

pub fn router(store: Arc<CertStore>) -> Router {
    Router::new()
        .route("/ExportCert",   post(export_cert))
        .route("/ValidateCert", post(validate_cert))
        .route("/ParseCert",    post(parse_cert))
        .with_state(store)
}
