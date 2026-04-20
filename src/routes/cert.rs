/// ExportCert / ValidateCert / ParseCert 路由
use axum::{extract::State, routing::post, Router};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

use crate::cert_store::CertStore;
use crate::error::*;
use crate::proto::{Payload, Reply};
use crate::service::cert_ops;

#[derive(Deserialize)]
struct ExportCertReq {
    /// 证书唯一标识（subject base64 或 SN hex）
    identification: String,
}

#[derive(Deserialize)]
struct ValidateCertReq {
    /// 待验证证书 DER base64
    cert: String,
    /// ocsp 字段（读后忽略，mock 不做 OCSP 校验）
    #[allow(dead_code)]
    ocsp: Option<String>,
}

#[derive(Deserialize)]
struct ParseCertReq {
    /// 证书 DER base64
    cert: String,
    /// 解析类型（见规范 infoType 常量）
    #[serde(rename = "infoType")]
    info_type: u32,
}

async fn export_cert(
    State(store): State<Arc<CertStore>>,
    Payload(req, wire): Payload<ExportCertReq>,
) -> Reply {
    match store.find_cert(&req.identification) {
        Some(der) => Reply(resp_ok_with(serde_json::json!({
            "cert": B64.encode(der)
        })), wire),
        None => Reply(resp_err(ERR_CERT_INVALID), wire),
    }
}

async fn validate_cert(
    State(store): State<Arc<CertStore>>,
    Payload(req, wire): Payload<ValidateCertReq>,
) -> Reply {
    let der = match B64.decode(&req.cert) {
        Ok(d) => d,
        Err(_) => return Reply(resp_err(ERR_CERT_DECODE), wire),
    };
    let code = cert_ops::validate_cert(&der, &store);
    if code == GM_SUCCESS {
        // state=0 表示证书正常（GM/T 0029 协议定义，0=正常/1=已吊销/2=未知）
        Reply(resp_ok_with(serde_json::json!({ "state": 0 })), wire)
    } else {
        Reply(resp_err(code), wire)
    }
}

async fn parse_cert(
    State(_store): State<Arc<CertStore>>,
    Payload(req, wire): Payload<ParseCertReq>,
) -> Reply {
    let der = match B64.decode(&req.cert) {
        Ok(d) => d,
        Err(_) => return Reply(resp_err(ERR_CERT_DECODE), wire),
    };
    match cert_ops::parse_cert(&der, req.info_type) {
        Ok(data) => {
            let info = extract_info(data);
            Reply(resp_ok_with(serde_json::json!({ "info": info })), wire)
        }
        Err(code) => Reply(resp_err(code), wire),
    }
}

/// 从 parse_cert 返回的动态 JSON 中提取主值字符串
fn extract_info(v: Value) -> String {
    let Value::Object(map) = v else { return String::new(); };
    // 大多数 infoType 返回 { "certInfo": "..." }
    if let Some(ci) = map.get("certInfo") {
        return match ci {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
    }
    // infoType=6 返回 { "notBefore": "...", "notAfter": "..." }，拼接输出
    map.values()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join("|")
}

pub fn router(store: Arc<CertStore>) -> Router {
    Router::new()
        .route("/ExportCert",   post(export_cert))
        .route("/ValidateCert", post(validate_cert))
        .route("/ParseCert",    post(parse_cert))
        .with_state(store)
}
