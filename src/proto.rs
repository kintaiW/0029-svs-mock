//! 双协议协商：根据 Content-Type 自动选择 JSON / form-urlencoded。
//! 默认走 JSON；检测到 application/x-www-form-urlencoded 时走 form。
use axum::{
    async_trait,
    body::Body,
    extract::{Form, FromRequest, Json, Request},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use serde_json::Value;

#[derive(Clone, Copy)]
pub enum Wire {
    Json,
    Form,
}

impl Wire {
    /// 从请求头检测协议类型
    pub fn detect(headers: &axum::http::HeaderMap) -> Self {
        let is_form = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("application/x-www-form-urlencoded"))
            .unwrap_or(false);
        if is_form { Wire::Form } else { Wire::Json }
    }
}

/// 双协议请求 extractor：自动按 Content-Type 选择 JSON 或 form 反序列化
pub struct Payload<T>(pub T, pub Wire);

#[async_trait]
impl<T, S> FromRequest<S> for Payload<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let wire = Wire::detect(req.headers());
        match wire {
            Wire::Form => {
                // Reason: resty (Go HTTP client) double-encodes form values — it calls url.Values.Encode()
                // on values already pre-encoded by urlEncodeB64 (%3D → %253D). We undo the extra layer
                // by replacing %25 → % before serde_urlencoded's own URL-decode pass.
                use axum::body::to_bytes;
                let (parts, body) = req.into_parts();
                let bytes = to_bytes(body, usize::MAX).await
                    .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
                let raw = std::str::from_utf8(&bytes)
                    .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
                let undoubled = raw.replace("%25", "%");
                let data: T = serde_urlencoded::from_str(&undoubled)
                    .map_err(|e| {
                        let msg = format!("Failed to deserialize form body: {}", e);
                        (StatusCode::UNPROCESSABLE_ENTITY, msg).into_response()
                    })?;
                let _ = parts;
                Ok(Payload(data, Wire::Form))
            }
            Wire::Json => {
                let Json(data) = Json::<T>::from_request(req, state)
                    .await
                    .map_err(|e| e.into_response())?;
                Ok(Payload(data, Wire::Json))
            }
        }
    }
}

/// 双协议响应：按请求时的 Wire 决定响应格式
pub struct Reply(pub Value, pub Wire);

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        match self.1 {
            Wire::Json => axum::Json(self.0).into_response(),
            Wire::Form => {
                let body = json_to_urlencoded(&self.0);
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
        }
    }
}

/// 把扁平 JSON 对象序列化为 URL 编码字符串（key=value&...）
fn json_to_urlencoded(v: &Value) -> String {
    let Value::Object(map) = v else { return String::new(); };
    let pairs: Vec<(String, String)> = map
        .iter()
        .map(|(k, v)| {
            let val = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                other => other.to_string(),
            };
            (k.clone(), val)
        })
        .collect();
    serde_urlencoded::to_string(&pairs).unwrap_or_default()
}
