/// SVS MCP Server — GM/T 0029-2014 工具集（MCP Streamable HTTP 传输）
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use der::Decode;
use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
};
use std::sync::Arc;
use x509_cert::Certificate;

use crate::cert_store::CertStore;
use crate::service::{cert_ops, cms_ops, crypto_ops};

// ── 参数结构 ─────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DigestParams {
    #[schemars(description = "待摘要的原始数据，hex 编码（如 \"48656c6c6f\"）")]
    pub data_hex: String,
    #[schemars(
        description = "可选。SM2 公钥点 04||x||y（65字节）的 hex 编码。\
                       提供后将先计算 Z 值前缀再摘要，用于 SM2 签名验签的消息预处理。"
    )]
    pub public_key_hex: Option<String>,
    #[schemars(
        description = "可选。SM2 用户 ID 的 hex 编码。\
                       未提供时使用 GM/T 0009 默认值 31323334353637383132333435363738。"
    )]
    pub user_id_hex: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SignParams {
    #[schemars(
        description = "签名模式：\"data\"（P1 格式 DER 签名）或 \"message\"（CMS SignedData）"
    )]
    pub mode: String,
    #[schemars(description = "待签名数据，hex 编码")]
    pub data_hex: String,
    #[schemars(
        description = "签名私钥索引（u32），对应 mock_certs.toml 中的 signing_keys[n].index。默认 0。"
    )]
    pub key_index: Option<u32>,
    #[schemars(
        description = "仅 mode=\"message\" 有效。是否附原文（false=分离签名，true=附原文）。默认 false。"
    )]
    pub include_content: Option<bool>,
    #[schemars(
        description = "仅 mode=\"message\" 有效。是否在 CMS 中附签名者证书链。默认 true。"
    )]
    pub include_cert: Option<bool>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct VerifyParams {
    #[schemars(description = "验签模式：\"data\"（P1 签名）或 \"message\"（CMS SignedData）")]
    pub mode: String,
    #[schemars(description = "原始数据，hex 编码")]
    pub data_hex: String,
    #[schemars(description = "待验证的签名数据，hex 编码（P1 DER 或 CMS DER）")]
    pub signed_data_hex: String,
    #[schemars(
        description = "仅 mode=\"data\" 需要。签名者 SM2 公钥点 04||x||y（65字节）的 hex 编码。\
                       或者用 signer_cert_id 替代。"
    )]
    pub signer_pub_key_hex: Option<String>,
    #[schemars(
        description = "仅 mode=\"data\" 需要（与 signer_pub_key_hex 二选一）。\
                       签名者证书 ID（subject base64 或 SN hex），用于从 mock store 取公钥。"
    )]
    pub signer_cert_id: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct EnvelopeEncParams {
    #[schemars(description = "待加密明文，hex 编码")]
    pub plaintext_hex: String,
    #[schemars(
        description = "接收方加密证书标识（subject base64 或 SN hex）。\
                       可通过 svs_cert action=export 获取，再 parse 读出 certID。"
    )]
    pub cert_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct EnvelopeDecParams {
    #[schemars(
        description = "加密证书 ID（subject base64 或 SN hex），用于定位解密私钥。\
                       与加密时使用的 cert_id 对应。"
    )]
    pub cert_id: String,
    #[schemars(
        description = "svs_envelope_enc 返回的信封 JSON（{enc_key_hex, enc_data_hex, iv_hex}）\
                       再整体 hex 编码后的字符串"
    )]
    pub envelope_hex: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CertParams {
    #[schemars(
        description = "操作类型：\"export\"（按 cert_id 导出证书 DER）、\
                       \"validate\"（验证证书链有效性）、\"parse\"（解析证书字段）"
    )]
    pub action: String,
    #[schemars(
        description = "export 时：cert_id（subject base64 或 SN hex）；\
                       validate/parse 时：证书 DER 的 hex 编码"
    )]
    pub cert_data: String,
    #[schemars(
        description = "仅 parse 需要。解析字段类型（u32）：\
                       1=版本号, 2=序列号, 5=颁发者 DN, 6=有效期(起止), 7=主题 DN, \
                       8=公钥 SPKI DER, 0x31=主题 CN 字符串, 0x35=起始时间, 0x36=终止时间"
    )]
    pub info_type: Option<u32>,
}

// ── MCP Server ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SvsMcpServer {
    tool_router: ToolRouter<Self>,
    store: Arc<CertStore>,
}

impl SvsMcpServer {
    pub fn new(store: Arc<CertStore>) -> Self {
        Self {
            tool_router: Self::tool_router(),
            store,
        }
    }
}

#[tool_router]
impl SvsMcpServer {
    #[tool(
        description = "计算 SM3 摘要（GM/T 0004-2012）。\
                       无 public_key_hex 时为普通摘要；\
                       提供 public_key_hex 时先计算 Z=SM3(entlen||uid||曲线参数||公钥) 再做 SM3(Z||data)，\
                       用于 SM2 签名验签消息预处理。\
                       返回 JSON：{\"hex\":\"...\",\"base64\":\"...\",\"length\":32}"
    )]
    async fn svs_digest(&self, Parameters(p): Parameters<DigestParams>) -> String {
        let data = match hex::decode(&p.data_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("data_hex 解码失败: {e}")),
        };
        let pk = decode_hex_opt(p.public_key_hex.as_deref(), "public_key_hex");
        let pk = match pk {
            Ok(v) => v,
            Err(e) => return err_json(&e),
        };
        let uid = decode_hex_opt(p.user_id_hex.as_deref(), "user_id_hex");
        let uid = match uid {
            Ok(v) => v,
            Err(e) => return err_json(&e),
        };
        match crypto_ops::sm3_digest(&data, pk.as_deref(), uid.as_deref()) {
            Ok(hash) => serde_json::json!({
                "hex": hex::encode(&hash),
                "base64": B64.encode(&hash),
                "length": hash.len()
            })
            .to_string(),
            Err(code) => err_json(&format!("密码运算失败，错误码: {code:#010x}")),
        }
    }

    #[tool(
        description = "SM2 签名（GM/T 0009-2012）。\
                       mode=\"data\"：P1 格式签名（DER SEQUENCE{r,s}）；\
                       mode=\"message\"：CMS SignedData 结构（附签名者证书）。\
                       返回 JSON：{\"signed_data_hex\":\"...\",\"mode\":\"...\"}"
    )]
    async fn svs_sign(&self, Parameters(p): Parameters<SignParams>) -> String {
        let data = match hex::decode(&p.data_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("data_hex 解码失败: {e}")),
        };
        let key_idx = p.key_index.unwrap_or(0);
        let key_cfg = match self.store.signing_keys.get(&key_idx) {
            Some(k) => k,
            None => {
                return err_json(&format!(
                    "key_index={key_idx} 不存在"
                ))
            }
        };
        match p.mode.as_str() {
            "data" => match crypto_ops::sm2_sign(&key_cfg.private_key, &data) {
                Ok(sig) => serde_json::json!({
                    "signed_data_hex": hex::encode(&sig),
                    "mode": "data"
                })
                .to_string(),
                Err(code) => err_json(&format!("签名失败，错误码: {code:#010x}")),
            },
            "message" => {
                let cert_der = match B64.decode(&key_cfg.cert) {
                    Ok(d) => d,
                    Err(e) => return err_json(&format!("证书 base64 解码失败: {e}")),
                };
                let detached = !p.include_content.unwrap_or(false);
                let include_cert = p.include_cert.unwrap_or(true);
                match cms_ops::sign_message(
                    &key_cfg.private_key,
                    &cert_der,
                    &data,
                    detached,
                    include_cert,
                ) {
                    Ok(cms) => serde_json::json!({
                        "signed_data_hex": hex::encode(&cms),
                        "mode": "message"
                    })
                    .to_string(),
                    Err(code) => err_json(&format!("CMS 签名失败，错误码: {code:#010x}")),
                }
            }
            _ => err_json("mode 必须为 \"data\" 或 \"message\""),
        }
    }

    #[tool(
        description = "SM2 验签（GM/T 0009-2012）。\
                       mode=\"data\"：验证 P1 格式签名，需提供 signer_pub_key_hex 或 signer_cert_id；\
                       mode=\"message\"：验证 CMS SignedData（含证书链验证），\
                                         data_hex 为分离签名的原文（附原文 CMS 可传空字符串）。\
                       返回 JSON：{\"valid\":true} 或 {\"error\":\"...\"}"
    )]
    async fn svs_verify(&self, Parameters(p): Parameters<VerifyParams>) -> String {
        let data = match hex::decode(&p.data_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("data_hex 解码失败: {e}")),
        };
        let signed = match hex::decode(&p.signed_data_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("signed_data_hex 解码失败: {e}")),
        };
        match p.mode.as_str() {
            "data" => {
                // 取公钥点：直接提供 hex 或通过 cert_id 从 store 取
                let pub_key_bytes = if let Some(pk_hex) = &p.signer_pub_key_hex {
                    match hex::decode(pk_hex) {
                        Ok(d) => d,
                        Err(e) => return err_json(&format!("signer_pub_key_hex 解码失败: {e}")),
                    }
                } else if let Some(cid) = &p.signer_cert_id {
                    match extract_pubkey_from_cert_id(&self.store, cid) {
                        Ok(pk) => pk.to_vec(),
                        Err(e) => return err_json(&e),
                    }
                } else {
                    return err_json("mode=\"data\" 需提供 signer_pub_key_hex 或 signer_cert_id");
                };
                match crypto_ops::sm2_verify(&pub_key_bytes, &data, &signed) {
                    Ok(_) => serde_json::json!({ "valid": true }).to_string(),
                    Err(code) => err_json(&format!("验签失败，错误码: {code:#010x}")),
                }
            }
            "message" => {
                let fallback: Vec<&[u8]> = self.store.all_cert_ders().into_iter().map(|v| v.as_slice()).collect();
                let content_opt = if data.is_empty() { None } else { Some(data.as_slice()) };
                match cms_ops::verify_signed_message(&signed, content_opt, &fallback) {
                    Ok(_) => serde_json::json!({ "valid": true }).to_string(),
                    Err(code) => err_json(&format!("CMS 验签失败，错误码: {code:#010x}")),
                }
            }
            _ => err_json("mode 必须为 \"data\" 或 \"message\""),
        }
    }

    #[tool(
        description = "数字信封加密（GM/T 0010-2012）。\
                       使用 cert_id 对应的 SM2 加密公钥生成数字信封（SM2 加密 SM4 密钥，SM4-CBC 加密明文）。\
                       返回 JSON：{\"enc_key_hex\":\"...\",\"enc_data_hex\":\"...\",\"iv_hex\":\"...\",\"cert_id\":\"...\"}，\
                       将整个返回 JSON 字符串 hex 编码后作为 svs_envelope_dec 的 envelope_hex 参数。"
    )]
    async fn svs_envelope_enc(&self, Parameters(p): Parameters<EnvelopeEncParams>) -> String {
        let plaintext = match hex::decode(&p.plaintext_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("plaintext_hex 解码失败: {e}")),
        };
        let cert_der = match self.store.find_cert(&p.cert_id) {
            Some(d) => d.clone(),
            None => return err_json(&format!("cert_id \"{}\" 未找到", p.cert_id)),
        };
        let pub_point = match extract_pubkey_point(&cert_der) {
            Ok(pk) => pk,
            Err(e) => return err_json(&e),
        };
        match crypto_ops::envelope_enc(&pub_point, &plaintext) {
            Ok((enc_key, enc_data, iv)) => {
                let result = serde_json::json!({
                    "enc_key_hex": hex::encode(&enc_key),
                    "enc_data_hex": hex::encode(&enc_data),
                    "iv_hex": hex::encode(&iv),
                    "cert_id": p.cert_id
                });
                // Reason: 将 JSON 整体 hex 编码，便于 LLM 直接传给 svs_envelope_dec
                hex::encode(result.to_string().as_bytes())
            }
            Err(code) => err_json(&format!("信封加密失败，错误码: {code:#010x}")),
        }
    }

    #[tool(
        description = "数字信封解密（GM/T 0010-2012）。\
                       envelope_hex 为 svs_envelope_enc 的返回值（JSON 字符串的 hex 编码）。\
                       cert_id 为加密时使用的证书 ID，用于定位解密私钥。\
                       返回 JSON：{\"plaintext_hex\":\"...\"}"
    )]
    async fn svs_envelope_dec(&self, Parameters(p): Parameters<EnvelopeDecParams>) -> String {
        let json_bytes = match hex::decode(&p.envelope_hex) {
            Ok(d) => d,
            Err(e) => return err_json(&format!("envelope_hex 解码失败: {e}")),
        };
        let envelope: serde_json::Value = match serde_json::from_slice(&json_bytes) {
            Ok(v) => v,
            Err(e) => return err_json(&format!("信封 JSON 解析失败: {e}")),
        };
        let get_hex = |key: &str| -> Result<Vec<u8>, String> {
            let s = envelope[key].as_str().ok_or_else(|| format!("缺少字段 {key}"))?;
            hex::decode(s).map_err(|e| format!("{key} hex 解码失败: {e}"))
        };
        let enc_key = match get_hex("enc_key_hex") { Ok(v) => v, Err(e) => return err_json(&e) };
        let enc_data = match get_hex("enc_data_hex") { Ok(v) => v, Err(e) => return err_json(&e) };
        let iv = match get_hex("iv_hex") { Ok(v) => v, Err(e) => return err_json(&e) };

        let enc_key_cfg = match self.store.find_enc_key_by_cert_id(&p.cert_id) {
            Some(k) => k.clone(),
            None => return err_json(&format!("cert_id \"{}\" 未找到对应解密私钥", p.cert_id)),
        };
        match crypto_ops::envelope_dec(&enc_key_cfg.private_key, &enc_key, &enc_data, &iv) {
            Ok(plain) => serde_json::json!({
                "plaintext_hex": hex::encode(&plain)
            })
            .to_string(),
            Err(code) => err_json(&format!("信封解密失败，错误码: {code:#010x}")),
        }
    }

    #[tool(
        description = "证书操作工具（GM/T 0029-2014 证书管理接口）。\
                       action=\"export\"：cert_data 填 cert_id，返回证书 DER（hex+base64）；\
                       action=\"validate\"：cert_data 填证书 DER hex，验证有效期和信任链，返回 {valid:true/false}；\
                       action=\"parse\"：cert_data 填证书 DER hex，info_type 指定字段，返回对应字段值。\
                       info_type 常用值：2=序列号, 6=有效期(起止), 7=主题 DN, 8=公钥 SPKI, 0x31=主题 CN。"
    )]
    async fn svs_cert(&self, Parameters(p): Parameters<CertParams>) -> String {
        match p.action.as_str() {
            "export" => match self.store.find_cert(&p.cert_data) {
                Some(der) => serde_json::json!({
                    "cert_der_hex": hex::encode(der),
                    "cert_der_base64": B64.encode(der)
                })
                .to_string(),
                None => err_json(&format!("cert_id \"{}\" 未找到", p.cert_data)),
            },
            "validate" => {
                let der = match hex::decode(&p.cert_data) {
                    Ok(d) => d,
                    Err(e) => return err_json(&format!("cert_data hex 解码失败: {e}")),
                };
                let code = cert_ops::validate_cert(&der, &self.store);
                if code == 0 {
                    serde_json::json!({ "valid": true }).to_string()
                } else {
                    err_json(&format!("证书验证失败，错误码: {code:#010x}"))
                }
            }
            "parse" => {
                let der = match hex::decode(&p.cert_data) {
                    Ok(d) => d,
                    Err(e) => return err_json(&format!("cert_data hex 解码失败: {e}")),
                };
                let info_type = p.info_type.unwrap_or(6); // 默认返回有效期
                match cert_ops::parse_cert(&der, info_type) {
                    Ok(val) => val.to_string(),
                    Err(code) => err_json(&format!("证书解析失败，错误码: {code:#010x}")),
                }
            }
            _ => err_json("action 必须为 \"export\"、\"validate\" 或 \"parse\""),
        }
    }
}

#[tool_handler]
impl ServerHandler for SvsMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "SVS Mock MCP Server — 提供符合 GM/T 0029-2014 的签名验签服务能力。\
                 支持 SM2 签名/验签、SM3 摘要（含 Z 值前缀）、数字信封（SM2+SM4）、证书管理。\
                 所有输入输出均使用 hex 编码字符串，结果以 JSON 返回。\
                 仅供学习和开发测试使用，严禁用于生产环境。",
            )
    }
}

// ── 辅助函数 ─────────────────────────────────────────────────────────────────

fn err_json(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

fn decode_hex_opt(s: Option<&str>, field: &str) -> Result<Option<Vec<u8>>, String> {
    match s {
        Some(h) => hex::decode(h)
            .map(Some)
            .map_err(|e| format!("{field} 解码失败: {e}")),
        None => Ok(None),
    }
}

/// 从证书 DER 提取 SM2 公钥点（04||x||y，65字节）
fn extract_pubkey_point(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| format!("证书 DER 解析失败: {e}"))?;
    let point = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    Ok(point.to_vec())
}

/// 按 cert_id 从 store 找证书并提取公钥点
fn extract_pubkey_from_cert_id(store: &CertStore, cert_id: &str) -> Result<Vec<u8>, String> {
    let cert_der = store
        .find_cert(cert_id)
        .ok_or_else(|| format!("cert_id \"{cert_id}\" 未找到"))?;
    extract_pubkey_point(cert_der)
}
