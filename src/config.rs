use serde::Deserialize;
use std::env;
use std::fs;

/// 服务器配置
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

/// 可信根证书配置项
#[derive(Debug, Deserialize, Clone)]
pub struct TrustedRoot {
    pub name: String,
    /// DER base64 编码的证书
    pub cert: String,
}

/// 签名密钥配置项
#[derive(Debug, Deserialize, Clone)]
pub struct SigningKey {
    pub index: u32,
    pub pin: String,
    /// 32字节私钥 hex
    pub private_key: String,
    /// 对应签名证书 DER base64
    pub cert: String,
}

/// 加密密钥配置项
#[derive(Debug, Deserialize, Clone)]
pub struct EncKey {
    pub index: u32,
    /// 32字节私钥 hex
    pub private_key: String,
    /// 对应加密证书 DER base64
    pub cert: String,
}

/// 完整配置文件结构
#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub trusted_roots: Vec<TrustedRoot>,
    #[serde(default)]
    pub signing_keys: Vec<SigningKey>,
    #[serde(default)]
    pub enc_keys: Vec<EncKey>,
}

impl AppConfig {
    /// 加载配置文件。
    /// 查找优先级：环境变量 SVS_MOCK_CONFIG → 当前工作目录 mock_certs.toml
    pub fn load() -> anyhow::Result<Self> {
        let path = if let Ok(p) = env::var("SVS_MOCK_CONFIG") {
            p
        } else {
            "mock_certs.toml".to_string()
        };

        let content = fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("无法读取配置文件 {}: {}", path, e))?;

        let config: AppConfig = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("解析配置文件失败: {}", e))?;

        Ok(config)
    }
}
