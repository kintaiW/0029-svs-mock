use crate::config::{AppConfig, EncKey, SigningKey, TrustedRoot};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use der::{Decode, Encode};
use std::collections::HashMap;

/// 内存证书/密钥仓库
/// 初始化时从 AppConfig 加载，运行时只读
pub struct CertStore {
    /// 可信根证书列表（DER bytes）
    pub trusted_roots: Vec<Vec<u8>>,
    /// subject DER base64 → 证书 DER bytes（用于 ExportCert 按 subject 查找）
    pub subject_index: HashMap<String, Vec<u8>>,
    /// 序列号 hex（小写） → 证书 DER bytes（用于 ExportCert 按 SN 查找）
    pub serial_index: HashMap<String, Vec<u8>>,
    /// keyIndex → 签名密钥配置
    pub signing_keys: HashMap<u32, SigningKey>,
    /// keyIndex → 加密密钥配置
    pub enc_keys: HashMap<u32, EncKey>,
}

impl CertStore {
    /// 从 AppConfig 构建 CertStore，解码所有 base64 证书
    pub fn from_config(config: &AppConfig) -> anyhow::Result<Self> {
        let mut store = CertStore {
            trusted_roots: Vec::new(),
            subject_index: HashMap::new(),
            serial_index: HashMap::new(),
            signing_keys: HashMap::new(),
            enc_keys: HashMap::new(),
        };

        // 加载可信根证书
        for root in &config.trusted_roots {
            let der = B64.decode(&root.cert)
                .map_err(|e| anyhow::anyhow!("根证书 {} base64 解码失败: {}", root.name, e))?;
            store.index_cert(&der)?;
            store.trusted_roots.push(der);
        }

        // 加载签名密钥及其证书
        for key in &config.signing_keys {
            let der = B64.decode(&key.cert)
                .map_err(|e| anyhow::anyhow!("签名密钥 {} 证书解码失败: {}", key.index, e))?;
            store.index_cert(&der)?;
            store.signing_keys.insert(key.index, key.clone());
        }

        // 加载加密密钥及其证书
        for key in &config.enc_keys {
            let der = B64.decode(&key.cert)
                .map_err(|e| anyhow::anyhow!("加密密钥 {} 证书解码失败: {}", key.index, e))?;
            store.index_cert(&der)?;
            store.enc_keys.insert(key.index, key.clone());
        }

        Ok(store)
    }

    /// 将证书的 subject 和 serial 建立索引
    fn index_cert(&mut self, der: &[u8]) -> anyhow::Result<()> {
        use der::Decode;
        use x509_cert::Certificate;

        let cert = Certificate::from_der(der)
            .map_err(|e| anyhow::anyhow!("证书 DER 解析失败: {}", e))?;

        // subject DER base64 → cert DER
        let subject_der = cert.tbs_certificate.subject.to_der()
            .map_err(|e| anyhow::anyhow!("subject DER 编码失败: {}", e))?;
        let subject_key = B64.encode(&subject_der);
        self.subject_index.insert(subject_key, der.to_vec());

        // serial hex → cert DER
        let serial_hex = hex::encode(cert.tbs_certificate.serial_number.as_bytes());
        self.serial_index.insert(serial_hex, der.to_vec());

        Ok(())
    }

    /// 按 subject base64 或 serial hex 查找证书 DER
    pub fn find_cert(&self, cert_id: &str) -> Option<&Vec<u8>> {
        // 优先按 subject base64 查找
        if let Some(der) = self.subject_index.get(cert_id) {
            return Some(der);
        }
        // 再按 serial hex 查找（统一转小写）
        self.serial_index.get(&cert_id.to_lowercase())
    }

    /// 返回 subject_index 中所有证书的 DER bytes（用于 CMS 无附证时 fallback 查找）
    pub fn all_cert_ders(&self) -> Vec<&Vec<u8>> {
        self.subject_index.values().collect()
    }

    /// 按 certID（subject base64 或 SN hex）反查对应的加密密钥配置
    pub fn find_enc_key_by_cert_id(&self, cert_id: &str) -> Option<&crate::config::EncKey> {
        let target_der = self.find_cert(cert_id)?;
        self.enc_keys.values().find(|k| {
            B64.decode(&k.cert).ok().as_deref() == Some(target_der.as_slice())
        })
    }
}
