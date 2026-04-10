use crate::cert_store::CertStore;
use crate::error::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use der::{Decode, Encode};
use x509_cert::Certificate;

/// 证书有效期验证 + 信任锚验签
pub fn validate_cert(der: &[u8], store: &CertStore) -> u32 {
    let cert = match Certificate::from_der(der) {
        Ok(c) => c,
        Err(_) => return ERR_CERT_DECODE,
    };

    // 检查有效期
    let now_ts = Utc::now().timestamp();
    let validity = &cert.tbs_certificate.validity;
    let not_before = validity.not_before.to_unix_duration().as_secs() as i64;
    let not_after = validity.not_after.to_unix_duration().as_secs() as i64;

    if now_ts < not_before {
        return ERR_CERT_NOT_YET;
    }
    if now_ts > not_after {
        return ERR_CERT_EXPIRED;
    }

    // 信任锚验签：尝试用每个根证书的公钥验证此证书签名
    // Reason: 仅做信任链根节点验证，不做中间链，符合 mock 简化策略
    let verified = store.trusted_roots.iter().any(|root_der| {
        verify_cert_signature(der, root_der).unwrap_or(false)
    });

    // 若证书本身就是根证书，也视为信任（自签名）
    let self_signed = verify_cert_signature(der, der).unwrap_or(false);

    if verified || self_signed {
        GM_SUCCESS
    } else {
        ERR_CERT_INVALID
    }
}

/// 用 issuer_cert 的公钥验证 subject_cert 的 TBS 签名
fn verify_cert_signature(subject_der: &[u8], issuer_der: &[u8]) -> anyhow::Result<bool> {
    let subject = Certificate::from_der(subject_der)?;
    let issuer = Certificate::from_der(issuer_der)?;

    // 提取 issuer 公钥（SM2，65字节 04||x||y）
    let issuer_pub_bits = issuer.tbs_certificate.subject_public_key_info
        .subject_public_key.raw_bytes();
    if issuer_pub_bits.len() != 65 || issuer_pub_bits[0] != 0x04 {
        return Ok(false);
    }
    let pub_key_arr: &[u8; 65] = issuer_pub_bits.try_into()?;

    // TBS 证书 DER（被签名的内容）
    let tbs_der = subject.tbs_certificate.to_der()?;

    // 签名值（DER SEQUENCE { INTEGER r, INTEGER s }）
    let sig_bytes = subject.signature.raw_bytes();

    // 解码 DER 签名为 64字节 r||s
    let sig_64 = decode_der_rs(sig_bytes)?;
    let sig_arr: &[u8; 64] = sig_64.as_slice().try_into()?;

    // SM2 验签，使用 DEFAULT_ID
    use crate::service::crypto_ops::DEFAULT_USER_ID;
    let result = libsmx::sm2::verify_message(&tbs_der, DEFAULT_USER_ID, pub_key_arr, sig_arr);
    Ok(result.is_ok())
}

/// 解析证书字段（ParseCert），按 infoType 返回对应数据
pub fn parse_cert(der: &[u8], info_type: u32) -> Result<serde_json::Value, u32> {
    let cert = Certificate::from_der(der).map_err(|_| ERR_CERT_DECODE)?;

    match info_type {
        1 => {
            // SGD_CERT_VERSION：版本号（0=v1, 1=v2, 2=v3）
            let ver = cert.tbs_certificate.version as u8;
            Ok(serde_json::json!({ "certInfo": B64.encode([ver]) }))
        }
        2 => {
            // SGD_CERT_SERIAL：序列号字节
            let sn = cert.tbs_certificate.serial_number.as_bytes();
            Ok(serde_json::json!({ "certInfo": B64.encode(sn) }))
        }
        5 => {
            // SGD_CERT_ISSUER：颁发者 DN DER base64
            let issuer_der = cert.tbs_certificate.issuer.to_der().map_err(|_| ERR_CERT_DECODE)?;
            Ok(serde_json::json!({ "certInfo": B64.encode(&issuer_der) }))
        }
        6 => {
            // SGD_CERT_VALID_TIME：有效期，返回两个时间字符串
            let nb = format_x509_time(cert.tbs_certificate.validity.not_before.to_unix_duration().as_secs());
            let na = format_x509_time(cert.tbs_certificate.validity.not_after.to_unix_duration().as_secs());
            Ok(serde_json::json!({ "notBefore": nb, "notAfter": na }))
        }
        7 => {
            // SGD_CERT_SUBJECT：拥有者 DN DER base64
            let subj_der = cert.tbs_certificate.subject.to_der().map_err(|_| ERR_CERT_DECODE)?;
            Ok(serde_json::json!({ "certInfo": B64.encode(&subj_der) }))
        }
        8 => {
            // SGD_CERT_DER_PUBLIC_KEY：公钥 SubjectPublicKeyInfo DER base64
            let pk_der = cert.tbs_certificate.subject_public_key_info.to_der().map_err(|_| ERR_CERT_DECODE)?;
            Ok(serde_json::json!({ "certInfo": B64.encode(&pk_der) }))
        }
        0x31 => {
            // SGD_CERT_SUBJECT_CN：CN 字符串
            let cn = extract_cn(&cert.tbs_certificate.subject).unwrap_or_default();
            Ok(serde_json::json!({ "certInfo": cn }))
        }
        0x35 => {
            // SGD_CERT_NOTBEFORE_TIME
            let nb = format_x509_time(cert.tbs_certificate.validity.not_before.to_unix_duration().as_secs());
            Ok(serde_json::json!({ "certInfo": nb }))
        }
        0x36 => {
            // SGD_CERT_NOTAFTER_TIME
            let na = format_x509_time(cert.tbs_certificate.validity.not_after.to_unix_duration().as_secs());
            Ok(serde_json::json!({ "certInfo": na }))
        }
        _ => Err(ERR_PARAM),
    }
}

/// 将 unix 秒数转为时间字符串（格式：YYYYMMDDHHMMSSZ）
fn format_x509_time(unix_secs: u64) -> String {
    let dt = chrono::DateTime::<Utc>::from_timestamp(unix_secs as i64, 0)
        .unwrap_or_default();
    dt.format("%Y%m%d%H%M%SZ").to_string()
}

/// 从 DN 中提取 CN 字段
fn extract_cn(name: &x509_cert::name::RdnSequence) -> Option<String> {
    use der::asn1::Utf8StringRef;

    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            // CN OID = 2.5.4.3
            if atv.oid.to_string() == "2.5.4.3" {
                // 尝试解析为 UTF8String
                if let Ok(s) = atv.value.decode_as::<Utf8StringRef>() {
                    return Some(s.as_str().to_string());
                }
                // 降级：直接转字节为 UTF-8
                return Some(String::from_utf8_lossy(atv.value.value()).to_string());
            }
        }
    }
    None
}

/// DER 解码 SEQUENCE { INTEGER r, INTEGER s } → 64字节 r||s
fn decode_der_rs(der: &[u8]) -> anyhow::Result<Vec<u8>> {
    if der.len() < 6 || der[0] != 0x30 {
        return Err(anyhow::anyhow!("非 SEQUENCE"));
    }
    let (content, _) = read_tlv_content(der)?;
    let (r_raw, rest) = read_integer(content)?;
    let (s_raw, _) = read_integer(rest)?;
    let r_padded = pad_to_32(&r_raw)?;
    let s_padded = pad_to_32(&s_raw)?;
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&r_padded);
    out.extend_from_slice(&s_padded);
    Ok(out)
}

fn read_tlv_content(data: &[u8]) -> anyhow::Result<(&[u8], usize)> {
    if data.len() < 2 { return Err(anyhow::anyhow!("太短")); }
    let (len, hlen) = read_der_len(&data[1..])?;
    let total = 1 + hlen + len;
    if data.len() < total { return Err(anyhow::anyhow!("不完整")); }
    Ok((&data[1 + hlen..total], total))
}

fn read_der_len(data: &[u8]) -> anyhow::Result<(usize, usize)> {
    if data.is_empty() { return Err(anyhow::anyhow!("空")); }
    if data[0] < 0x80 {
        Ok((data[0] as usize, 1))
    } else {
        let n = (data[0] & 0x7f) as usize;
        if data.len() < 1 + n { return Err(anyhow::anyhow!("长度字节不足")); }
        let mut len = 0usize;
        for i in 0..n { len = (len << 8) | data[1 + i] as usize; }
        Ok((len, 1 + n))
    }
}

fn read_integer(data: &[u8]) -> anyhow::Result<(Vec<u8>, &[u8])> {
    if data.is_empty() || data[0] != 0x02 {
        return Err(anyhow::anyhow!("非 INTEGER"));
    }
    let (content, total) = read_tlv_content(data)?;
    let val = if content.first() == Some(&0x00) { &content[1..] } else { content };
    Ok((val.to_vec(), &data[total..]))
}

fn pad_to_32(val: &[u8]) -> anyhow::Result<[u8; 32]> {
    if val.len() > 32 { return Err(anyhow::anyhow!("超过32字节")); }
    let mut arr = [0u8; 32];
    arr[32 - val.len()..].copy_from_slice(val);
    Ok(arr)
}
