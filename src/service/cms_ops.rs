/// CMS SignedData 构建与解析（简化版，与真实设备格式兼容）
/// Reason: 完整 CMS 实现复杂，此处实现核心字段，满足密评工具交互需求
use crate::error::*;
use crate::service::crypto_ops;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use der::{Decode, Encode};
use x509_cert::Certificate;

/// 构建 CMS SignedData（签名 PKCS7 消息）
/// 返回 DER 编码的 ContentInfo DER bytes
pub fn sign_message(
    priv_key_hex: &str,
    signer_cert_der: &[u8],
    data: &[u8],
    detached: bool,          // true=不附原文, false=附原文
    include_cert: bool,      // 是否附证书链
) -> Result<Vec<u8>, u32> {
    // 1. SM2 签名
    let sig_der = crypto_ops::sm2_sign(priv_key_hex, data)?;

    // 2. 解析签名者证书
    let cert = Certificate::from_der(signer_cert_der).map_err(|_| ERR_CERT_DECODE)?;
    let serial = cert.tbs_certificate.serial_number.as_bytes().to_vec();
    let issuer_der = cert.tbs_certificate.issuer.to_der().map_err(|_| ERR_DATA_FORMAT)?;

    // 3. 构建简化 CMS SignedData（手工 DER 编码）
    // Reason: 不引入重量级 CMS crate，直接手工序列化满足密评工具需求
    build_signed_data(
        data,
        detached,
        signer_cert_der,
        include_cert,
        &issuer_der,
        &serial,
        &sig_der,
    ).map_err(|_| ERR_DATA_FORMAT)
}

/// 验证 CMS SignedData
pub fn verify_signed_message(cms_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), u32> {
    // 解析 CMS，提取签名者证书、原文、签名值
    parse_and_verify_signed_data(cms_der).map_err(|_| ERR_SIG_INVALID)
}

// ──────────────────── 简化 CMS 构建 ────────────────────

/// 手工构建 CMS SignedData ContentInfo DER
/// 格式（简化）：
///   ContentInfo ::= SEQUENCE {
///     contentType OBJECT IDENTIFIER (1.2.840.113549.1.7.2),
///     content [0] EXPLICIT SignedData
///   }
///   SignedData ::= SEQUENCE {
///     version       INTEGER (1),
///     digestAlgorithms  SET OF DigestAlgorithmIdentifier,
///     encapContentInfo  EncapsulatedContentInfo,
///     certificates  [0] IMPLICIT CertificateSet OPTIONAL,
///     signerInfos   SET OF SignerInfo
///   }
fn build_signed_data(
    content: &[u8],
    detached: bool,
    signer_cert_der: &[u8],
    include_cert: bool,
    issuer_der: &[u8],
    serial: &[u8],
    sig_der: &[u8],
) -> anyhow::Result<Vec<u8>> {
    // SM3 OID: 1.2.156.10197.1.401
    let sm3_oid = oid_bytes(&[1, 2, 156, 10197, 1, 401]);
    // SM2withSM3 OID: 1.2.156.10197.1.501
    let sm2sm3_oid = oid_bytes(&[1, 2, 156, 10197, 1, 501]);
    // Data OID: 1.2.840.113549.1.7.1
    let data_oid = oid_bytes(&[1, 2, 840, 113549, 1, 7, 1]);
    // SignedData OID: 1.2.840.113549.1.7.2
    let signed_data_oid = oid_bytes(&[1, 2, 840, 113549, 1, 7, 2]);

    // digestAlgorithms: SET { SEQUENCE { OID(SM3) } }
    let digest_alg = der_seq(&[&der_seq(&[&der_oid(&sm3_oid), &der_null()])]);
    let digest_algs = der_set(&[&digest_alg]);

    // encapContentInfo
    let econtent = if detached {
        der_seq(&[&der_oid(&data_oid)])
    } else {
        let wrapped = der_explicit(0, &der_octet_string(content));
        der_seq(&[&der_oid(&data_oid), &wrapped])
    };

    // certificates [0] IMPLICIT
    let certs_field = if include_cert {
        der_context_implicit(0, signer_cert_der)
    } else {
        vec![]
    };

    // SignerInfo
    // IssuerAndSerialNumber
    let issuer_and_serial = der_seq(&[issuer_der, &der_integer(serial)]);
    // signatureAlgorithm
    let sig_alg = der_seq(&[&der_oid(&sm2sm3_oid), &der_null()]);
    // SignerInfo SEQUENCE
    let signer_info = der_seq(&[
        &der_integer(&[1u8]),          // version
        &issuer_and_serial,
        &der_seq(&[&der_oid(&sm3_oid), &der_null()]),  // digestAlgorithm
        &sig_alg,                      // signatureAlgorithm
        &der_octet_string(sig_der),    // signature
    ]);
    let signer_infos = der_set(&[&signer_info]);

    // SignedData SEQUENCE
    let mut signed_data_fields: Vec<Vec<u8>> = vec![
        der_integer(&[1u8]),
        digest_algs,
        econtent,
    ];
    if !certs_field.is_empty() {
        signed_data_fields.push(certs_field);
    }
    signed_data_fields.push(signer_infos);

    let signed_data = der_seq(&signed_data_fields.iter().map(|v| v.as_slice()).collect::<Vec<_>>());

    // ContentInfo
    let content_info = der_seq(&[
        &der_oid(&signed_data_oid),
        &der_explicit(0, &signed_data),
    ]);

    Ok(content_info)
}

// ──────────────────── 简化 CMS 解析 ────────────────────

/// 从 CMS SignedData DER 中提取（签名者公钥 DER, 原文字节, 签名者证书 DER）并验签
/// 返回 (原文, 签名者证书 DER)
fn parse_and_verify_signed_data(cms_der: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    // 简化解析：使用 der crate 的 Any/RawValue 遍历
    // Reason: 手工解析 TLV 比引入完整 CMS crate 更轻量
    use der::asn1::Any;

    // 从 ContentInfo 取出 SignedData content
    let ci = der_parse_sequence(cms_der)?;
    // ci[0] = OID, ci[1] = [0] EXPLICIT SignedData
    let signed_data_wrapped = ci.get(1).ok_or(anyhow::anyhow!("缺少 content"))?;
    // 去掉 [0] EXPLICIT 包装
    let signed_data_der = der_unwrap_explicit(signed_data_wrapped)?;
    let sd = der_parse_sequence(&signed_data_der)?;
    // sd[0]=version, sd[1]=digestAlgorithms, sd[2]=encapContentInfo, sd[3]=certs or signerInfos
    let econtent_seq = sd.get(2).ok_or(anyhow::anyhow!("缺少 encapContentInfo"))?;
    let econtent_parts = der_parse_sequence(econtent_seq)?;

    // 原文：econtent_parts[1] 是 [0] EXPLICIT OCTET STRING
    let content = if econtent_parts.len() > 1 {
        let wrapped = &econtent_parts[1];
        let inner = der_unwrap_explicit(wrapped)?;
        // inner 是 OCTET STRING TLV
        der_parse_octet_string(&inner)?
    } else {
        vec![]
    };

    // 找到 signerInfos（最后一个 SET）和 certificates
    let mut signer_cert_der = vec![];
    let mut sig_bytes = vec![];

    // 遍历 sd 字段找 certificates [0] 和 signerInfos SET
    for i in 3..sd.len() {
        let field = &sd[i];
        if field[0] == 0xa0 {
            // certificates [0] IMPLICIT：包含证书 DER
            let inner = der_unwrap_implicit(field)?;
            signer_cert_der = inner;
        } else if field[0] == 0x31 {
            // signerInfos SET
            let si_set = der_parse_set(field)?;
            let si = si_set.first().ok_or(anyhow::anyhow!("空 signerInfos"))?;
            let si_parts = der_parse_sequence(si)?;
            // si_parts: [version, issuerAndSerial, digestAlg, sigAlg, signature]
            let sig_raw = si_parts.last().ok_or(anyhow::anyhow!("缺少签名"))?;
            sig_bytes = der_parse_octet_string(sig_raw)?;
        }
    }

    if signer_cert_der.is_empty() || sig_bytes.is_empty() {
        return Err(anyhow::anyhow!("CMS 解析不完整"));
    }

    // 从证书提取公钥
    let cert = Certificate::from_der(&signer_cert_der)?;
    let pub_key_point = cert.tbs_certificate.subject_public_key_info
        .subject_public_key.raw_bytes();

    // 验签
    crypto_ops::sm2_verify(pub_key_point, &content, &sig_bytes)
        .map_err(|_| anyhow::anyhow!("签名验证失败"))?;

    Ok((content, signer_cert_der))
}

// ──────────────────── DER 辅助函数 ────────────────────

fn der_oid(encoded: &[u8]) -> Vec<u8> {
    let mut v = vec![0x06];
    push_der_length(&mut v, encoded.len());
    v.extend_from_slice(encoded);
    v
}

fn der_null() -> Vec<u8> { vec![0x05, 0x00] }

fn der_integer(val: &[u8]) -> Vec<u8> {
    // 若最高位为1，需要前置0x00
    let needs_pad = val.first().map(|&b| b >= 0x80).unwrap_or(false);
    let mut v = vec![0x02];
    let len = val.len() + if needs_pad { 1 } else { 0 };
    push_der_length(&mut v, len);
    if needs_pad { v.push(0x00); }
    v.extend_from_slice(val);
    v
}

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x04];
    push_der_length(&mut v, data.len());
    v.extend_from_slice(data);
    v
}

fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
    let content: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    let mut v = vec![0x30];
    push_der_length(&mut v, content.len());
    v.extend_from_slice(&content);
    v
}

fn der_set(parts: &[&[u8]]) -> Vec<u8> {
    let content: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    let mut v = vec![0x31];
    push_der_length(&mut v, content.len());
    v.extend_from_slice(&content);
    v
}

fn der_explicit(tag: u8, inner: &[u8]) -> Vec<u8> {
    let mut v = vec![0xa0 | tag];
    push_der_length(&mut v, inner.len());
    v.extend_from_slice(inner);
    v
}

fn der_context_implicit(tag: u8, inner: &[u8]) -> Vec<u8> {
    let mut v = vec![0xa0 | tag];
    push_der_length(&mut v, inner.len());
    v.extend_from_slice(inner);
    v
}

fn push_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xff) as u8);
    }
}

/// 编码 OID（弧列表 → DER OID content bytes）
fn oid_bytes(arcs: &[u64]) -> Vec<u8> {
    let mut v = Vec::new();
    // 前两弧合并
    if arcs.len() >= 2 {
        v.push((arcs[0] * 40 + arcs[1]) as u8);
    }
    for &arc in &arcs[2..] {
        encode_base128(&mut v, arc);
    }
    v
}

fn encode_base128(buf: &mut Vec<u8>, mut val: u64) {
    let mut bytes = Vec::new();
    bytes.push((val & 0x7f) as u8);
    val >>= 7;
    while val > 0 {
        bytes.push(0x80 | (val & 0x7f) as u8);
        val >>= 7;
    }
    bytes.reverse();
    buf.extend_from_slice(&bytes);
}

// ──────────────────── DER 解析辅助 ────────────────────

/// 解析 DER SEQUENCE，返回各子元素 TLV bytes
fn der_parse_sequence(data: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    if data.is_empty() || data[0] != 0x30 {
        return Err(anyhow::anyhow!("非 SEQUENCE"));
    }
    let (content, _) = der_read_tlv_content(data)?;
    der_split_elements(content)
}

fn der_parse_set(data: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    if data.is_empty() || data[0] != 0x31 {
        return Err(anyhow::anyhow!("非 SET"));
    }
    let (content, _) = der_read_tlv_content(data)?;
    der_split_elements(content)
}

fn der_parse_octet_string(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.is_empty() || data[0] != 0x04 {
        return Err(anyhow::anyhow!("非 OCTET STRING"));
    }
    let (content, _) = der_read_tlv_content(data)?;
    Ok(content.to_vec())
}

fn der_unwrap_explicit(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let (content, _) = der_read_tlv_content(data)?;
    Ok(content.to_vec())
}

fn der_unwrap_implicit(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    // [0] IMPLICIT: 跳过标签和长度，直接返回内容（作为证书 DER）
    let (content, _) = der_read_tlv_content(data)?;
    Ok(content.to_vec())
}

/// 读取 TLV，返回 (content_bytes, total_len)
fn der_read_tlv_content(data: &[u8]) -> anyhow::Result<(&[u8], usize)> {
    if data.len() < 2 {
        return Err(anyhow::anyhow!("数据太短"));
    }
    let (len, header_len) = read_der_length(&data[1..])?;
    let total = 1 + header_len + len;
    if data.len() < total {
        return Err(anyhow::anyhow!("数据不完整"));
    }
    Ok((&data[1 + header_len..total], total))
}

fn read_der_length(data: &[u8]) -> anyhow::Result<(usize, usize)> {
    if data.is_empty() {
        return Err(anyhow::anyhow!("空数据"));
    }
    if data[0] < 0x80 {
        Ok((data[0] as usize, 1))
    } else {
        let n = (data[0] & 0x7f) as usize;
        if data.len() < 1 + n {
            return Err(anyhow::anyhow!("长度字节不足"));
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | data[1 + i] as usize;
        }
        Ok((len, 1 + n))
    }
}

/// 将 content bytes 拆分为各 TLV 元素
fn der_split_elements(data: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let (_, total) = der_read_tlv_content(&data[pos..])?;
        result.push(data[pos..pos + total].to_vec());
        pos += total;
    }
    Ok(result)
}
