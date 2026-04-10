/// SM2/SM3/SM4 密码运算封装
use crate::error::*;
use libsmx::{sm2, sm3, sm4};
use rand::rngs::OsRng;

/// SM2 默认 userId（固定 16字节）
pub const DEFAULT_USER_ID: &[u8] = b"1234567812345678";

/// 计算 SM3 摘要
/// 若提供 pub_key_65（04||x||y，65字节）和 user_id，则先计算 Z 值再拼接原文
pub fn sm3_digest(
    data: &[u8],
    pub_key_65: Option<&[u8]>,
    user_id: Option<&[u8]>,
) -> Result<Vec<u8>, u32> {
    if let (Some(pk), Some(uid)) = (pub_key_65, user_id) {
        // Reason: SM2 签名需要先计算 Z=SM3(entlen||uid||curve_params||pubkey)，Z 再与原文一起做摘要
        let pk_arr: &[u8; 65] = pk.try_into().map_err(|_| ERR_PARAM)?;
        let uid_used = if uid.is_empty() { DEFAULT_USER_ID } else { uid };
        let z = sm2::get_z(uid_used, pk_arr);
        let e = sm2::get_e(&z, data);
        Ok(e.to_vec())
    } else {
        let digest = sm3::Sm3Hasher::digest(data);
        Ok(digest.to_vec())
    }
}

/// SM2 签名（返回 DER 编码的 SEQUENCE { INTEGER r, INTEGER s }）
pub fn sm2_sign(private_key_hex: &str, data: &[u8]) -> Result<Vec<u8>, u32> {
    let key_bytes: [u8; 32] = hex::decode(private_key_hex)
        .map_err(|_| ERR_CRYPTO)?
        .try_into()
        .map_err(|_| ERR_CRYPTO)?;

    let priv_key = sm2::PrivateKey::from_bytes(&key_bytes).map_err(|_| ERR_CRYPTO)?;
    // sign_message 内部自动计算 Z 值
    let sig_64 = sm2::sign_message(data, DEFAULT_USER_ID, &priv_key, &mut OsRng);
    // sig_64: r(32) || s(32)，转为 DER SEQUENCE
    encode_der_rs(&sig_64[..32], &sig_64[32..]).map_err(|_| ERR_DATA_FORMAT)
}

/// SM2 验签（sig_der 为 DER 编码的 SEQUENCE { INTEGER r, INTEGER s }，pub_key_point 为 65字节 04||x||y）
pub fn sm2_verify(pub_key_point: &[u8], data: &[u8], sig_der: &[u8]) -> Result<(), u32> {
    let pk_arr: &[u8; 65] = pub_key_point.try_into().map_err(|_| ERR_CERT_DECODE)?;
    // DER 解码签名
    let sig_64 = decode_der_rs(sig_der).map_err(|_| ERR_DATA_FORMAT)?;
    let sig_arr: &[u8; 64] = sig_64.as_slice().try_into().map_err(|_| ERR_DATA_FORMAT)?;
    sm2::verify_message(data, DEFAULT_USER_ID, pk_arr, sig_arr).map_err(|_| ERR_SIG_INVALID)
}

/// 数字信封加密：SM2 加密随机 SM4 密钥，SM4-CBC 加密数据
/// 返回 (encrypted_key, encrypted_data, iv)
pub fn envelope_enc(pub_key_point: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), u32> {
    use rand::RngCore;

    let pk_arr: &[u8; 65] = pub_key_point.try_into().map_err(|_| ERR_CERT_DECODE)?;

    // 生成随机 SM4 密钥和 IV
    let mut sm4_key = [0u8; 16];
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut sm4_key);
    OsRng.fill_bytes(&mut iv);

    // SM2 加密 SM4 密钥
    let encrypted_key = sm2::encrypt(pk_arr, &sm4_key, &mut OsRng).map_err(|_| ERR_CRYPTO)?;

    // SM4-CBC 加密原文（手工 PKCS7 padding，libsmx CBC 不含 padding）
    let padded = pkcs7_pad(plaintext, 16);
    let encrypted_data = sm4::sm4_encrypt_cbc(&sm4_key, &iv, &padded);

    Ok((encrypted_key, encrypted_data, iv.to_vec()))
}

/// 数字信封解密
pub fn envelope_dec(
    priv_key_hex: &str,
    encrypted_key: &[u8],
    encrypted_data: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, u32> {
    let key_bytes: [u8; 32] = hex::decode(priv_key_hex)
        .map_err(|_| ERR_CRYPTO)?
        .try_into()
        .map_err(|_| ERR_CRYPTO)?;
    let iv_arr: &[u8; 16] = iv.try_into().map_err(|_| ERR_PARAM)?;

    let priv_key = sm2::PrivateKey::from_bytes(&key_bytes).map_err(|_| ERR_CRYPTO)?;

    // SM2 解密 SM4 密钥
    let sm4_key_vec = sm2::decrypt(&priv_key, encrypted_key).map_err(|_| ERR_CRYPTO)?;
    let sm4_key: &[u8; 16] = sm4_key_vec.as_slice().try_into().map_err(|_| ERR_DATA_FORMAT)?;

    // SM4-CBC 解密，再去 PKCS7 padding
    let padded = sm4::sm4_decrypt_cbc(sm4_key, iv_arr, encrypted_data);
    let plain = pkcs7_unpad(&padded).map_err(|_| ERR_DATA_FORMAT)?;
    Ok(plain)
}

/// 从 SubjectPublicKeyInfo DER 提取 SM2 公钥点（04||x||y，65字节）
pub fn extract_pubkey_from_spki(spki_der: &[u8]) -> Result<[u8; 65], u32> {
    use der::Decode;
    use x509_cert::spki::SubjectPublicKeyInfoRef;
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der).map_err(|_| ERR_CERT_DECODE)?;
    let point = spki.subject_public_key.raw_bytes();
    point.try_into().map_err(|_| ERR_CERT_DECODE)
}

// ──────────────────── DER r||s 编解码 ────────────────────

/// DER 编码 SM2 签名 SEQUENCE { INTEGER r, INTEGER s } → 64字节
fn encode_der_rs(r: &[u8], s: &[u8]) -> anyhow::Result<Vec<u8>> {
    let r_enc = encode_der_integer(r);
    let s_enc = encode_der_integer(s);
    let content_len = r_enc.len() + s_enc.len();
    let mut out = Vec::new();
    out.push(0x30); // SEQUENCE tag
    push_der_len(&mut out, content_len);
    out.extend_from_slice(&r_enc);
    out.extend_from_slice(&s_enc);
    Ok(out)
}

/// DER 解码 SEQUENCE { INTEGER r, INTEGER s } → 64字节 r||s
fn decode_der_rs(der: &[u8]) -> anyhow::Result<Vec<u8>> {
    // 最少 8 字节：SEQUENCE(1) + len(1) + INTEGER(1) + 1 + INTEGER(1) + 1 + data
    if der.len() < 8 || der[0] != 0x30 {
        return Err(anyhow::anyhow!("非 SEQUENCE"));
    }
    let (content, _) = read_tlv_content(der)?;
    let (r_raw, rest) = read_integer(content)?;
    let (s_raw, _) = read_integer(rest)?;

    // 将 r, s 填充到 32 字节
    let r_padded = pad_to_32(&r_raw)?;
    let s_padded = pad_to_32(&s_raw)?;

    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&r_padded);
    out.extend_from_slice(&s_padded);
    Ok(out)
}

fn encode_der_integer(val: &[u8]) -> Vec<u8> {
    // 去前置零，保留至少1字节
    let start = val.iter().position(|&x| x != 0).unwrap_or(val.len().saturating_sub(1));
    let trimmed = &val[start..];
    // 若最高位为1，加前置 0x00
    let needs_pad = trimmed.first().map(|&b| b >= 0x80).unwrap_or(false);
    let content_len = trimmed.len() + if needs_pad { 1 } else { 0 };

    let mut out = vec![0x02]; // INTEGER tag
    push_der_len(&mut out, content_len);
    if needs_pad { out.push(0x00); }
    out.extend_from_slice(trimmed);
    out
}

fn push_der_len(buf: &mut Vec<u8>, len: usize) {
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

fn read_tlv_content(data: &[u8]) -> anyhow::Result<(&[u8], usize)> {
    if data.len() < 2 { return Err(anyhow::anyhow!("数据太短")); }
    let (len, hlen) = read_der_len(&data[1..])?;
    let total = 1 + hlen + len;
    if data.len() < total { return Err(anyhow::anyhow!("数据不完整")); }
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

/// 读取一个 DER INTEGER，返回 (value_bytes_without_sign_byte, remaining)
fn read_integer(data: &[u8]) -> anyhow::Result<(Vec<u8>, &[u8])> {
    if data.is_empty() || data[0] != 0x02 {
        return Err(anyhow::anyhow!("非 INTEGER"));
    }
    let (content, total) = read_tlv_content(data)?;
    // 去掉可能的前置 0x00（符号位）
    let val = if content.first() == Some(&0x00) { &content[1..] } else { content };
    Ok((val.to_vec(), &data[total..]))
}

fn pad_to_32(val: &[u8]) -> anyhow::Result<[u8; 32]> {
    if val.len() > 32 { return Err(anyhow::anyhow!("整数超过32字节")); }
    let mut arr = [0u8; 32];
    arr[32 - val.len()..].copy_from_slice(val);
    Ok(arr)
}

/// PKCS7 填充（block_size=16）
fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

/// PKCS7 去填充
fn pkcs7_unpad(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let pad_len = *data.last().ok_or(anyhow::anyhow!("空数据"))? as usize;
    if pad_len == 0 || pad_len > 16 || pad_len > data.len() {
        return Err(anyhow::anyhow!("填充无效: pad_len={}", pad_len));
    }
    Ok(data[..data.len() - pad_len].to_vec())
}
