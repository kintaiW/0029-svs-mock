/// 生成测试用 SM2 密钥对和自签名证书
/// 运行: cargo run --example gen_test_data
/// 输出结果粘贴到 mock_certs.toml 的对应字段
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use libsmx::sm2;
use rand::rngs::OsRng;

fn main() {
    println!("=== 生成 SM2 测试密钥对 ===\n");

    // 生成签名密钥对
    let (sign_priv, sign_pub) = sm2::generate_keypair(&mut OsRng);
    println!("[signing_keys] index=1, pin=12345678");
    println!("private_key = \"{}\"", hex::encode(sign_priv.as_bytes()));
    println!("公钥(04||x||y, hex): {}", hex::encode(&sign_pub));
    println!();

    // 生成加密密钥对
    let (enc_priv, enc_pub) = sm2::generate_keypair(&mut OsRng);
    println!("[enc_keys] index=1");
    println!("private_key = \"{}\"", hex::encode(enc_priv.as_bytes()));
    println!("公钥(04||x||y, hex): {}", hex::encode(&enc_pub));
    println!();

    // 构建最小化自签名 SM2 证书 DER（手工编码，仅供测试）
    println!("=== 生成测试自签名证书 ===");
    println!("注意：手工构建的最小 DER 证书，仅用于接口冒烟测试");
    println!();

    let sign_cert = build_self_signed_cert(&sign_priv, &sign_pub, "Test Sign Cert");
    let enc_cert  = build_self_signed_cert(&enc_priv,  &enc_pub,  "Test Enc Cert");

    println!("[signing_keys]");
    println!("cert = \"{}\"", B64.encode(&sign_cert));
    println!();
    println!("[enc_keys]");
    println!("cert = \"{}\"", B64.encode(&enc_cert));
    println!();

    // 根证书就复用签名证书（自签名即是根）
    println!("[[trusted_roots]]");
    println!("name = \"test root\"");
    println!("cert = \"{}\"", B64.encode(&sign_cert));
    println!();

    println!("=== 签名/验签自测 ===");
    let msg = b"hello svs-mock";
    let sig = sm2::sign_message(msg, b"1234567812345678", &sign_priv, &mut OsRng);
    let result = sm2::verify_message(msg, b"1234567812345678", &sign_pub, &sig);
    println!("SM2 sign+verify: {:?}", result);
}

/// 构建极简自签名 SM2 证书 DER
/// 结构：Certificate { tbs, algId, signature }
/// tbs 包含最小必要字段，方便 x509-cert 解析
fn build_self_signed_cert(priv_key: &sm2::PrivateKey, pub_key: &[u8; 65], cn: &str) -> Vec<u8> {
    // 有效期：UTCTime 格式 YYMMDDHHMMSSZ（2020-01-01 到 2049-12-31）
    // Reason: RFC 5280 要求 2050 年前用 UTCTime(0x17)，格式 YYMMDDHHmmssZ
    let not_before = b"200101000000Z";
    let not_after  = b"491231235959Z";

    // OID: SM2withSM3 = 1.2.156.10197.1.501
    let sm2sm3_oid = oid_bytes(&[1, 2, 156, 10197, 1, 501]);
    let alg_id = der_seq(&[&der_oid(&sm2sm3_oid), &der_null()]);

    // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING(pub_key) }
    // SM2 公钥 OID: 1.2.840.10045.2.1（EC public key）
    // 曲线 OID SM2: 1.2.156.10197.1.301
    let ec_oid  = oid_bytes(&[1, 2, 840, 10045, 2, 1]);
    let sm2_curve_oid = oid_bytes(&[1, 2, 156, 10197, 1, 301]);
    let pk_alg_id = der_seq(&[&der_oid(&ec_oid), &der_oid(&sm2_curve_oid)]);
    let pk_bits = der_bitstring(pub_key); // 04||x||y
    let spki = der_seq(&[&pk_alg_id, &pk_bits]);

    // Subject/Issuer DN: SEQUENCE { SET { SEQUENCE { OID(CN=2.5.4.3), UTF8String(cn) } } }
    let cn_oid = oid_bytes(&[2, 5, 4, 3]);
    let cn_utf8 = der_utf8string(cn.as_bytes());
    let atv = der_seq(&[&der_oid(&cn_oid), &cn_utf8]);
    let rdn = der_set(&[&atv]);
    let dn = der_seq(&[&rdn]);

    // Validity：用 UTCTime(0x17)
    let validity = der_seq(&[
        &der_utctime(not_before),
        &der_utctime(not_after),
    ]);

    // Serial number: 1
    let serial = der_integer(&[1u8]);

    // TBSCertificate
    // version [0] EXPLICIT v3 = 2
    let version = der_explicit(0, &der_integer(&[2u8]));
    let tbs = der_seq(&[
        &version,
        &serial,
        &alg_id,
        &dn,     // issuer
        &validity,
        &dn,     // subject（自签名，issuer=subject）
        &spki,
    ]);

    // 对 TBS 签名
    let sig = sm2::sign_message(&tbs, b"1234567812345678", priv_key, &mut OsRng);
    // DER 编码签名 SEQUENCE { INTEGER r, INTEGER s }
    let sig_der = encode_der_rs(&sig[..32], &sig[32..]);

    // Certificate
    der_seq(&[&tbs, &alg_id, &der_bitstring(&sig_der)])
}

// ── DER 辅助 ──

fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
    let content: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    let mut v = vec![0x30];
    push_len(&mut v, content.len());
    v.extend_from_slice(&content);
    v
}

fn der_set(parts: &[&[u8]]) -> Vec<u8> {
    let content: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    let mut v = vec![0x31];
    push_len(&mut v, content.len());
    v.extend_from_slice(&content);
    v
}

fn der_oid(encoded: &[u8]) -> Vec<u8> {
    let mut v = vec![0x06];
    push_len(&mut v, encoded.len());
    v.extend_from_slice(encoded);
    v
}

fn der_null() -> Vec<u8> { vec![0x05, 0x00] }

fn der_integer(val: &[u8]) -> Vec<u8> {
    let needs_pad = val.first().map(|&b| b >= 0x80).unwrap_or(false);
    let mut v = vec![0x02];
    push_len(&mut v, val.len() + if needs_pad { 1 } else { 0 });
    if needs_pad { v.push(0x00); }
    v.extend_from_slice(val);
    v
}

fn der_bitstring(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x03];
    push_len(&mut v, data.len() + 1);
    v.push(0x00); // 无填充位
    v.extend_from_slice(data);
    v
}

fn der_utf8string(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x0c];
    push_len(&mut v, data.len());
    v.extend_from_slice(data);
    v
}

fn der_utctime(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x17]; // UTCTime
    push_len(&mut v, data.len());
    v.extend_from_slice(data);
    v
}

fn der_gentime(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x18]; // GeneralizedTime
    push_len(&mut v, data.len());
    v.extend_from_slice(data);
    v
}

fn der_explicit(tag: u8, inner: &[u8]) -> Vec<u8> {
    let mut v = vec![0xa0 | tag];
    push_len(&mut v, inner.len());
    v.extend_from_slice(inner);
    v
}

fn push_len(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81); buf.push(len as u8);
    } else {
        buf.push(0x82); buf.push((len >> 8) as u8); buf.push((len & 0xff) as u8);
    }
}

fn oid_bytes(arcs: &[u64]) -> Vec<u8> {
    let mut v = Vec::new();
    if arcs.len() >= 2 { v.push((arcs[0] * 40 + arcs[1]) as u8); }
    for &arc in &arcs[2..] { encode_base128(&mut v, arc); }
    v
}

fn encode_base128(buf: &mut Vec<u8>, mut val: u64) {
    let mut bytes = Vec::new();
    bytes.push((val & 0x7f) as u8);
    val >>= 7;
    while val > 0 { bytes.push(0x80 | (val & 0x7f) as u8); val >>= 7; }
    bytes.reverse();
    buf.extend_from_slice(&bytes);
}

fn encode_der_rs(r: &[u8], s: &[u8]) -> Vec<u8> {
    let r_enc = encode_int(r);
    let s_enc = encode_int(s);
    let mut out = vec![0x30];
    push_len(&mut out, r_enc.len() + s_enc.len());
    out.extend_from_slice(&r_enc);
    out.extend_from_slice(&s_enc);
    out
}

fn encode_int(val: &[u8]) -> Vec<u8> {
    let start = val.iter().position(|&x| x != 0).unwrap_or(val.len() - 1);
    let trimmed = &val[start..];
    let needs_pad = trimmed.first().map(|&b| b >= 0x80).unwrap_or(false);
    let mut v = vec![0x02];
    push_len(&mut v, trimmed.len() + if needs_pad { 1 } else { 0 });
    if needs_pad { v.push(0x00); }
    v.extend_from_slice(trimmed);
    v
}
