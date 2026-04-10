/// GM/T 0029 错误码定义
pub const GM_SUCCESS: u32 = 0;
pub const ERR_CERT_ID: u32 = 0x04000001;       // 错误的证书标识
pub const ERR_ALG_ID: u32 = 0x04000004;        // 签名算法类型错误
pub const ERR_KEY_INDEX: u32 = 0x04000005;     // 私钥索引值错误
pub const ERR_KEY_AUTH: u32 = 0x04000006;      // 权限标识码错误
pub const ERR_CERT_INVALID: u32 = 0x04000007;  // 证书非法或不存在
pub const ERR_CERT_DECODE: u32 = 0x04000008;   // 证书解码错误
pub const ERR_CERT_EXPIRED: u32 = 0x04000009;  // 证书过期
pub const ERR_CERT_NOT_YET: u32 = 0x0400000a;  // 证书尚未生效
pub const ERR_CERT_REVOKED: u32 = 0x0400000b;  // 证书已被吊销（未实现，保留）
pub const ERR_SIG_INVALID: u32 = 0x0400000c;   // 签名无效
pub const ERR_DATA_FORMAT: u32 = 0x0400000d;   // 数据格式错误
pub const ERR_INTERNAL: u32 = 0x0400000e;      // 系统内部错误（多包接口 stub 返回此码）
pub const ERR_CRYPTO: u32 = 0x0400000f;        // 密码运算错误
pub const ERR_PARAM: u32 = 0x04000010;         // 输入参数错误

/// 构造成功 JSON 响应，respValue = 0
pub fn resp_ok() -> serde_json::Value {
    serde_json::json!({ "respValue": GM_SUCCESS })
}

/// 构造错误 JSON 响应，respValue = err_code
pub fn resp_err(err_code: u32) -> serde_json::Value {
    serde_json::json!({ "respValue": err_code })
}

/// 构造带数据的成功 JSON 响应
pub fn resp_ok_with(mut data: serde_json::Value) -> serde_json::Value {
    data["respValue"] = serde_json::json!(GM_SUCCESS);
    data
}
