# SVS Mock 服务错误码文档

> 标准依据：GM/T 0029—2014 《签名验签服务器技术规范》

---

## 1. 错误码双层架构说明

SVS（签名验签服务器）基于 HTTP/HTTPS 协议提供服务，错误码分为两层：

### 第一层：HTTP 状态码

| HTTP 状态码 | 含义 | 触发场景 |
|------------|------|----------|
| `200 OK` | 请求处理成功（注意：业务层仍可能返回非零错误码） | 正常请求 |
| `400 Bad Request` | 请求体格式错误，无法解析 JSON | 请求 Body 非合法 JSON；必填字段缺失 |
| `404 Not Found` | 请求的接口路径不存在 | URL 拼写错误；接口版本不匹配 |
| `405 Method Not Allowed` | HTTP 方法不支持（如用 GET 请求 POST 接口） | 使用了错误的 HTTP 动词 |
| `413 Payload Too Large` | 请求体超过大小限制 | 传入的证书或签名数据过大 |
| `500 Internal Server Error` | Mock 服务内部未处理的异常 | 严重内部错误，应查看服务日志 |
| `503 Service Unavailable` | 服务暂时不可用 | 服务启动中或过载 |

### 第二层：业务层错误码

HTTP 状态码为 `200` 时，响应体中的 `code` 字段表示业务处理结果：

```json
{
  "code": 0,
  "message": "成功",
  "data": { ... }
}
```

```json
{
  "code": 16777219,
  "message": "证书不可信",
  "data": null
}
```

> `code` 字段为十进制整数。本文档同时提供十六进制表示以便对照。

---

## 2. 业务层错误码速查表

### 2.1 成功码

| 错误码（十六进制） | 十进制 | 名称 | 含义 |
|-------------------|--------|------|------|
| `0x00000000` | `0` | 成功 | 操作完成，无错误 |

### 2.2 通用与内部错误

| 错误码（十六进制） | 十进制 | 含义 | 可能原因 | 解决方案 |
|-------------------|--------|------|----------|----------|
| `0x01000001` | `16777217` | 内部错误 | SVS 服务内部发生未预期的异常；底层密码运算失败 | 开启 `RUST_LOG=debug` 查看完整堆栈信息；检查 SDF 服务是否正常运行 |
| `0x01000002` | `16777218` | 参数错误 | 请求字段缺失；字段格式不合规（如 Base64 格式证书传入了 PEM 带头部） | 检查请求 JSON 的字段名和数据类型；对照 API 文档确认必填字段 |

### 2.3 证书验证错误

| 错误码（十六进制） | 十进制 | 含义 | 可能原因 | 解决方案 |
|-------------------|--------|------|----------|----------|
| `0x01000003` | `16777219` | 证书不可信 | 证书链无法追溯到受信任的根 CA；证书的签发者与 Mock 配置的 CA 不匹配 | 确认使用的证书由 Mock 服务内置的测试 CA 签发（见 `mock_certs.toml`）；或将自定义 CA 添加到信任列表 |
| `0x01000004` | `16777220` | 证书已吊销 | 证书序列号已列入 Mock 服务的 CRL 或 OCSP 吊销列表 | 确认使用的是未被吊销的测试证书；检查 `mock_certs.toml` 中的吊销状态配置 |
| `0x01000005` | `16777221` | 证书已过期 | 证书的有效期（NotAfter）早于当前时间 | 使用 Mock 服务提供的有效期内测试证书；或调整 Mock 服务的时间基准（见配置文件） |

### 2.4 签名验证错误

| 错误码（十六进制） | 十进制 | 含义 | 可能原因 | 解决方案 |
|-------------------|--------|------|----------|----------|
| `0x01000006` | `16777222` | 签名值错误 | 签名值与原始数据/证书公钥不匹配；签名数据在传输中被篡改或截断 | 确认签名值来自证书中对应的私钥；检查签名数据的 Base64 编解码是否有填充问题 |
| `0x01000007` | `16777223` | 时间戳错误 | 时间戳令牌格式错误；时间戳与签名时间偏差超过允许范围；时间戳证书不可信 | 使用 Mock 服务提��的时间戳接口生成时间戳；确认时间戳令牌未被修改 |

### 2.5 编码与算法错误

| 错误码（十六进制） | 十进制 | 含义 | 可能原因 | 解决方案 |
|-------------------|--------|------|----------|----------|
| `0x01000008` | `16777224` | Base64 解码失败 | 传入的 Base64 字符串包含非法字符；字符串长度不符合 Base64 规范；误传入了 PEM 格式（含 `-----BEGIN...-----` 头部） | 确认数据为纯 Base64 编码（无换行、无头尾标记）；使用标准 Base64 编码而非 URL-safe 变体（除非接口文档说明） |
| `0x01000009` | `16777225` | 不支持的算法 | 请求中指定的签名算法或哈希算法不在 Mock 服务支持列表中 | Mock 服务支持：SM2withSM3；确认请求中的 `algorithm` 字段值 |

### 2.6 在线证书状态错误

| 错误码（十六进制） | 十进制 | 含义 | 可能原因 | 解决方案 |
|-------------------|--------|------|----------|----------|
| `0x0100000A` | `16777226` | CRL 获取失败 | 证书中的 CRL Distribution Points 无法访问；Mock 服务未配置 CRL 离线数据 | Mock 环境下应配置离线 CRL（见 `mock_certs.toml` 的 `crl_path`）；避免依赖外网 CRL 地址 |
| `0x0100000B` | `16777227` | OCSP 查询失败 | OCSP 服务器不可达；OCSP 响应格式错误；证书中未包含 OCSP URL | Mock 环境下使用内置 OCSP 模拟器；确认配置文件中 `enable_ocsp_mock = true` |

---

## 3. HTTP 请求与响应示例

### 3.1 签名验签请求（正常）

```bash
curl -X POST http://localhost:8080/svs/v1/verify \
  -H "Content-Type: application/json" \
  -d '{
    "certificate": "<Base64 编码的 DER 格式证书>",
    "original_data": "<Base64 编码的原始数据>",
    "signature": "<Base64 编码的签名值>",
    "algorithm": "SM2withSM3"
  }'
```

成功响应：
```json
{
  "code": 0,
  "message": "成功",
  "data": {
    "valid": true,
    "cert_subject": "CN=测试用户,O=测试机构,C=CN",
    "cert_not_after": "2027-01-01T00:00:00Z"
  }
}
```

### 3.2 错误响应格式

```json
{
  "code": 16777222,
  "message": "签名值错误",
  "data": null
}
```

> 注意：即使业务层返回错误，HTTP 状态码仍为 `200`，客户端应始终检查 `code` 字段。

---

## 4. 调试方法

### 4.1 开启 Debug 日志

```bash
# 推荐方式：开启全量 debug 日志
RUST_LOG=debug cargo run

# 仅开启 SVS 模块日志（减少噪音）
RUST_LOG=svs_mock=debug cargo run

# 同时记录到文件
RUST_LOG=debug cargo run 2>&1 | tee svs_mock.log
```

日志输出示例：
```
[DEBUG svs_mock::handler] POST /svs/v1/verify: cert_len=892, sig_len=64
[DEBUG svs_mock::cert]    证书解析成功: CN=测试用户
[DEBUG svs_mock::verify]  SM2withSM3 验签结果: false
[ERROR svs_mock::handler] 返回错误码 0x01000006: 签名值错误
```

### 4.2 使用 curl 调试

```bash
# 添加 -v 查看完整 HTTP 头部（用于排查 4xx 错误）
curl -v -X POST http://localhost:8080/svs/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"certificate": "...", ...}'

# 格式化 JSON 输出
curl -s -X POST ... | python3 -m json.tool
```

### 4.3 证书信息查看

```bash
# 查看 DER 格式证书内容（先 Base64 解码）
echo "<Base64字符串>" | base64 -d | openssl x509 -inform DER -text -noout

# 查看有效期
echo "<Base64字符串>" | base64 -d | openssl x509 -inform DER -noout -dates

# 查看证书序列号（用于检查是否在 CRL 中）
echo "<Base64字符串>" | base64 -d | openssl x509 -inform DER -noout -serial
```

### 4.4 Mock 配置文件说明

SVS Mock 的证书和吊销状态通过 `mock_certs.toml` 配置：

```toml
# mock_certs.toml 示例

[[certs]]
name = "测试用户证书"
path = "certs/user_cert.der"
revoked = false          # 设为 true 则模拟已吊销证书

[[certs]]
name = "已吊销测试证书"
path = "certs/revoked_cert.der"
revoked = true           # 触发 0x01000004 证书已吊销

[trust_anchor]
ca_cert_path = "certs/root_ca.der"   # 信任锚点 CA

[crl]
enable = true
crl_path = "certs/test.crl"          # 本地 CRL 文件路径

[ocsp]
enable_mock = true       # 启用内置 OCSP 模拟器
```

---

## 5. 与 SKF/SDF 联动排查

SVS 签名验签服务通常依赖 SKF（设备层）和 SDF（运算层）共同完成端到端流程，当 SVS 返回错误时，应结合下游服务日志综合排查。

### 5.1 完整签名流程（联动示意）

```
客户端
  │
  ├─ 1. SKF Mock (GM/T 0016)
  │      SKF_VerifyPIN       → 验证用户 PIN
  │      SKF_ECCSignData     → 使用设备内私钥签名
  │                            ↓ 返回签名值 signature
  │
  ├─ 2. SDF Mock (GM/T 0018)  [可选，直接软件签名]
  │      SDF_InternalSign_ECC → SM2 签名运算
  │                            ↓ 返回签名值 signature
  │
  └─ 3. SVS Mock (GM/T 0029)  ← 当前文档
         /svs/v1/verify       → 验证证书有效性 + 签名值
```

### 5.2 联动错误排查矩阵

| SVS 返回错误 | 可能的根源层 | 排查方向 |
|-------------|-------------|----------|
| `0x01000006` 签名值错误 | SKF 或 SDF 层 | 检查 SKF `SAR_FAIL` / SDF `SDR_SIGNERR` 日志；确认签名数据未经二次编码 |
| `0x01000003` 证书不可信 | 证书配置问题 | 检查 `mock_certs.toml` 中 CA 配置；确认证书由正确 CA 签发 |
| `0x01000004` 证书已吊销 | Mock 配置 | 检查 `mock_certs.toml` 中 `revoked = true` 字段 |
| `0x01000002` 参数错误 | 客户端代码 | 检查 SKF/SDF 返回的签名格式是否需要转换后才能传入 SVS |
| `0x01000001` 内部错误 | SDF 层故障 | 确认 SDF Mock 服务正在运行且 SM2 密钥已生成 |

### 5.3 完整联动调试命令

开启所有三个服务的详细日志（在三个终端分别运行）：

```bash
# 终端 1：SKF Mock
cd /path/to/0016-skf-mock
RUST_LOG=debug cargo run

# 终端 2：SDF Mock
cd /path/to/0018-sdf-mock
RUST_LOG=debug cargo run

# 终端 3：SVS Mock
cd /path/to/0029-svs-mock
RUST_LOG=debug cargo run
```

或通过 Docker Compose 统一启动（推荐）：

```bash
cd /path/to/mp-mock
docker-compose up
```

---

## 6. 常见问题

### Q1：所有请求均返回 `400 Bad Request`

```
原因：请求 JSON 格式错误
排查：
  1. 使用 json.tool 或 jq 验证 JSON 合法性
  2. 确认 Content-Type 头部为 application/json
  3. 检查 Base64 字符串中是否包含了换行符（PEM 格式）
     修复：cat cert.pem | grep -v "^---" | tr -d '\n'
```

### Q2：`0x01000008` Base64 解码失败

```
常见错误输入：
  ❌ -----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----
  ❌ data:application/x-x509-ca-cert;base64,MIIB...
  ✅ MIIB...（纯 Base64，无头尾，无换行）

修复命令：
  openssl x509 -in cert.pem -outform DER | base64 | tr -d '\n'
```

### Q3：`0x01000005` 证书已过期，但证书看起来有效

```
检查 Mock 服务的系统时间：
  date

检查证书有效期：
  echo "<cert_base64>" | base64 -d | openssl x509 -inform DER -noout -dates

如果测试证书确实已过期，生成新测试证书：
  cargo run --example gen_test_certs
```

### Q4：`0x0100000B` OCSP 查询失败

```
Mock 环境下不应依赖外网 OCSP，解决方案：

方案 A：在 mock_certs.toml 中禁用 OCSP 检查
  [ocsp]
  enable_mock = false

方案 B：启用内置 OCSP 模拟器（推荐）
  [ocsp]
  enable_mock = true

方案 C：在请求参数中跳过 OCSP 检查
  {"skip_ocsp": true, ...}  （具体字段名见 API 文档）
```

### Q5：签名验签失败，但我确定签名是正确的

```
检查清单：
  □ 签名算法是否为 SM2withSM3（而非 SM2withSHA256）？
  □ 原始数据是否经过哈希预处理后再传入？
    （SVS 通常期望传入原文，内部做 SM3 哈希，而 SDF 层可能已做过哈希）
  □ SM2 签名的 ASN.1 DER 格式（R||S）vs 原始字节格式是否一致？
  □ 证书公钥与签名时使用的私钥是否配对？
```

---

## 7. 错误码十六进制/十进制对照表（完整）

| 十六进制 | 十进制 | 含义 |
|---------|--------|------|
| `0x00000000` | `0` | 成功 |
| `0x01000001` | `16777217` | 内部错误 |
| `0x01000002` | `16777218` | 参数错误 |
| `0x01000003` | `16777219` | 证书不可信 |
| `0x01000004` | `16777220` | 证书已吊销 |
| `0x01000005` | `16777221` | 证书已过期 |
| `0x01000006` | `16777222` | 签名值错误 |
| `0x01000007` | `16777223` | 时间戳错误 |
| `0x01000008` | `16777224` | Base64 解码失败 |
| `0x01000009` | `16777225` | 不支持的算法 |
| `0x0100000A` | `16777226` | CRL 获取失败 |
| `0x0100000B` | `16777227` | OCSP 查询失败 |

---

*文档版本：1.0 | 更新日期：2026-04-14*
