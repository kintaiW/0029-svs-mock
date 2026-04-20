# GM/T 0029 签名验签服务器模拟 - 设计与开发执行计划

## 一、项目概述

**目标**：基于 Rust + axum 开发 GM/T 0029-2014 签名验签服务器（SVS）的纯软件模拟服务，以 JSON over HTTP 形式对外提供服务，URL 路径与字段名与真实设备（纽创信安 XC-M30W）完全一致，支持国密证书导入、外部证书验签、数字信封、SM3 摘要等主要功能。

**参考文档**：
- `docs/0029-2014签名验签服务器技术规范.pdf`（标准规范）
- `docs/纽创信安XC-M30W签名验签接口协议.docx`（真实设备接口文档）

**对标真实设备**：<your-svs-ip>（可用于集成测试对比）

**技术栈**：Rust 1.75+，axum，libsmx 0.3.0，x509-cert，tokio

---

## 二、整体架构设计

```
HTTP 客户端（密评工具 / 应用系统）
        ↓  JSON POST 请求
┌──────────────────────────────────────┐
│  axum 路由层 (src/routes/)            │
│  职责：参数反序列化、错误映射、JSON 响应  │
├──────────────────────────────────────┤
│  业务逻辑层 (src/service/)            │
│  职责：证书解析、签名/验签、摘要、信封   │
├──────────────────────────────────────┤
│  证书/密钥存储层 (src/cert_store.rs)  │
│  职责：内存存储 trusted roots + 签名密钥 │
├──────────────────────────────────────┤
│  配置层 (src/config.rs)               │
│  职责：加载 mock_certs.toml           │
└──────────────────────────────────────┘
```

**关键设计决策**：
- API 格式：JSON（不用标准的 form-urlencoded）
- 证书验证范围：有效期 + 信任锚比对（不做真实 CRL/OCSP）
- 签名算法：SGD_SM3_SM2 = 0x00020201（131585），与真实设备一致
- SM2 userId：固定使用 DEFAULT_ID = "1234567812345678"（16字节）
- 多包接口（12个）：全部 stub，返回错误码 0x0400000e

---

## 三、接口清单

### 3.1 通用接口（6个）
| 路径 | 功能 | 实现方式 |
|------|------|---------|
| POST /ExportCert | 导出证书 | 按 subject(b64) 或 SN(hex) 查表返回 DER |
| POST /ValidateCert | 验证证书有效性 | 有效期 + 信任锚验签（忽略 ocsp 字段）|
| POST /ParseCert | 解析证书信息 | 按 infoType 提取证书字段 |
| POST /envelopeEnc | 数字信封加密 | SM2 加密随机 SM4 密钥，SM4-CBC 加密数据 |
| POST /envelopeDec | 数字信封解密 | SM2 解密 SM4 密钥，SM4-CBC 解密数据 |
| POST /Digest | 计算 SM3 摘要 | 支持 publicKey+userId 前置 Z 值计算 |

### 3.2 单包签名/验签（4个）
| 路径 | 功能 | 实现方式 |
|------|------|---------|
| POST /SignData | P1 签名 | 用内部密钥对 SM2 签名，输出 DER 格式 r||s |
| POST /VerifySignedData | P1 验签 | 用证书公钥验证 SM2 签名 |
| POST /SignMessage | PKCS7 签名 | 生成 CMS SignedData 结构 |
| POST /VerifySignedMessage | PKCS7 验签 | 解析并验证 CMS SignedData |

### 3.3 多包接口（12个，全部 stub）
- /SignDataInit, /SignDataUpdate, /SignDataFinal
- /VerifySignedDataInit, /VerifySignedDataUpdate, /VerifySignedDataFinal
- /SignMessageInit, /SignMessageUpdate, /SignMessageFinal
- /VerifySignedMessageInit, /VerifySignedMessageUpdate, /VerifySignedMessageFinal

---

## 四、配置文件设计

### 4.1 mock_certs.toml（新增）

```toml
# SVS Mock 证书与密钥配置

[server]
port = 9000                          # 监听端口
log_level = "info"                   # debug / info / warn / error

# 可信根证书列表（DER base64 编码）
[[trusted_roots]]
name = "sm2 osr ca"
cert = "MIIC..."                     # DER base64

# 签名密钥对（用于 SignData / SignMessage）
# keyIndex 对应接口参数中的 keyIndex，keyValue 为 PIN 码
[[signing_keys]]
index = 1
pin = "12345678"
private_key = "3945208F..."          # 32字节私钥 hex
cert = "MIIC..."                     # 对应的签名证书 DER base64

# 加密密钥对（用于 envelopeDec）
[[enc_keys]]
index = 1
private_key = "56B96C94..."          # 32字节私钥 hex
cert = "MIIC..."                     # 对应的加密证书 DER base64
```

**配置文件查找优先级**（从高到低）：
1. 环境变量 `SVS_MOCK_CONFIG` 指定的绝对路径
2. 当前工作目录 `mock_certs.toml`

---

## 五、错误码定义

| 错误码 | 常量名 | 说明 |
|--------|--------|------|
| 0 | GM_SUCCESS | 成功 |
| 0x04000001 | ERR_CERT_ID | 错误的证书标识 |
| 0x04000004 | ERR_ALG_ID | 签名算法类型错误 |
| 0x04000005 | ERR_KEY_INDEX | 私钥索引值错误 |
| 0x04000006 | ERR_KEY_AUTH | 权限标识码错误 |
| 0x04000007 | ERR_CERT_INVALID | 证书非法或不存在 |
| 0x04000008 | ERR_CERT_DECODE | 证书解码错误 |
| 0x04000009 | ERR_CERT_EXPIRED | 证书过期 |
| 0x0400000a | ERR_CERT_NOT_YET | 证书尚未生效 |
| 0x0400000b | ERR_CERT_REVOKED | 证书已被吊销 |
| 0x0400000c | ERR_SIG_INVALID | 签名无效 |
| 0x0400000d | ERR_DATA_FORMAT | 数据格式错误 |
| 0x0400000e | ERR_INTERNAL | 系统内部错误 |
| 0x0400000f | ERR_CRYPTO | 密码运算错误 |
| 0x04000010 | ERR_PARAM | 输入参数错误 |

---

## 六、开发阶段划分

### 阶段 1：项目骨架搭建
**交付物**：可编译的 Cargo 项目，基本目录结构

- [x] 1.1 初始化 Cargo 项目（`cargo init`），配置 Cargo.toml 依赖
- [x] 1.2 创建模块目录结构（`routes/`, `service/`）
- [x] 1.3 定义错误码常量（`src/error.rs`）
- [x] 1.4 实现 JSON 响应辅助函数（`resp_ok`, `resp_err`）
- [x] 1.5 设计并实现 `mock_certs.toml` 格式与解析（`src/config.rs`）
- [x] 1.6 搭建 axum 主程序入口（`src/main.rs`），注册路由占位

### 阶段 2：证书存储模块
**交付物**：内存证书/密钥仓库，支持查表与验证

- [x] 2.1 实现 `CertStore`（`src/cert_store.rs`）：存储根证书 + 签名密钥 + 加密密钥
- [x] 2.2 实现证书索引：subject(DER base64) → DER bytes，SN(hex) → DER bytes
- [x] 2.3 实现有效期验证函数（对比当前系统时间）
- [x] 2.4 实现信任锚验证函数（用根证书公钥验证叶证书签名）

### 阶段 3：通用证书接口
**交付物**：ExportCert / ValidateCert / ParseCert 三个接口

- [x] 3.1 实现 `POST /ExportCert`：按 subject 或 SN 查表返回 cert
- [x] 3.2 实现 `POST /ValidateCert`：有效期 + 信任锚检查，返回 state
- [x] 3.3 实现 `POST /ParseCert`：按 infoType 解析证书字段
  - infoType 支持范围：1(version), 2(serial), 5(issuer), 6(validity), 7(subject), 8(pubkey), 0x31(subject CN), 0x35(notbefore), 0x36(notafter)

### 阶段 4：摘要与数字信封接口
**交付物**：Digest / envelopeEnc / envelopeDec 三个接口

- [x] 4.1 实现 `POST /Digest`：SM3 摘要，支持 publicKey+userId 前置 Z 值计算
- [x] 4.2 实现 `POST /envelopeEnc`：SM2+SM4 数字信封加密
  - 生成随机 SM4 密钥 → SM2 加密该密钥 → SM4-CBC 加密原文 → 组装 CMS EnvelopedData
- [x] 4.3 实现 `POST /envelopeDec`：SM2+SM4 数字信封解密
  - 解析 CMS EnvelopedData → SM2 解密 SM4 密钥 → SM4-CBC 解密密文

### 阶段 5：单包签名/验签接口
**交付物**：SignData / VerifySignedData / SignMessage / VerifySignedMessage 四个接口

- [x] 5.1 实现 `POST /SignData`（P1 签名）
  - 验证 keyIndex + keyValue（PIN）→ 计算 SM3 Z 值 → SM2 签名 → DER 编码 r||s
- [x] 5.2 实现 `POST /VerifySignedData`（P1 验签）
  - 获取证书公钥 → 计算 SM3 Z 值 → 验证 SM2 签名 → 执行证书有效性检查
- [x] 5.3 实现 `POST /SignMessage`（PKCS7/CMS 签名）
  - 构建 CMS SignedData：根据参数决定是否附加 originalText / certificateChain / crl
- [x] 5.4 实现 `POST /VerifySignedMessage`（PKCS7/CMS 验签）
  - 解析 CMS SignedData → 提取签名者证书 → 验证签名 → 验证证书有效性

### 阶段 6：多包接口 stub
**交付物**：12 个多包接口，全部返回错误码 0x0400000e

- [x] 6.1 实现 12 个 stub 路由（统一返回 `{"respValue": 67108878}`）
- [x] 6.2 注册至 axum 路由表

### 阶段 7：集成测试
**交付物**：与真实设备对比测试，验证 JSON 响应格式兼容

- [ ] 7.1 编写基本冒烟测试脚本（curl 测试各接口）
- [ ] 7.2 对比真实设备 <your-svs-ip> 的响应格式
- [ ] 7.3 编写 README.md
- [ ] 7.4 为 mock_certs.toml 配置真实测试证书（从真实设备导出）

---

## 七、项目目录结构

```
0029-svs-mock/
├── Cargo.toml
├── mock_certs.toml           # 证书与密钥配置
├── README.md
├── projectplan.md
└── src/
    ├── main.rs               # axum 入口，路由注册
    ├── config.rs             # mock_certs.toml 解析
    ├── cert_store.rs         # 内存证书/密钥仓库
    ├── error.rs              # 错误码常量 + JSON 响应辅助
    ├── routes/
    │   ├── mod.rs            # 路由汇总
    │   ├── cert.rs           # ExportCert, ValidateCert, ParseCert
    │   ├── digest.rs         # Digest
    │   ├── envelope.rs       # envelopeEnc, envelopeDec
    │   ├── sign.rs           # SignData, SignMessage
    │   ├── verify.rs         # VerifySignedData, VerifySignedMessage
    │   └── stub.rs           # 12个多包接口 stub
    └── service/
        ├── mod.rs
        ├── cert_ops.rs       # 证书操作：解析、验证、导出
        ├── crypto_ops.rs     # SM2/SM3/SM4 密码运算
        └── cms_ops.rs        # CMS SignedData 构建与解析
```

---

## 八、Cargo.toml 核心依赖

```toml
[package]
name = "svs-mock"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "svs-mock"
path = "src/main.rs"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
toml = "0.8"
libsmx = "0.3"
x509-cert = "0.2"
der = "0.7"
hex = "0.4"
chrono = "0.4"
tracing = "0.1"
tracing-subscriber = "0.3"
```

---

## 九、关键实现细节

### 9.1 SM2 签名流程（SignData）

```
输入：keyIndex, keyValue(PIN), inDataLen, inData(b64)
1. 验证 keyIndex 是否存在于 signing_keys
2. 验证 keyValue 与配置中的 pin 是否一致
3. 对 inData 进行 base64 解码得到原始字节
4. 计算 Z 值：SM3(entlen||DEFAULT_ID||curve_params||pubkey)
5. 计算最终摘要：SM3(Z || inData)
6. SM2 签名最终摘要，得到 (r, s)
7. DER 编码 (r, s) 为 SEQUENCE { INTEGER r, INTEGER s }
8. base64 编码返回
```

### 9.2 数字信封加密流程（envelopeEnc）

```
输入：certID(b64, 证书唯一标识), data(b64)
1. 按 certID 查找加密证书，提取 SM2 公钥
2. 生成随机 16 字节 SM4 密钥
3. 生成随机 16 字节 IV
4. SM4-CBC 加密原始数据（PKCS7 padding）
5. SM2 加密 SM4 密钥（得到 C1||C3||C2 格式密文）
6. 组装 CMS EnvelopedData（按实际设备格式）
7. DER 编码后 base64 返回
```

### 9.3 证书解析 infoType 支持列表

| infoType（十进制） | 常量 | 返回内容 |
|-----------------|------|---------|
| 1 | SGD_CERT_VERSION | 版本号（整数 base64） |
| 2 | SGD_CERT_SERIAL | 序列号（bytes base64） |
| 5 | SGD_CERT_ISSUER | 颁发者 DN（DER base64） |
| 6 | SGD_CERT_VALID_TIME | 有效期（两个时间字符串）|
| 7 | SGD_CERT_SUBJECT | 拥有者 DN（DER base64）|
| 8 | SGD_CERT_DER_PUBLIC_KEY | 公钥信息（DER base64） |
| 49(0x31) | SGD_CERT_SUBJECT_CN | 拥有者 CN 字符串 |
| 53(0x35) | SGD_CERT_NOTBEFORE_TIME | 起始时间 |
| 54(0x36) | SGD_CERT_NOTAFTER_TIME | 截止时间 |

---

## Review

### 完成情况（2026-04-09）

**阶段 1-6 全部完成**，项目可通过 `cargo check` 零错误编译。

**创建文件列表**：
- `Cargo.toml` — 依赖：axum 0.7, tokio, serde_json, libsmx 0.3, x509-cert 0.2, der 0.7, chrono, anyhow 等
- `src/main.rs` — axum 主入口，加载配置 → 构建 CertStore → 注册路由
- `src/config.rs` — TOML 配置解析（server / trusted_roots / signing_keys / enc_keys）
- `src/error.rs` — 错误码常量 + resp_ok / resp_err 辅助函数
- `src/cert_store.rs` — 内存证书仓库，subject/serial 双索引
- `src/service/cert_ops.rs` — 证书有效期验证、信任锚验签、ParseCert 字段提取
- `src/service/crypto_ops.rs` — SM2 签名/验签、SM3 摘要、SM4-CBC 数字信封
- `src/service/cms_ops.rs` — 手工 DER 序列化/反序列化 CMS SignedData
- `src/routes/cert.rs` — ExportCert / ValidateCert / ParseCert
- `src/routes/digest.rs` — Digest
- `src/routes/envelope.rs` — envelopeEnc / envelopeDec
- `src/routes/sign.rs` — SignData / SignMessage
- `src/routes/verify.rs` — VerifySignedData / VerifySignedMessage
- `src/routes/stub.rs` — 12 个多包接口 stub（返回 ERR_INTERNAL = 0x0400000e）
- `mock_certs.toml` — 配置文件示例（注释掉，待填真实证书）

**关键设计决策**：
- libsmx 0.3 API 与 plan 中描述有差异，实际用 `sign_message`/`verify_message` 代替 `sign_with_z`/`verify_with_z`
- CMS 构建采用手工 DER TLV 编码，避免引入重量级 CMS crate
- SM4-CBC 由 libsmx 内部处理 PKCS7 padding，不需要手工实现

**待完成**：
- 阶段 7：集成测试（需要真实设备证书配置后才能运行）

---

## 十、svsc 协议适配改造（方案 A，2026-04-20）

### 背景

svsc 客户端采用 **form-urlencoded + 自定义字段命名 + 特定请求头**，与本 mock 现有的 JSON API 不兼容。本次改造把 mock 对外契约**全面向 svsc 对齐**，以便两项目直接联调。原则：**改动最小、逐接口替换、多包接口继续保持 stub 不实现**。

### 改造策略（关键决策）

1. **双协议协商**：根据请求 `Content-Type` 分流——
   - `application/x-www-form-urlencoded` → 按 form 解析，响应也用 form-urlencoded。
   - 其它（含缺省、`application/json`）→ 按 JSON 解析，响应用 JSON（**默认分支**）。
   - 实现方式：在每个 handler 入口用自定义 extractor（见 A1.1）根据 `Content-Type` header 分发；handler 内部拿到的永远是同一个 Rust struct，响应同样通过自定义 responder 按请求协议回写。
2. **字段命名统一向 svsc 对齐**（`identification`/`cert`/`signature`/`digest`/`signMethod`/… 等）。理由：
   - 真实商用 SVS 字段名与 svsc 一致，mock 对齐更贴近实物。
   - 两协议用同一套 DTO，避免双字段 struct 维护成本翻倍。
   - 旧 JSON 契约（`certID`/`certContent`/`signData` 等）**整体退役**；JSON 支持仅保留"协议壳"，字段名不兼容旧版。
3. **请求头**`SVS-Request-Version` / `SVS-Request-Time` **只读不校验**（兼容即可，不阻塞）。
4. **`envelopedData` 单字段打包**：mock 内部仍用 `encryptedKey/encryptedData/iv` 三件套，但对外用 `base64(JSON{encryptedKey, encryptedData, iv})` 组合，Dec 时反向解包。因 svsc 只做回灌，不关心内部结构。
5. **`envelopeDec` 由 `certID` 定位私钥**：新增 cert_store 反查方法，把 `certID` → `enc_keys` 里对应 index。
6. **错误码**：mock 现有 `0x04xxxxxx` 体系保持不变，svsc 只校验 0/非0。
7. **多包接口**：保持 stub 返回 `0x0400000e`，响应格式也走双协议协商。

### 字段映射总表

| 接口 | 请求字段改动 | 响应字段改动 |
|---|---|---|
| `/ExportCert` | `certID` → `identification` | `certContent` → `cert` |
| `/ValidateCert` | `certContent` → `cert`；新增 `ocsp`（TRUE/FALSE，读后忽略）；删 `verifyLevel` | `state` 保持 |
| `/ParseCert` | `certContent` → `cert`；`infoType` 保持 | 所有动态字段 → 统一放进 `info` 字符串（按 infoType 取主值） |
| `/Digest` | `algID` → `algId`；`userID` → `userId` | `hashData` → `digest` |
| `/SignData` | `algID` → `signMethod`；新增 `inDataLen`（读后忽略） | `signData` → `signature` |
| `/VerifySignedData` | 新增 `type`（1=cert / 2=certSN）；`certContent` → `cert`；新增 `certSN`；`signData` → `signature`；`verifyFlag` → `verifyLevel`；新增 `inDataLen` | 仅 `respValue` |
| `/SignMessage` | 新增 `signMethod`、`inDataLen`、`hashFlag`、`originalText`、`certificateChain`、`crl`、`authenticationAttributes`（均 TRUE/FALSE）；删 `signatureType`、`certType` | `signData` → `signedMessage` |
| `/VerifySignedMessage` | `signData` → `signedMessage`；新增 `inDataLen`、`hashFlag`、`originalText`、`certificateChain`、`crl`、`authenticationAttributes` | 仅 `respValue`（去掉 `outData`、`certContent`） |
| `/envelopeEnc` | `inData` → `data` | `encryptedKey`+`encryptedData`+`iv` → 合并为 `envelopedData` |
| `/envelopeDec` | 请求改为 `certID` + `envelopedData`（删 `keyIndex`/三件套） | `outData` → `data` |
| 12 个 multi-part stub | 仅接 form 请求 | 返回 `respValue=67108878`（form） |

### Todo 清单

#### 阶段 A1：公共基础（双协议协商）
- [x] A1.1 新建 `src/proto.rs`：
  - 定义 `enum Wire { Json, Form }`，封装 `Content-Type` 判定（缺省/`application/json` → Json；含 `application/x-www-form-urlencoded` → Form）。
  - 实现 `struct Payload<T>(pub T, pub Wire)` 作为 axum extractor，`FromRequest` 内部分支：Form 分支用 `axum::extract::Form<T>`，JSON 分支用 `axum::extract::Json<T>`。
  - 实现 `struct Reply(pub serde_json::Value, pub Wire)` 作为响应类型，`IntoResponse` 内根据 Wire 选 JSON body 或 urlencoded body；Form 分支只允许扁平 `{key: string|number}` 对，遇嵌套按 `value.to_string()` 平铺（mock 当前所有响应都是扁平的，OK）。
- [x] A1.2 `src/error.rs`：现有 `resp_ok`/`resp_err`/`resp_ok_with` 继续返回 `serde_json::Value`，handler 组装成 `Reply(value, wire)` 即可复用。
- [x] A1.3 `Cargo.toml`：新增 `serde_urlencoded = "0.7"`（axum 已间接依赖，确认版本对齐）。
- [x] A1.4 `src/cert_store.rs`：新增 `find_enc_key_by_cert_id(&self, id: &str) -> Option<&EncKey>`，按 subject/SN 反查 enc_keys。

#### 阶段 A2：逐接口改造（10 个接口 + 12 个 stub）
所有 handler 通用模式：`async fn xxx(State, Payload(req, wire): Payload<XxxReq>) -> Reply { ... Reply(v, wire) }`。

- [x] A2.1 `/ExportCert`：`ExportCertReq { identification }`；响应 `cert`。
- [x] A2.2 `/ValidateCert`：`ValidateCertReq { cert, ocsp: Option<String> }`（`ocsp` 读后丢弃）；响应 `state`。
- [x] A2.3 `/ParseCert`：`ParseCertReq { cert, infoType }`；响应把原动态字段合并成单个 `info` 字符串（按 infoType 取主值，必要时 JSON 序列化复合字段为字符串）。
- [x] A2.4 `/Digest`：请求字段 `algId`、`userId`；响应 `digest`。
- [x] A2.5 `/SignData`：请求字段 `signMethod` 替代 `algID`；响应 `signature`。
- [x] A2.6 `/VerifySignedData`：新增 `type` 分支——`type=1` 使用 `cert`；`type=2` 使用 `certSN` → 调 `store.find_cert(&cert_sn_hex)` 取证书；字段 `signature`、`verifyLevel`。
- [x] A2.7 `/SignMessage`：请求字段 `signMethod`、`keyIndex`、`keyValue`、`inDataLen`、`inData`、`hashFlag`、`originalText`、`certificateChain`、`crl`、`authenticationAttributes`（TRUE/FALSE）；仅解析 `originalText`（decide detached）与 `certificateChain`（decide include_cert），其余读后忽略。响应字段 `signedMessage`。
- [x] A2.8 `/VerifySignedMessage`：字段 `signedMessage`、`inData`、其余多布尔读后忽略；响应只留 `respValue`。
- [x] A2.9 `/envelopeEnc`：请求字段 `certID`、`data`；响应把三件套 JSON 序列化后 base64 作为 `envelopedData`。
- [x] A2.10 `/envelopeDec`：请求字段 `certID` + `envelopedData`；base64 解码 + JSON 反序列化取出 ekey/edata/iv，通过 `find_enc_key_by_cert_id` 找私钥，沿用现有 `crypto_ops::envelope_dec`；响应字段 `data`。
- [x] A2.11 `src/routes/stub.rs`：`stub_handler` 改用 `Payload/Reply`，根据请求协议返回 `respValue=67108878`。

#### 阶段 A3：编译与冒烟
- [x] A3.1 `cargo check` 零错误。
- [x] A3.2 `cargo run` 启动，双协议各跑一轮：
  - JSON：`curl -H 'Content-Type: application/json' -d '{...}'` 验证默认分支。
  - Form：`curl --data-urlencode 'k=v'` 验证 svsc 路径。
  - 覆盖 3 个典型接口：`/ExportCert`、`/SignData`、`/envelopeEnc`→`/envelopeDec`（JSON & Form 均通过）。
- [x] A3.3 对接 svsc：`go test ./...` 全部通过（含 E2E 全链路 Step1-10），结果 `ok github.com/ccasa-project/svs-test`。

### 不做的事（范围边界）

- 不实现 12 个多包接口业务逻辑，继续 stub。
- 不改 CMS 结构，签名/验签内部逻辑维持现状。
- 不实现 OCSP / CRL，`ocsp` 字段只读不校验。
- 不保留旧 JSON 字段名（`certID`/`certContent`/`signData` 等）；JSON 协议支持保留，但字段统一用 svsc 命名。
- 不改 README.md 的接口说明（等 svsc 联调稳定再统一修 README）。

### 关键文件

- `0029-svs-mock/src/error.rs`（新增 form 响应辅助）
- `0029-svs-mock/src/cert_store.rs`（新增 `find_enc_key_by_cert_id`）
- `0029-svs-mock/src/routes/*.rs`（全部 extractor 和响应改造）
- `0029-svs-mock/Cargo.toml`（可能新增 `serde_urlencoded` 或等价库）

### 风险 / 待澄清

1. svsc 回传的 `envelopedData` 是由 mock 自己生成的（内部 JSON 格式），只要 Enc→Dec 闭环可解即可；**不保证**跨真实 SVS 设备互操作。
2. `/ParseCert` 的 `info` 字段合并方式会丢失 mock 现有的字段语义（如 `validity` 的起/止日期），svsc 当前测试只断言 `info != ""`，预期无影响，但需要在冒烟时确认。
3. `SignMessage` 的 5 个布尔开关语义映射是**约简**实现，与真实 SVS 语义不完全等价；svsc 测试未区分 CRL/authAttr，应该可通过。

---

## 十一、联调修复记录（2026-04-20）

运行 `go test ./...` 对接 svsc 发现并修复以下问题：

### 修复一：Form 双重 URL 编码
- **问题**：resty `SetFormData` 对已经 `urlEncodeB64` 过的值再次 `url.QueryEscape`，导致 `%3D` → `%253D`，mock 收到的 base64 字段无法解码（返回 ERR_PARAM）。
- **修复**：`src/proto.rs` Form extractor 在 `serde_urlencoded::from_str` 前先将 raw body 中的 `%25` 替换回 `%`，等效于一次预解码，恢复正确 base64。

### 修复二：ValidateCert state 值
- **问题**：mock 返回 `state=1` 表示有效，但 GM/T 0029 协议定义 `0=正常/1=吊销/2=未知`，测试断言 `state=0`。
- **修复**：`src/routes/cert.rs` `validate_cert` 改为成功时返回 `state=0`。

### 修复三：CMS 无附证书时 VerifySignedMessage 失败
- **问题**：`certificateChain=FALSE` 时 CMS 不含证书，`parse_and_verify_signed_data` 找不到签名者证书报错。
- **修复**：`src/service/cms_ops.rs` 新增 `fallback_certs` 参数；当 CMS 无证书时，从 SignerInfo 提取 serial，在 fallback 列表按 serial 匹配；`src/cert_store.rs` 新增 `all_cert_ders()`。

### 修复四：空输入校验
- **问题**：`inData/data` 为空时 mock 返回成功，但测试期望错误。
- **修复**：`src/routes/digest.rs`、`envelope.rs`、`sign.rs` 各加空字段检测，`sign.rs` 同时校验 `inDataLen` 与实际长度不匹配。

### 修复五：测试代码修复
- `svsc/svs_api_test.go` `TestApiExportCert` 改用 `SVS_TEST_IDENTIFICATION` env var 作为 happy path identification（原为硬编码真实设备证书 ID）。
- `TestApiRequiredHeaders` 两个 TODO 用例 `expectError` 改为 `false`（projectplan.md 明确决定 Header 只读不校验）。
