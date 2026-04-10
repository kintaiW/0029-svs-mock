# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目简介

GM/T 0029-2014 签名验签服务器（SVS）的纯软件模拟服务。基于 Rust + axum，以 JSON over HTTP 形式对外提供服务，URL 路径与字段名与真实设备（纽创信安 XC-M30W）完全一致。支持国密证书导入、外部证书验签、数字信封、SM3 摘要等主要功能。

参考规范：
- `docs/0029-2014签名验签服务器技术规范.pdf`（标准规范）
- `docs/纽创信安XC-M30W签名验签接口协议.docx`（真实设备接口文档）

对标真实设备：192.168.177.20

## 常用命令

```bash
# 编译检查
cargo check

# 构建
cargo build

# 运行（默认端口 9000，需要 mock_certs.toml 在 CWD 下）
cargo run

# 指定配置文件路径
SVS_MOCK_CONFIG=/path/to/mock_certs.toml cargo run

# 生成测试证书和密钥（输出粘贴到 mock_certs.toml）
cargo run --example gen_test_data
```

## 架构分层

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

### 路由层 `src/routes/`

每个路由文件定义一组相关接口，使用 `axum::Router` + `post()` 注册，共享 `Arc<CertStore>` 作为状态。请求体为 JSON，反序列化为 `#[derive(Deserialize)]` 的 Rust 结构体。响应统一使用 `resp_ok()` / `resp_err(code)` / `resp_ok_with(data)` 辅助函数构造 JSON。

| 文件 | 接口 |
|------|------|
| `cert.rs` | ExportCert, ValidateCert, ParseCert |
| `digest.rs` | Digest |
| `envelope.rs` | envelopeEnc, envelopeDec |
| `sign.rs` | SignData, SignMessage |
| `verify.rs` | VerifySignedData, VerifySignedMessage |
| `stub.rs` | 12 个多包接口 stub（全部返回 ERR_INTERNAL = 0x0400000e） |

### 业务逻辑层 `src/service/`

| 文件 | 职责 |
|------|------|
| `crypto_ops.rs` | SM2 签名/验签（含 DER r‖s 编解码）、SM3 摘要（含 Z 值）、SM4-CBC 数字信封加解密（含手工 PKCS7 pad/unpad） |
| `cert_ops.rs` | 证书有效期验证、信任锚验签、ParseCert 字段提取（9 种 infoType） |
| `cms_ops.rs` | 手工 DER 序列化/反序列化 CMS SignedData（不依赖外部 CMS crate） |

### 证书/密钥存储 `src/cert_store.rs`

`CertStore` 在启动时从 `AppConfig` 构建，运行时只读：
- `trusted_roots: Vec<Vec<u8>>` — 可信根证书 DER 列表
- `subject_index: HashMap<String, Vec<u8>>` — subject DER base64 → 证书 DER
- `serial_index: HashMap<String, Vec<u8>>` — 序列号 hex(小写) → 证书 DER
- `signing_keys: HashMap<u32, SigningKey>` — keyIndex → 签名密钥配置
- `enc_keys: HashMap<u32, EncKey>` — keyIndex → 加密密钥配置

`find_cert(cert_id)` 优先按 subject base64 查找，再按 serial hex 查找。

## 接口清单（22个端点）

### 通用接口（6个，全部实现）
- `POST /ExportCert` — 按 subject(b64) 或 SN(hex) 导出证书
- `POST /ValidateCert` — 有效期 + 信任锚验签
- `POST /ParseCert` — 按 infoType 解析证书字段（支持 1/2/5/6/7/8/0x31/0x35/0x36）
- `POST /Digest` — SM3 摘要，支持 publicKey+userId 前置 Z 值
- `POST /envelopeEnc` — SM2+SM4 数字信封加密
- `POST /envelopeDec` — SM2+SM4 数字信封解密

### 单包签名/验签（4个，全部实现）
- `POST /SignData` — P1 签名（SM2，DER 编码 r‖s）
- `POST /VerifySignedData` — P1 验签
- `POST /SignMessage` — PKCS7/CMS SignedData 签名
- `POST /VerifySignedMessage` — PKCS7/CMS SignedData 验签

### 多包接口（12个，全部 stub）
- SignDataInit/Update/Final
- VerifySignedDataInit/Update/Final
- SignMessageInit/Update/Final
- VerifySignedMessageInit/Update/Final

全部返回 `{"respValue": 67108878}`（ERR_INTERNAL = 0x0400000e）。

## 错误码

| 值 | 常量名 | 说明 |
|----|--------|------|
| 0 | GM_SUCCESS | 成功 |
| 0x04000001 | ERR_CERT_ID | 错误的证书标识 |
| 0x04000004 | ERR_ALG_ID | 签名算法类型错误 |
| 0x04000005 | ERR_KEY_INDEX | 私钥索引值错误 |
| 0x04000006 | ERR_KEY_AUTH | 权限标识码(PIN)错误 |
| 0x04000007 | ERR_CERT_INVALID | 证书非法或不存在 |
| 0x04000008 | ERR_CERT_DECODE | 证书解码错误 |
| 0x04000009 | ERR_CERT_EXPIRED | 证书过期 |
| 0x0400000a | ERR_CERT_NOT_YET | 证书尚未生效 |
| 0x0400000b | ERR_CERT_REVOKED | 证书已被吊销（保留） |
| 0x0400000c | ERR_SIG_INVALID | 签名无效 |
| 0x0400000d | ERR_DATA_FORMAT | 数据格式错误 |
| 0x0400000e | ERR_INTERNAL | 系统内部错误 |
| 0x0400000f | ERR_CRYPTO | 密码运算错误 |
| 0x04000010 | ERR_PARAM | 输入参数错误 |

## 配置文件

`mock_certs.toml`，查找优先级：环境变量 `SVS_MOCK_CONFIG` → 当前工作目录。

```toml
[server]
port = 9000
log_level = "info"

[[trusted_roots]]
name = "test root"
cert = "<DER base64>"

[[signing_keys]]
index = 1
pin = "12345678"
private_key = "<32字节私钥 hex>"
cert = "<对应签名证书 DER base64>"

[[enc_keys]]
index = 1
private_key = "<32字节私钥 hex>"
cert = "<对应加密证书 DER base64>"
```

## 关键设计决策

- **签名算法标识**：SGD_SM3_SM2 = 0x00020201（131585），与真实设备一致
- **SM2 userId**：固定使用 `DEFAULT_USER_ID = b"1234567812345678"`（16字节）
- **CMS 构建**：手工 DER TLV 编码，不引入重量级 CMS crate
- **SM4-CBC padding**：libsmx 的 `sm4_encrypt_cbc` / `sm4_decrypt_cbc` **不处理 PKCS7 padding**，需在 `crypto_ops.rs` 中手工 `pkcs7_pad()` / `pkcs7_unpad()`
- **证书验证**：仅做有效期 + 信任锚比对，不做 CRL/OCSP
- **多包接口**：全部 stub，返回 ERR_INTERNAL

## 依赖说明

- **libsmx 0.3**：SM2/SM3/SM4 纯 Rust 算法库
  - SM2：`sm2::sign_message()`, `sm2::verify_message()`, `sm2::encrypt()`, `sm2::decrypt()`, `sm2::generate_keypair()`, `sm2::get_z()`, `sm2::get_e()`, `sm2::PrivateKey`（公钥为 `[u8; 65]`，无独立 PublicKey struct）
  - SM3：`sm3::Sm3Hasher::digest()`
  - SM4：`sm4::sm4_encrypt_cbc()`, `sm4::sm4_decrypt_cbc()`（不含 padding）
- **x509-cert 0.2 + der 0.7**：X.509 证书 DER 解析（需 `use der::{Decode, Encode}`）
- **axum 0.7**：HTTP 框架
- **chrono**：证书有效期时间比较

## 测试

当前未配置自动化测试套件。冒烟测试通过 curl 执行（19/19 PASS），覆盖所有接口类别和错误条件。

```bash
# 冒烟测试示例（需先 cargo run 启动服务）
# SignData
curl -s -X POST http://127.0.0.1:9000/SignData \
  -H "Content-Type: application/json" \
  -d '{"keyIndex":1,"keyValue":"12345678","inData":"aGVsbG8="}'

# Digest
curl -s -X POST http://127.0.0.1:9000/Digest \
  -H "Content-Type: application/json" \
  -d '{"inData":"aGVsbG8="}'
```

## Standard Rules
1. Always answer my question in Simplified Chinese.
## Standard Workflow
1. First think through the problem, read the codebase for relevant files, and write a plan to projectplan.md.
2. The plan should have a list of todo items that you can check off as you complete them
3. Before you begin working, check in with me and I will verify the plan.
4. Then, begin working on the todo items, marking them as complete as you go.
5. Please every step of the way just give me a high level explanation of what changes you made
6. Make every task and code change you do as simple as possible. We want to avoid making any massive or complex changes. Every change should impact as little code as possible. Everything is about simplicity.
7. Finally, add a review section to the projectplan.md file with a summary of the changes you made and any other relevant information.
## Documentation & Explainability
1. Update README.md when new features are added, dependencies change, or setup steps are modified.
2. Comment non-obvious code and ensure everything is understandable to a mid-level developer.
3. When writing complex logic, add an inline # Reason: comment explaining the why, not just the what.
## AI Behavior Rules
1. Never assume missing context. Ask questions if uncertain.
2. Never hallucinate libraries or functions – only use known, verified packages.
3. Always confirm file paths and module names exist before referencing them in code or tests.
4. Never delete or overwrite existing code unless explicitly instructed to or if part of a task from TASK.md.
## Code Quality & Standards
1. Follow PEP 8 for Python code style.
2. Use type annotations for all functions and methods.
3. Use version control (e.g., Git) for collaborative development.
