# GM/T 0029-2014 签名验签服务器模拟服务 (SVS Mock)

基于 Rust + axum 开发的 GM/T 0029-2014 签名验签服务器（SVS）纯软件模拟服务，以 JSON over HTTP 形式对外提供服务，URL 路径与字段名与真实设备完全一致。支持国密证书导入、外部证书验签、数字信封、SM3 摘要等主要功能。

## 功能特性

- ✅ **标准 SVS 接口**：完全按照 GM/T 0029-2014 规范实现 HTTP 接口
- ✅ **国密算法支持**：SM2 签名/验签、SM3 哈希、数字信封（SM2 加密 + SM4 加密）
- ✅ **证书管理**：支持导入国密证书，内置证书存储
- ✅ **外部证书验签**：支持使用外部证书进行签名验证
- ✅ **数字信封**：支持 SM2 加密会话密钥 + SM4 加密数据
- ✅ **SM3 摘要**：支持计算数据的 SM3 哈希值
- ✅ **跨平台**：支持 Windows、Linux、macOS
- ✅ **配置灵活**：通过 `mock_certs.toml` 配置预置证书

## 技术栈

- **语言**：Rust 1.75+
- **Web 框架**：axum 0.7
- **异步运行时**：tokio
- **国密算法**：libsmx 0.3
- **证书处理**：x509-cert 0.2
- **序列化**：serde + serde_json
- **配置**：toml 0.8

## 快速开始

### 1. 构建项目

```bash
# 编译检查
cargo check

# 构建可执行文件
cargo build --release

# 运行服务
cargo run --release
```

### 2. 配置证书

编辑 `mock_certs.toml` 文件，添加预置证书：

```toml
# 设备证书
[device_cert]
pem = """
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"""

# 可信根证书
[[trusted_certs]]
pem = """
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"""
```

### 3. 启动服务

```bash
# 默认端口：3000
cargo run --release

# 自定义端口
PORT=8080 cargo run --release
```

服务启动后，可通过 `http://localhost:3000` 访问。

## API 接口

### 证书管理

| 接口 | 方法 | 功能 |
|------|------|------|
| `/SVS/ImportCert` | POST | 导入证书 |
| `/SVS/DeleteCert` | POST | 删除证书 |
| `/SVS/ListCert` | POST | 列出证书 |

### 签名验证

| 接口 | 方法 | 功能 |
|------|------|------|
| `/SVS/VerifySign` | POST | 验证签名 |
| `/SVS/VerifySignByCert` | POST | 使用外部证书验证签名 |

### 数字信封

| 接口 | 方法 | 功能 |
|------|------|------|
| `/SVS/CreateEnvelope` | POST | 创建数字信封 |
| `/SVS/OpenEnvelope` | POST | 打开数字信封 |

### 摘要计算

| 接口 | 方法 | 功能 |
|------|------|------|
| `/SVS/SM3` | POST | 计算 SM3 摘要 |

### 其他接口

| 接口 | 方法 | 功能 |
|------|------|------|
| `/SVS/Hello` | POST | 测试接口 |
| `/SVS/ChangeAuthKey` | POST | 修改认证密钥（Stub） |

## 请求/响应格式

所有接口均使用 JSON 格式，示例：

### 验证签名请求

```json
{
  "CertID": "cert1",
  "Data": "SGVsbG8gV29ybGQ=",
  "Signature": "MEUCIG...",
  "SignAlg": "1.2.156.10197.1.501"
}
```

### 验证签名响应

```json
{
  "Result": 0,
  "Message": "验证成功"
}
```

## 项目结构

```
0029-svs-mock/
├── Cargo.toml
├── LICENSE
├── README.md
├── mock_certs.toml       # 证书配置
├── examples/             # 示例代码
│   └── gen_test_data.rs  # 测试数据生成
└── src/
    ├── main.rs           # 服务入口
    ├── config.rs         # 配置解析
    ├── cert_store.rs     # 证书存储
    ├── error.rs          # 错误处理
    ├── routes/           # HTTP 路由
    │   ├── cert.rs       # 证书管理接口
    │   ├── sign.rs       # 签名验证接口
    │   ├── envelope.rs   # 数字信封接口
    │   ├── digest.rs     # 摘要计算接口
    │   ├── stub.rs       # 未实现接口
    │   └── mod.rs        # 路由汇总
    └── service/          # 业务逻辑
        ├── cert_ops.rs   # 证书操作
        ├── cms_ops.rs    # CMS 操作
        ├── crypto_ops.rs # 密码学操作
        └── mod.rs        # 服务汇总
```

## 开发指南

### 运行测试

```bash
# 运行测试
cargo test

# 查看详细日志
RUST_LOG=debug cargo run --release
```

### 生成测试数据

```bash
cargo run --example gen_test_data
```

### 配置文件

**`mock_certs.toml`** 支持以下配置：
- `device_cert`：设备证书（PEM 格式）
- `trusted_certs`：可信根证书列表（PEM 格式）

### 环境变量

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `PORT` | 3000 | 服务监听端口 |
| `HOST` | 127.0.0.1 | 服务监听地址 |
| `RUST_LOG` | info | 日志级别（debug, info, warn, error） |

## 技术实现

### 证书存储
- 使用内存哈希表存储导入的证书
- 支持按证书 ID 和主题查找证书
- 启动时从 `mock_certs.toml` 加载预置证书

### 签名验证
- 支持 SM2 签名验证
- 支持使用内置证书和外部证书验证
- 实现 GM/T 0009-2012 数字签名算法

### 数字信封
- 实现 GM/T 0010-2012 数字信封格式
- 使用 SM2 加密会话密钥
- 使用 SM4 加密数据（支持 ECB 模式）

### 摘要计算
- 实现 GM/T 0004-2012 SM3 哈希算法
- 支持处理 base64 编码的数据

## 与真实 SVS 设备的差异

- **无硬件依赖**：纯软件实现，无需真实 SVS 硬件设备
- **性能优化**：内存操作，响应速度快
- **配置灵活**：通过配置文件管理证书
- **开发友好**：提供详细日志和错误信息
- **部分接口**：某些高级功能可能为 Stub 实现

## 依赖

- [axum](https://crates.io/crates/axum)：Web 框架
- [tokio](https://crates.io/crates/tokio)：异步运行时
- [libsmx](https://crates.io/crates/libsmx)：国密算法库
- [x509-cert](https://crates.io/crates/x509-cert)：X.509 证书处理
- [serde](https://crates.io/crates/serde)：序列化/反序列化
- [toml](https://crates.io/crates/toml)：配置文件解析

## 许可证

本项目基于 [Apache License 2.0](LICENSE) 开源。

> **⚠️ 警告**：本项目**仅供学习和开发测试使用**。配置文件中的示例证书为公开测试值，**严禁用于生产环境**。

## 参考资料

- GM/T 0029-2014 签名验签服务器技术规范
- GM/T 0004-2012 SM3 密码杂凑算法
- GM/T 0009-2012  SM2 椭圆曲线公钥密码算法
- GM/T 0010-2012  SM2 密码算法使用规范
- [libsmx 文档](https://docs.rs/libsmx/)
- [axum 文档](https://docs.rs/axum/)