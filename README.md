# svs-mock — GM/T 0029-2014 Signature Verification Server

> Part of [gm-agent-stack](../gm-agent-stack/) — AI-native GM cryptography toolkit

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![GM/T](https://img.shields.io/badge/GM%2FT-0029--2014-red.svg)](docs/)
[![MCP](https://img.shields.io/badge/MCP-Streamable%20HTTP-green.svg)](http://localhost:9000/mcp)

Pure-software mock of the GM/T 0029-2014 Signature Verification Server (SVS). Runs as an HTTP service providing **JSON REST API and MCP Server** on the same port. No hardware required.

纯软件实现的 GM/T 0029-2014 签名验签服务器模拟，同端口同时提供 JSON REST API 和 MCP Server，无需真实设备。

---

## Quick Start / 快速开始

```bash
# Docker
docker build -t svs-mock .
docker run -d -p 9000:9000 svs-mock

# From source / 源码运行（Rust 1.75+）
cargo run -- --mode both   # REST + MCP, port 9000

# Add to Claude Code as MCP Server
claude mcp add svs-mock --url http://localhost:9000/mcp
```

## REST API

All endpoints accept `Content-Type: application/json` or `application/x-www-form-urlencoded`.

| Path | Description |
|------|-------------|
| `POST /Digest` | SM3 hash (with optional Z-value prefix) |
| `POST /SignData` | SM2 P1 signature (DER r\|\|s) |
| `POST /VerifySignedData` | Verify SM2 P1 signature |
| `POST /SignMessage` | CMS SignedData (PKCS#7) |
| `POST /VerifySignedMessage` | Verify CMS SignedData |
| `POST /envelopeEnc` | Digital envelope encrypt (SM2+SM4-CBC) |
| `POST /envelopeDec` | Digital envelope decrypt |
| `POST /ExportCert` | Export certificate by ID |
| `POST /ValidateCert` | Validate certificate (validity + trust anchor) |
| `POST /ParseCert` | Parse certificate fields |

```bash
# Example: SM3 digest / SM3 摘要示例
curl -X POST http://localhost:9000/Digest \
  -H "Content-Type: application/json" \
  -d '{"algId": 1, "data": "SGVsbG8gV29ybGQ="}'
# → {"respValue":0,"digest":"Yfx4dFBi..."}
```

## MCP Tools / MCP 工具

6 tools exposed at `/mcp`:

| Tool | Description |
|------|-------------|
| `svs_digest` | SM3 hash with optional Z-value (SM2 pre-processing) |
| `svs_sign` | SM2 sign — `mode:"data"` (P1 DER) or `"message"` (CMS) |
| `svs_verify` | SM2 verify — P1 or CMS, with certificate chain check |
| `svs_envelope_enc` | Digital envelope encrypt (SM2+SM4-CBC) |
| `svs_envelope_dec` | Digital envelope decrypt |
| `svs_cert` | Certificate ops — `action:"export"/"validate"/"parse"` |

## Configuration / 配置

`mock_certs.toml` configures trusted roots, signing keys, and encryption keys:

```toml
[server]
port = 9000
log_level = "info"

[[trusted_roots]]
name = "test root CA"
cert = "MIIC..."   # DER base64

[[signing_keys]]
index = 1
pin = "12345678"
private_key = "3945..."   # 32-byte hex
cert = "MIIC..."           # DER base64
```

Config lookup: `SVS_MOCK_CONFIG` env var → `./mock_certs.toml`.

## Run Modes / 运行模式

```bash
svs-mock --mode both   # REST + MCP (default)
svs-mock --mode rest   # REST only
svs-mock --mode mcp    # MCP only
```

> ⚠️ **For development and testing only. Not for production use.**  
> ⚠️ **仅供学习和开发测试使用，严禁用于生产环境。**
