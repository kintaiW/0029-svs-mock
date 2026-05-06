# Contributing to svs-mock

## 版本发布纪律

本项目遵循 [SemVer 2.0](https://semver.org/lang/zh-CN/)。**当前处于 `0.x` 阶段**，`minor` bump 允许引入破坏性变更，但必须在 `CHANGELOG.md` 的 `### Breaking` 段显式列出。

### Bump 规则

| 改动类型 | Bump | 示例 |
|---|---|---|
| bug fix、文案、日志、内部重构（用户行为无变化） | **patch** | 0.2.0 → 0.2.1 |
| 新增 CLI flag、新接口、配置新增字段、输出追加字段 | **minor** | 0.2.0 → 0.3.0 |
| 删除命令/接口、改已有 flag 语义、配置向后不兼容 | **major** | 0.2.0 → 1.0.0 |

### PR 标签约定

- `bump:patch` — 自动触发 patch release
- `bump:minor` — 自动触发 minor release
- `bump:major` — 人工确认后触发 major release

### 发布流程

1. 在 `CHANGELOG.md` 填写本次变更内容（`## [x.y.z] - YYYY-MM-DD` 段）
2. 合入 PR 到 `main`
3. 打 tag：`git tag v0.2.0 && git push --tags`
4. GitHub Actions `release.yml` 自动：回写 `Cargo.toml` 版本 → 构建 → 版本自检 → 发 GitHub Release

### 贡献要求

- 提交信息格式：`fix: 修复 X`、`feat: 新增 Y`、`refactor: 重构 Z`
- Rust 代码遵循 `cargo clippy --deny warnings` 零 warning 标准
- 公共接口修改需更新 `docs/` 下对应文档
