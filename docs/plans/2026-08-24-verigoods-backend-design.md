# VeriGoods 可验证商品生命周期网络 — 后端设计文档

**日期**：2026-08-24
**依据**：《可验证商品生命周期网络_完整产品文档_v1.0.md》《企业级可验证商品生命周期网络_系统架构文档_v1.0.md》
**参考合约**：`commodity-network-smart-contracts-mvp-v1.0/`

---

## 1. 范围与决策记录

| 决策项 | 结论 |
|---|---|
| 功能范围 | Phase 1+2：DID、Batch、单品 Asset、Ownership/Custody 分离、Transfer、C2C 计数、VC 签发/验证/撤销、监管域 + Policy Engine、Intent 引擎、MCP。跳过 ERP/IoT 适配器 |
| 隐私架构 | 双模式：模式一应用层 Shielded Transactions（Note 承诺 + Nullifier + Stealth Address + 监管 ViewKey 加密 ExtraData）；模式二 Private Validium（明文留私有节点，链上仅 State Root + ZK 指纹，监管经 IAM 授权读明文） |
| 链层 | alloy 适配器指向 Polygon CDK；合约只开发不本地测试，后续在 WSL 安装 kurtosis-cdk 运行真实链后测试；默认账本为 Postgres 支撑的 InProcessLedger 保证本地闭环 |
| ZK 层 | 优先基于 Plonky3 实现真实电路（uni_stark）；TransparentProver 哈希证明仅作测试回退 |
| MCP | rmcp 官方 SDK（Streamable HTTP）+ 完整 REST API |
| 语言 | 中文注释 + 英文命名 |

## 2. 工程结构

```text
verigoods/
├── Cargo.toml                 # workspace
├── contracts-ext/             # 扩展合约：ShieldedRegistry.sol 等（只开发，暂不部署）
├── crates/
│   ├── vg-domain/             # 纯领域层：实体/值对象/聚合/领域服务/端口 trait（无 sqlx/tokio 依赖）
│   ├── vg-application/        # 应用层：用例编排、事务边界（关联类型 Context 模式，见 Rust事务.md）
│   ├── vg-infra-pg/           # sqlx Repository 实现 + migrations
│   ├── vg-infra-chain/        # LedgerPort 的 alloy 适配器 + InProcessLedger 默认实现
│   ├── vg-infra-crypto/       # secp256k1 ECDH / Keccak / ECIES(ViewKey) 原语
│   ├── vg-infra-zk/           # Plonky3 电路与 Prover 实现
│   └── vg-api/                # Axum HTTP + rmcp MCP Server + 配置装配
```

**事务模式**（Rust事务.md）：Domain Repository trait 定义 `type Context` 关联类型；Infra 层绑定为 `sqlx::Transaction<'static, Postgres>`；Application 层持有 `Pool`，`begin()` 后将 `&mut tx` 注入各仓储，统一 commit/rollback。

## 3. 领域模型与数据库

| 聚合 | 核心表 | 要点 |
|---|---|---|
| Identity | `dids`, `did_documents`, `verification_methods`, `capabilities` | DID 方法 `did:vg:`；Agent DID 挂 Enterprise DID 下，Capability 白名单 |
| Credential | `credentials`, `credential_status` | 链下完整 VC JSON；锚定 credentialHash；状态 VALID/SUSPENDED/REVOKED/EXPIRED |
| Commodity | `products`, `batches`, `batch_lineage`, `assets` | split/merge 数量守恒；lineage 父子边；Asset 含 authenticityCommitment |
| Ownership | `ownership_states`, `custody_states`, `transfers` | Owner/Custodian 分离；transferCount/c2cCount；记录 policyVersion、proofId |
| Lifecycle | `lifecycle_events` | 12 态状态机；每次转换带 intentId + proofId + policyVersion |
| Policy | `regulatory_domains`, `policies`, `policy_credentials` | 版本化；requiredCredentials/requiredProofs/转换矩阵 |
| Intent | `intents` | 9 态生命周期 + REJECTED/EXPIRED/CANCELLED；intentId 唯一 → 幂等；nonce+expiration+domainSeparator 防重放 |
| Privacy | `notes`, `nullifiers`, `shielded_txs`, `data_access_grants`, `private_batches`(validium) | commitment/nullifier 唯一约束防双花 |
| Audit/Event | `audit_events`, `domain_events`(outbox) | 全量审计；outbox 供索引器消费 |
| Proof | `proofs` | proofId、circuitId/circuitVersion、statementHash、verified |

领域不变量在聚合内强制：数量守恒、状态转换合法性、Capability 校验。

## 4. Intent 管道（唯一写入口径）

```text
MCP / REST / 企业事件
  ↓ Intent 创建（幂等）
Schema Validation → DID/Capability 授权 → VC 有效性校验 → Policy Engine
  → ZK Prover（Plonky3）→ LedgerPort 提交 → 状态机更新 + 领域事件(outbox)
```

风险分级：L1 自动执行（读/验）、L2 企业策略自动批准（建批次/custody）、L3 额外授权（所有权转移）、L4 监管多签人工审批（召回/冻结）。L3/L4 写 `approvals` 待审批。

## 5. 隐私层

### 模式一 Shielded Transactions
1. 接收方注册 Stealth Meta-Address；发送方以 secp256k1 ECDH + 随机熵派生一次性隐匿地址
2. 转移 = 提交 nullifier = H(noteSecret ‖ context) 销毁旧 Note + 新 Note commitment = H(assetId ‖ stealthAddr ‖ salt)
3. ExtraData：ECIES(AES-GCM+HKDF) 用监管 ViewKey 加密 {fromDID, toDID, assetId, ts}
4. Prover 约束"ExtraData 身份 == 签名者"，不符则拒绝
5. 接收方用自身 viewKey 扫描识别自己的 Note；公开视图无法关联双方

### 模式二 Private Validium
明文仅存私有 PG；`data_access_grants` IAM 表授权监管读取；批量 intent 聚合 Merkle StateRoot 经 LedgerPort 提交。

### Plonky3 电路（首批）

| CircuitID | 公开输入 | 私有见证 | 用途 |
|---|---|---|---|
| `note_opening@v1` | Poseidon2 承诺 | noteSecret 分片 | Note 所有权 |
| `range_check@v1` | 承诺值、bound | 原始数值 | 数量范围 |
| `coldchain_max@v1` | 温度承诺 root、T_max | 全部读数 | 冷链合规 |

依赖：p3-koala-bear / p3-poseidon2 / p3-merkle-tree / p3-commit / p3-fri / p3-uni-stark。
诚实边界：uni_stark 默认未盲化，保证简洁性与完整性；标注非零知识，后续可切 blinding。

## 6. API 层

REST（前缀 `/api/v1`）：dids / credentials / products / batches / assets / transfers / shielded / compliance / policies / consumer/{id} / intents/{id}。

鉴权：DID 签名挑战（`Authorization: VG-SIG did=..., sig=..., ts=..., nonce=`），中间件 → ABAC（Subject×Role×Jurisdiction×ProductType×DataType×Time）。

MCP（rmcp，挂载 `/mcp`）：Tools 全集（commodity/ownership/transaction/credential/compliance/zk 六组）、Resources `commodity://...`、Prompts 8 个；Agent DID 鉴权后走同一 Intent 管道，无直连链权限。

横切：幂等、重放保护、审计全量、OpenTelemetry tracing。

## 7. 测试策略

- 领域层纯单测（聚合不变量）
- 应用层 `sqlx::test` 临时库事务用例
- zk 电路 prove→verify 往返测试（TransparentProver 加速单测）
- alloy/kurtosis-cdk 集成测试 `#[ignore]` 或 feature-gated，待 WSL Polygon CDK 就绪启用
- 端到端场景：猪肉批次全链路、大闸蟹单品 C2C、隐匿转移、召回联动
