# VeriGoods 后端实施计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 实现可验证商品生命周期网络后端：Rust + Axum + PostgreSQL + DDD + sqlx，双隐私模式（Shielded Transactions / Private Validium），Plonky3 ZK，alloy 链适配（Polygon CDK 待 WSL kurtosis-cdk），rmcp MCP。

**Architecture:** Cargo workspace 分层：vg-domain（纯领域）→ vg-application（用例编排/事务）→ vg-infra-pg / vg-infra-crypto / vg-infra-zk / vg-infra-chain（基础设施）→ vg-api（HTTP+MCP 装配）。事务采用关联类型 Context 模式（见 `Rust事务.md`）。Intent 是唯一写入口径。

**Tech Stack:** Rust 1.96、axum、sqlx(Postgres, 运行时查询非宏)、rmcp、alloy(feature-gate)、p3-koala-bear/p3-poseidon2/p3-uni-stark/p3-fri/p3-merkle-tree/p3-challenger/p3-matrix/p3-field/p3-commit/p3-air、k256(secp256k1)、aes-gcm/hkdf、sha3(keccak)、tokio、tracing、serde/serde_json、thiserror、config/dotenvy。

**约定:**
- 所有 crate 注释中文、命名英文；`#![deny(missing_docs)]` 不强制
- sqlx 一律使用运行时 API（`sqlx::query/query_as`），不用 `query!` 宏（避免编译期连库）
- 每个任务完成即 commit；测试不过不得提交
- 测试命令统一在 workspace 根执行

---

## Task 0: 环境准备

**Step 1: 启动 PostgreSQL 服务**

```bash
net start postgresql-x64-17
```

若权限不足则请用户手动以管理员启动。验证：

```bash
pg_isready -h localhost -p 5432   # 期望: accepting connections
```

**Step 2: 创建数据库与 .env**

向用户确认超级用户口令后：

```bash
psql -U postgres -c "CREATE DATABASE verigoods;"   # 已存在则忽略
```

创建 `E:\programs\VeriGoods\.env`：

```text
DATABASE_URL=postgres://postgres:<口令>@localhost:5432/verigoods
BIND_ADDR=0.0.0.0:8080
RUST_LOG=info,vg_api=debug
```

`.gitignore` 加入 `.env`、`target/`。

---

## Task 1: Workspace 骨架 + vg-domain::shared

**Files:**
- Create: `Cargo.toml`(workspace)、`crates/vg-domain/Cargo.toml`、`crates/vg-domain/src/lib.rs`
- Create: `crates/vg-domain/src/shared/mod.rs`、`errors.rs`、`did.rs`、`hash.rs`、`ids.rs`
- Test: `crates/vg-domain/src/shared/did.rs` 内嵌 `#[cfg(test)]`

**要点代码 — workspace `Cargo.toml`:**

```toml
[workspace]
resolver = "2"
members = ["crates/*"]

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
anyhow = "1"
uuid = { version = "1", features = ["v4", "v7"] }
chrono = { version = "0.4", features = ["serde"] }
hex = "0.4"
sha3 = "0.10"
k256 = { version = "0.13", features = ["ecdsa", "arithmetic", "ecdh"] }
aes-gcm = "0.10"
hkdf = "0.12"
rand = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

**shared/errors.rs:** `#[derive(thiserror::Error)] pub enum DomainError { InvalidTransition{from,to}, NotFound, AlreadyExists, Unauthorized(String), PolicyViolated(String), QuantityMismatch, CredentialInvalid{...}, ReplayDetected, Storage(String), InvalidInput(String) }`

**shared/did.rs:** 值对象 `Did(String)`，格式校验前缀 `did:vg:`；`fn did(&self)->&str`、`Display`。Agent DID 形如 `did:vg:agent:<id>` 提供 `is_agent()`。
测试：合法/非法 DID 解析。

**shared/hash.rs:** `pub struct Hash32([u8;32])` + `from_hex/as_hex/keccak(bytes)->Hash32`（sha3::Keccak256）。零值判断 `is_zero`（对应合约 bytes32(0) 哨兵）。

**ids.rs:** `BatchId/AssetId/CredentialId/IntentId/ProofId/PolicyId` 等 newtype，内部 uuid v7 或调用方提供字符串 ID；实现 Display。

**Steps:** 写测试→`cargo test -p vg-domain` 失败→实现→通过→commit `feat(domain): workspace 与 shared 值对象`。

---

## Task 2: domain::identity

**Files:** `crates/vg-domain/src/identity/{mod.rs,document.rs,capability.rs}`

**模型:**
```rust
pub enum SubjectKind { Enterprise, Consumer, Regulator, Inspector, Logistics, Agent, Device }
pub struct VerificationMethod { pub id:String, pub key_type:KeyType /*Secp256k1*/, pub public_key:Hash32, pub controller:Did, pub revoked:bool }
pub struct DidDocument { pub did:Did, pub kind:SubjectKind, pub methods:Vec<VerificationMethod>, pub parent:Option<Did> /*Agent→企业*/, pub jurisdiction:Option<String>, pub created_at:DateTime<Utc> }
impl DidDocument { fn active_pubkey(&self)->Option<&VerificationMethod> } // 取首个未撤销方法
pub struct Capability { pub agent:Did, pub action:Action, pub granted_by:Did, pub expires_at:Option<DateTime<Utc>> }
pub enum Action { ReadProduct, CreateBatch, RequestTransfer, TransferOwnership, IssueCredential, RevokeCredential, RegisterPolicy, UpdateCustody, SubmitShieldedTx, MassRecall }
```

**领域规则（TDD 用例）:**
1. Agent 文档必须带 parent 且 parent 非 Agent → 违规报 `Unauthorized`
2. `assert_allowed(&[Capability], Action) -> Result<()>`：过期/未授予拒绝
3. 密钥撤销后 `active_pubkey` 返回 None

**端口 trait（同文件 mod ports）：**
```rust
#[async_trait]
pub trait IdentityRepository {
    type Context;
    async fn save_document(&self, ctx:&mut Self::Context, doc:&DidDocument) -> Result<(), DomainError>;
    async fn find_document(&self, ctx:&mut Self::Context, did:&Did) -> Result<Option<DidDocument>, DomainError>;
    async fn grant_capability(&self, ctx:&mut Self::Context, cap:&Capability) -> Result<(), DomainError>;
    async fn capabilities_of(&self, ctx:&mut Self::Context, agent:&Did) -> Result<Vec<Capability>, DomainError>;
}
```

commit `feat(domain): 身份上下文与 Capability 规则`。

---

## Task 3: domain::credential

**Files:** `crates/vg-domain/src/credential/{mod.rs,vc.rs,status.rs}`

**模型:** `enum CredentialType { EnterpriseLicense, ProductionLicense, Origin, FoodSafetyInspection, QualityInspection, ColdChain, Customs, Tax, Authenticity, Ownership, Transport, Recall }`（12 类全量）；`enum CredStatus { Valid, Suspended, Revoked, Expired }`；

```rust
pub struct VerifiableCredential { pub id:CredentialId, pub issuer:Did, pub subject:Did, pub ctype:CredentialType,
    pub claims:serde_json::Value, pub issued_at:DateTime<Utc>, pub expires_at:Option<DateTime<Utc>>,
    pub status:CredStatus, pub credential_hash:Hash32 /*keccak(canonical json)*/ }
impl VerifiableCredential {
    fn compute_hash(&self)->Hash32;                 // keccak(serde_json canonical)
    fn transition(&mut self, to:CredStatus, actor:&Did, now) -> Result<(),DomainError>; // 仅 issuer 可改；Valid→Suspended|Revoked; Suspended→Valid|Revoked; 终态不可出
    fn is_effective(&self, now)->bool;              // status==Valid && 未过期
    pub struct CredentialSchema { id, ctype, required_claims: Vec<String> } // 校验 claims 键齐全
}
```

端口 `CredentialRepository{type Context; save, find, list_by_subject, update_status}`、`CredentialAnchorPort(async fn anchor_issued(&self,&CredentialId,&Hash32))`（链锚定，由 infra 实现）。
测试：状态机非法转换拒绝、issuer 不符拒绝、哈希稳定。

commit `feat(domain): VC 聚合与状态机`。

---

## Task 4: domain::lifecycle

**Files:** `crates/vg-domain/src/lifecycle/{mod.rs,state.rs,event.rs}`

`enum LifecycleState { Created, Produced, Inspected, InTransit, InWarehouse, Available, Sold, Owned, Resold, Recalled, Expired, Destroyed }`（12 态，serde 小写蛇形）。
**修订（用户需求）：新增第 13 态 `Delisted`（已下架）**——企业可对可售商品执行下架/重新上架。

**转换矩阵**（`ALLOWED: &[(LifecycleState, LifecycleState)]`，文档 §16）：
Created→Produced；Produced→Inspected|InTransit|InWarehouse|Destroyed；Inspected→InTransit|InWarehouse|Available|Recalled；InTransit→InWarehouse|Available；InWarehouse→Available|InTransit；Available→Sold|Recalled|Expired|**Delisted**；**Delisted→Available（重新上架）**；Sold→Owned；Owned→Resold|Recalled；**Recalled→Available（恢复路径，应用层强制校验全部必需凭证有效且 policy 允许后方可执行，见产品文档 §59 Policy Engine 重算语义）**；任意→Recalled|Destroyed（监管强制）；Expired/Destroyed 终态。

`fn can_transition(from,to)->bool`; `struct LifecycleEvent{ id, subject_id:SubjectRef /*Batch|Asset 双类型*/, from,to, reason:Option<String>, intent_id:IntentId, proof_id:Option<ProofId>, policy_version:Option<u64>, at }`。
测试：矩阵全覆盖（合法通过/非法拒绝）、终态锁定。

commit `feat(domain): 生命周期状态机`。

---

## Task 5: domain::commodity

**Files:** `crates/vg-domain/src/commodity/{mod.rs,product.rs,batch.rs,asset.rs,lineage.rs}`

```rust
pub struct ProductType { id:ProductId, category:String, metadata_hash:Hash32, active:bool }
pub struct Batch { id:BatchId, product:ProductId, quantity:u64, unit:String, produced_at:DateTime<Utc>,
    producer:Did, parent_lineage:Vec<BatchId>, state:LifecycleState, compliance_ok:bool, active:bool }
impl Batch {
    fn new(...)->Result  // quantity>0, 初始 Created
    fn split(&mut self, children:&[(BatchId,u64)]) -> Result<Vec<Batch>,DomainError>
      // 总量守恒 == self.quantity；子批继承 product/unit/produced_at/producer；self.active=false
    fn merge(children:&mut [Batch], new_id:BatchId, producer:Did) -> Result<Batch,DomainError>
      // 同 product 同 unit 同 producer 才可合；全部 active=false
    fn mark_destroyed/recall(...) 经 lifecycle 矩阵
}
pub struct Asset { id:AssetId, product:ProductId, manufacturer:Did, authenticity_commitment:Hash32,
    created_at, state:LifecycleState, transfer_count:u32, c2c_count:u32 }
pub struct LineageEdge { parent:BatchId, child:BatchId, op:LineageOp /*Split|Merge|Transform*/ }
```

端口 `CommodityRepository{type Context; save_product/save_batch/save_asset/find_batch/find_asset/update_batch/save_lineage/lineage_of(batch)->Vec<LineageEdge>/children/parents}`。
测试：拆分守恒失败 `QuantityMismatch`；合并异源拒绝；谱系边生成正确；split 后父 inactive。

commit `feat(domain): 批次/单品聚合与谱系`。

---

## Task 6: domain::ownership

**Files:** `crates/vg-domain/src/ownership/{mod.rs,states.rs,transfer.rs}`

```rust
pub struct OwnershipState { subject:SubjectRef, owner:Did, acquired_at:DateTime<Utc>, transfer_count:u32, c2c_count:u32 }
pub struct CustodyState { subject:SubjectRef, custodian:Did, since:DateTime<Utc> }
impl OwnershipState {
    fn initialize(subject, owner, at)->Result // 已存在 owner 报 AlreadyExists（对应合约 "owner exists"）
    fn transfer(&mut self, to:&Did, c2c:bool, at) -> Result<TransferRecord,DomainError>
      // to != 零 && to != 当前 owner；counters 自增；产生记录含 from/to/c2c/at
}
pub struct CustodyUpdate { subject, from:Option<Did>, to:Did, reason:CustodyReason /*Ship|WarehouseIn|WarehouseOut|Handover*/ }
```

所有权与保管完全分离：转移所有权不改 custodian；custody 更新独立事件。
端口 `OwnershipRepository{type Context; init_owner/get/update_custody/history(subject)->Vec<TransferRecord>}`。
测试：自转拒绝、c2c 计数、custody 与 ownership 互不影响。

commit `feat(domain): 所有权/保管分离模型`。

---

## Task 7: domain::policy

**Files:** `crates/vg-domain/src/policy/{mod.rs,domain.rs,policy.rs,abac.rs}`

```rust
pub struct RegulatoryDomain { domain_id:String, authority:Did, jurisdiction:String, product_types:Vec<String>,
    credential_schemas:Vec<CredentialSchema>, effective_from:DateTime<Utc> }
pub struct Policy { policy_id:PolicyId, version:u64, authority:Did, jurisdiction:String, product_type:String,
    required_credentials:Vec<CredentialType>, required_proofs:Vec<ProofKind /*Ownership|ColdChain|Range|Age|Identity|Credential*/>,
    transitions:Vec<(LifecycleState,LifecycleState)>, effective_at, expires_at:Option<DateTime<Utc>>, active:bool }
impl Policy { fn is_active(now); fn allows_transition(from,to)->bool; }
pub struct PolicyEngine; // 纯函数域服务
impl PolicyEngine {
    fn check_transition(policies:&[Policy], creds:&[VerifiableCredential], proofs:&[VerifiedProofRef], from,to,now)
        -> Result<PolicyDecision, DomainError>
    fn abac_check(req:AbacRequest) -> bool // subject_kind×role×jurisdiction×product_type×data_type×time 窗口
}
pub struct AbacRequest { subject:Did, role:Role /*Enterprise|Regulator|Consumer|Auditor|Logistics*/,
    jurisdiction:String, product_type:String, data:DataType /*Price|Contract|ReportFull|IdentityPii|LifecyclePublic*/, now }
```

测试：缺必需凭证 `PolicyViolated`；policy 过期不生效；ABAC 监管跨辖区拒绝。

commit `feat(domain): 监管域/策略引擎/ABAC`。

---

## Task 8: domain::intent

**Files:** `crates/vg-domain/src/intent/{mod.rs,intent.rs}`

```rust
pub enum IntentAction { CreateBatch, SplitBatch, MergeBatch, TransformBatch, CreateItem, TransferProduct,
    UpdateCustody, IssueCredential, RevokeCredential, ComplianceCheck, ShieldedTransfer, SubmitStateRoot, MassRecall }
pub enum RiskLevel { L1, L2, L3, L4 }  // 文档 §40 映射：L3=TransferOwnership 等, L4=MassRecall/Freeze
pub enum IntentStatus { Created, Validated, Authorized, PolicyChecked, ProofRequired, Proved, Approved, Submitted, Confirmed, Rejected, Expired, Cancelled }
pub struct Intent { id:IntentId, action, actor:Did, on_behalf_of:Option<Did> /*Agent 代企业*/,
    payload:serde_json::Value, nonce:u64, created_at, expires_at, status, rejection:Option<String>,
    risk:RiskLevel, result_ref:Option<String> }
impl Intent { fn advance(&mut self, to:IntentStatus)->Result  // 按 §27 有向图约束；终态不可再变
             fn is_replay_safe(now) }
```

端口 `IntentRepository{type Context; insert(幂等冲突→AlreadyExists)/get/update_status/list_pending}`。
测试：状态图非法跳转拒绝；终态锁定。

commit `feat(domain): Intent 状态机与风险分级`。

---

## Task 9: domain::privacy + 全局端口

**Files:** `crates/vg-domain/src/privacy/{mod.rs,note.rs,stealth.rs,extra.rs}`、`crates/vg-domain/src/ports.rs`、`crates/vg-domain/src/events.rs`

```rust
pub struct StealthMetaAddress { view_pub:Hash32/*压缩点*/, spend_pub:Hash32 }
pub struct OneTimeAddress { pub addr_point:Hash32, pub ephemeral:Hash32 /*R=rG 公布用于扫描*/ }
pub struct Note { asset_ref:SubjectRef, owner_ot_addr:Hash32, amount:u64, secret:[u8;32], salt:[u8;16] }
impl Note { fn commitment(&self)->Hash32 /*Poseidon2 host-hash, 见 Task10*/ ;
            fn nullifier(&self, ctx_domain:&str)->Hash32 /*keccak(secret‖domain)*/ }
pub struct EncryptedExtraData(pub Vec<u8>); // ECIES(viewKey_pub){from,to,asset,ts}
```

**ports.rs（全局端口，infra 各自实现）：**
```rust
#[async_trait] pub trait LedgerPort: Send+Sync {
    async fn anchor(&self, item:LedgerItem) -> Result<AnchorReceipt, DomainError>;
    async fn submit_state_root(&self, root:Hash32, batch_ref:&str) -> Result<AnchorReceipt, DomainError>;
    async fn is_nullifier_spent(&self, n:&Hash32) -> Result<bool, DomainError>;
    async fn is_commitment_present(&self, c:&Hash32) -> Result<bool, DomainError>;
}
pub enum LedgerItem { Commitment(Hash32), Nullifier(Hash32), EncryptedExtra(Vec<u8>), Transfer{subject,from,to,c2c},
    CredentialStatus{id,hash,status}, LifecycleChange{subject,from,to}, PolicyRegistered{id,version,hash} }
pub struct AnchorReceipt { tx_ref:String, anchored_at:DateTime<Utc>, in_process:bool }
#[async_trait] pub trait ProofProver: Send+Sync {
    async fn prove(&self, circuit:&CircuitSpec, witness:&Witness) -> Result<ProofBundle, DomainError>;
    fn verify(&self, bundle:&ProofBundle) -> Result<bool, DomainError>;
}
pub struct CircuitSpec { pub id:String/*note_opening*/, pub version:u64, pub public_inputs:Vec<FieldElement> }
pub struct Witness { pub secrets:Vec<FieldElement> }
pub struct ProofBundle { pub circuit_id:String, pub version:u64, pub proof:Vec<u8>, pub publics:Vec<FieldElement> }
```

**events.rs:** `enum DomainEvent { BatchCreated(..), BatchSplit{parent,children}, BatchMerged, AssetCreated, CredentialIssued/Revoked, CustodyChanged, OwnershipTransferred{..c2c,count}, ComplianceChanged, ProductRecalled, ProofRecorded, StateRootSubmitted }`（serde tag 名与文档 §53 一致）。

测试：nullifier 域分隔生效（不同 ctx 不同值）；Note commitment 确定。

commit `feat(domain): 隐私原语模型与全局端口/事件`。

---

## Task 10: vg-infra-crypto

**Files:** `crates/vg-infra-crypto/{Cargo.toml,src/lib.rs,keypair.rs,stealth.rs,ecies.rs,poseidon.rs}`

**stealth.rs 核心算法（k256）：**
```rust
// 发送方: r 随机; R = r*G; sS = r*viewPub (ECDH 点乘);
// t = keccak(sS.x); stealth_point = spendPub + t*G  => 一次性地址公钥
pub fn derive_one_time(meta:&StealthMetaAddressView) -> (OneTimeAddress, SharedSecretBytes)
// 接收方扫描: sS' = viewPriv * R; t'=keccak(sS'.x); P = spendPub + t'*G 比对命中
pub fn scan_and_unlock(view_priv:&SecretKey, ot:&OneTimeAddress, spend_pub:&PublicKey) -> Option<UnlockInfo>
```
**ecies.rs:** ECDH(k256)→HKDF-SHA256→AES-256-GCM；输出 nonce‖ct‖tag；`encrypt_to(pubkey, plaintext)->Vec<u8>` / `decrypt_with(privkey,&[u8])->Result<Vec<u8>>`。
**poseidon.rs:** 用 p3-poseidon2(KoalaBear) 对字节分片编码做 host 端哈希，输出 Hash32 —— 与电路内承诺一致（Task11 使用同一构造）。封装 `fn poseidon_note_commitment(parts:&[[u8;32]])->Hash32` 与 `fn to_field_le(bytes)->KoalaBear 元素序列` 工具。
**keypair.rs:** secp256k1 生成/签名(recoverable)/验签，供 VG-SIG 中间件与服务端签发复用。

**测试:** 加解密往返+篡改失败；stealth 收发两端一致性；scan 未命中 None；Poseidon 确定性。

依赖注意：p3-* 版本需一致，先 `cargo search p3-koala-bear` 取最新共同版本锁入 workspace deps。
commit `feat(crypto): secp256k1/隐匿地址/ECIES/Poseidon 原语`。

---

## Task 11: vg-infra-zk — note_opening 电路

**Files:** `crates/vg-infra-zk/{Cargo.toml,src/lib.rs,circuits/note_opening.rs}`

电路语义：公开输入 = Poseidon2 承诺 C；私有见证 = note 秘密分片 s[0..4]；trace 每行重算逐步 Poseidon2 状态，最后一行输出 == C。基于 p3-uni-stark `prove/verify` + FRI 配置：

```rust
type F = KoalaBear; type ChunkF = KoalaBear;  // 若版本提供压缩配置用对应 config
let config = StarkConfig::new(runner?, poseidon2_perm, ...) // 按 docs.rs 锁定版本 API 组装
prove(&config, &NoteOpeningAir, trace, &publics) -> proof; verify(&config, &NoteOpeningAir, &proof, &publics)
```

**测试（必须过）:** 正确见证 prove→verify true；错误公开输入 verify false；空见证编译期 panic 防御。
API 漂移对策：以 crates.io 锁定的具体版本文档为准调整构造参数；保持 `PlonkyProver::prove(note_opening@v1, w)` 对外签名不变。
commit `feat(zk): Plonky3 note_opening 电路与证明往返`。

---

## Task 12: range_check 电路

公开：bound B 与承诺 C=Poseidon2(x‖salt)；私有：x、salt。约束：分解 x 的 31-bit 位行逐位累积重建 x 且 x ≤ B（位比较 AIR），并重算 C。
测试：x<B 通过、x>B verify false。commit `feat(zk): range_check 电路`。

## Task 13: coldchain_max 电路 + Prover 分发

公开：温度承诺链 root（每读数 Poseidon2 链式 H(prev‖t_i)）、上限 T_max；私有：读数序列。AIR 逐行校验链重算 + 每 t_i ≤ T_max。
`ProverDispatcher implements domain ProofProver`：按 CircuitSpec.id 分发三电路；另实现 `TransparentProver`（keccak(statement‖witness) 签名式回执，仅测试）。
测试：违规温度序列 false；dispatcher 路由正确。commit `feat(zk): 冷链合规电路与 Prover 分发`。

---

## Task 14: vg-infra-pg — migrations 全量表

**Files:** `crates/vg-infra-pg/migrations/0001_init.sql`（单文件起步）

按设计文档 §3 表清单建表（要点）：
- 主键 text（ID 字符串）；金额/数量 bigint；时间 timestamptz
- `dids(id PK, kind, parent_did FK NULL, jurisdiction, created_at)`；`verification_methods(did FK, method_id, key_type, public_key bytea, revoked)`；`capabilities(agent_did, action, granted_by, expires_at, PK(agent_did,action))`
- `credentials(id PK, issuer, subject, ctype, claims jsonb, issued_at, expires_at, status, credential_hash UNIQUE)`
- `products(id PK,...)`；`batches(id PK, product_id, quantity, unit, produced_at, producer, state, compliance_ok, active)`；`batch_lineage(parent,child,op,PK(parent,child))`；`assets(id PK,...transfer_count,c2c_count)`
- `ownership_states(subject PK, owner, acquired_at, transfer_count, c2c_count)`；`custody_states(subject PK, custodian, since)`；`transfers(serial PK, subject, from_did, to_did, c2c, at, intent_id UNIQUE)`
- `regulatory_domains(domain_id PK,...)`；`policies(policy_id,version,jurisdiction,product_type,required jsonb,transitions jsonb,effective_at,expires_at,active, PK(policy_id,version))`
- `intents(id PK, action, actor, on_behalf_of, payload jsonb, nonce, status, risk, expires_at, created_at, updated_at)`（幂等靠 PK 冲突）
- `notes(commitment PK, asset_ref, owner_ot_addr, amount, created_tx)`；`nullifiers(nf PK, spent_at, intent_id)`；`shielded_txs(serial PK, nf UNIQUE, commitment UNIQUE, extra bytea, at)`；`data_access_grants(grantee, dataset, until, PK)`；`validium_batches(root, batch_ref UNIQUE, proof_id, submitted_at)`
- `proofs(proof_id PK, circuit_id, circuit_version, statement_hash, proof bytea, publics jsonb, verified)`
- `audit_events(bigserial, actor, agent, intent_id, action, resource, policy_version, proof_id, result, at)`
- `domain_events(bigserial PK, aggregate, event_type, payload jsonb, created_at, dispatched bool DEFAULT false)`（outbox）
- `ledger_anchors(bigserial PK, kind, ref_hash bytea UNIQUE WHERE kind IN(...), payload jsonb, tx_ref, status, created_at, anchored_at)` + 局部唯一索引保证 nullifier/commitment 幂等

**Step:** `sqlx migrate run`（或启动时自动 migrate，见 Task23 bootstrap）+ `psql \dt` 目检 18 张表。
commit `feat(infra-pg): 初始 schema 迁移`。

---

## Task 15: pg 仓储 — identity/credential

**Files:** `crates/vg-infra-pg/src/{lib.rs,pool.rs,identity_repo.rs,credential_repo.rs}`

模式（严格按 Rust事务.md）：
```rust
pub struct PgIdentityRepo;
#[async_trait] impl IdentityRepository for PgIdentityRepo {
    type Context = sqlx::Transaction<'static, sqlx::Postgres>;
    async fn save_document(&self, ctx:&mut Self::Context, d:&DidDocument) -> Result<(),DomainError> { sqlx::query("INSERT ...").bind(..).execute(&mut **ctx).await.map_err(storage)?; Ok(()) }
}
```
upsert 语义：documents/methods ON CONFLICT 更新；capability 授予幂等。
`credential_repo` 含状态更新乐观检查（WHERE status=期望，影响行数 0 → DomainError::InvalidTransition）。

**测试（sqlx::test，DATABASE_URL 必须可用）：**
保存→find 往返；重复 capability 幂等；credential 并发二次 revoke 第二次失败。
commit `feat(infra-pg): 身份与凭证仓储（Context 事务模式）`。

## Task 16: pg 仓储 — commodity/ownership/lifecycle

同模式。重点测试：split 写入 lineage 边+父 active=false 在同一 ctx；ownership_states.transfer 后计数持久化；transfers.intent_id UNIQUE 二次插入报错（幂等）。
commit `feat(infra-pg): 商品/权属/生命周期仓储`。

## Task 17: pg 仓储 — policy/intent/proof/audit/outbox

intent insert 冲突转 `AlreadyExists`（幂等信号，上层返回既有结果）；outbox append-only；audit 只增。
commit `feat(infra-pg): 策略/意图/证明/审计仓储`。

## Task 18: InProcessLedger

**Files:** `crates/vg-infra-pg/src/ledger_inprocess.rs`

实现 `LedgerPort`：写 `ledger_anchors`（UNIQUE 冲突→已存在视为成功幂等）；`state_root = keccak(prev_root ‖ item_hashes)` 链式推进存于专用行；`is_nullifier_spent/is_commitment_present` 查询。模拟 CDK：`AnchorReceipt{tx_ref:"inprocess:<seq>", in_process:true}`。
测试：同 nullifier 二次 anchor 幂等；root 单调演进。
commit `feat(infra-pg): InProcessLedger 默认账本`。

---

## Task 19: vg-application — IntentEngine 管道

**Files:** `crates/vg-application/{Cargo.toml,src/lib.rs,error.rs,intent_engine.rs,deps.rs}`

**deps.rs 组合根接口：**
```rust
pub struct AppDeps<I,Cm,Own,Pol,Pr,Lg,Pv> where 每个 trait object Arc<dyn ...> { identity, credentials, commodity, ownership, lifecycle, policies, intents, proofs, audit, outbox, ledger:Lg, prover:Pv, crypto }
```
泛型化以保事务组合；实际装配用具体 Pg 类型别名。

**intent_engine 流程（核心，约 300 行）：**
```rust
pub async fn execute(&self, raw:RawIntent) -> Result<IntentResult,AppError> {
  1. 开事务 tx = pool.begin()
  2. insert intent（冲突→读取既有 intent 直接返回其状态 = 幂等）
  3. 校验 expires/nonce/replay → Expired/ReplayDetected
  4. resolve actor document；agent 则校验 parent + capability(Action)
  5. match action → 分派 handler（Task20/21/22 注册的 HandlerMap）
  6. handler 内：业务校验→policy engine→prover(需要时)→ledger.anchor→聚合变更落库→outbox 事件→intent.status=Confirmed
  7. 任一步 DomainError → intent.status=Rejected(reason) 提交审计后 rollback 业务部分（intent 本身保留）
  8. commit
}
```
L3/L4：handler 通过前置检查后置 status=Approved 之前插入 `approvals` 待办（新增表 `approvals(intent_id PK, required_role, decided_by NULL, decided_at)`），由 `approve(intent_id, approver)` 续跑后半程。
**测试:** 幂等重复提交同 ID 返回同一结果；无 Capability 拒绝且 intent=Rejected；L3 无审批停在 Approved 前一状态。

commit `feat(app): Intent 引擎管道与审批门`。

## Task 20: app — 商品与公开转移服务

Handlers: create_batch（需 ProductionLicense VC 有效→Policy 允许 Created→? 由 payload.state 定）、split/merge（守恒+谱系）、create_item、transfer_public（ownership.transfer + lifecycle Owned/Sold + custody 可选联动 + ledger.Transfer 锚定 + counters）。
**e2e-ish 测试:** 猪肉批次 生产→检测(VC)→转运→零售→消费者 五步管道全绿；数量守恒拆分后子批可各自转移。
commit `feat(app): 批次/单品/公开转移用例`。

## Task 21: app — Shielded 与 Validium 服务

`shielded_transfer`: 入参含接收方 meta-address、旧 Note secret、amount、监管 ViewKey 公钥 → crypto 派生 OT 地址 → 构造新 Note → nullifier 未花费检查（ledger.is_nullifier_spent）→ ECIES ExtraData → prover.note_opening → ledger.anchor(Nullifier+Commitment+Extra) → notes/nullifiers/shielded_txs 三表写入（同事务）→ intent Confirmed。
`scan_notes(view_priv)`: 遍历未识别 shielded_txs 尝试 unlock 返回我的 Notes。
`regulator_decrypt(extra, view_priv)`.
`submit_validium_root(batch_ref, items)`: Merkle(items hashes)→root→ledger.submit_state_root→validium_batches；`grant_data_access(regulator, dataset, until)` IAM。
测试：完整隐匿转移后接收方可扫到、第三方视角无 from/to；双花同 Note 第二次 Rejected；validium root 幂等。
commit `feat(app): 隐匿交易与 Private Validium 用例`。

## Task 22: app — 合规/策略/召回联动

issue_credential/revoke_credential handler（issuer Capability + 类型匹配 RegulatoryDomain schema）；revoke 后触发 `recompute_compliance(subject)`: 依当前有效 policy 重查必需凭证 → 不满足则 lifecycle 强制 Recalled + outbox ProductRecalled + ledger.CredentialStatus 锚定。
check_compliance / get_required_credentials 查询服务。
测试：FoodSafety VC 撤销 → 批次自动 RECALLED；重新签发恢复 Available（经 policy 允许路径）。
commit `feat(app): 凭证生命周期与召回联动`。

---

## Task 23: vg-api — Axum 引导与鉴权

**Files:** `crates/vg-api/{Cargo.toml,src/main.rs,config.rs,state.rs,error.rs,middleware/auth.rs,routes/health.rs}`

bootstrap: dotenvy→tracing→PgPool(connect+migrate!)→装配 AppDeps(InProcessLedger, PlonkyProver 或 cfg transparent 时 TransparentProver)→Router→serve(BIND_ADDR)。
**auth.rs VG-SIG:** 解析头 `VG-SIG did="...", sig="0x..", ts=..., nonce="..."`；ts 漂移 ≤300s；nonce 内存 LRU 防重放；消息 = `method\npath\nts\nnonce` keccak → k256 ecrecover 比对 did_documents 活跃公钥；通过后注入 `AuthedDid` extension。白名单 `/health`、`/api/v1/consumer/*` 只读免签。
error.rs: DomainError/AppError → HTTP 状态映射（NotFound404/Unauthorized401/Forbidden403/Conflict409/BadRequest400/Storage500），统一 JSON `{code,message,intent_id?}`。
**测试:** 签名中间件单测（好签过、坏签 401、重放 401）。
commit `feat(api): Axum 引导/VG-SIG 鉴权/错误映射`。

## Task 24: REST 路由全集

**Files:** `routes/{identity,credentials,commodity,transfer,shielded,compliance,policy,consumer,intent}.rs`

按设计 §6 路径表实现薄 handler：解析 JSON→调 service→包响应。consumer/{id} 聚合视图（脱敏：非授权方显示 `DID-XXXX` 前 8 位）。intents/{id} GET 轮询。
**集成测试（sqlx::test + tower ServiceExt oneshot，无需起端口）:** 注册 DID→签发 VC→建批次→转移→消费者视图断言 counters/年龄字段。
commit `feat(api): REST 全路由与场景集成测试`。

## Task 25: rmcp MCP Server

**Files:** `crates/vg-api/src/mcp/{mod.rs,tools.rs,resources.rs,prompts.rs}`

rmcp `ServerHandler`：Tools 六组映射应用服务入参出参 JSON Schema 化；Resources URI 模板解析→查询服务；Prompts 8 条文案模板。transport-streamable-http 挂 `/mcp`；连接级 header 携带 VG-SIG（复用 middleware 校验函数）映射 Agent DID→Capability。
**测试:** tools/list 含全部工具名；create_batch tool 调用走通管道（mock auth 直通 feature 下）。
commit `feat(api): rmcp MCP 工具/资源/提示词`。

---

## Task 26: vg-infra-chain — alloy 适配器（待 CDK 启用）

**Files:** `crates/vg-infra-chain/{Cargo.toml,src/lib.rs,provider.rs,anchor.rs,bindings.rs}` + workspace `[features] chain-alloy`

sol! 绑定 `contracts-ext` 两合约 ABI；AlloyLedger impl LedgerPort：anchor→合约 calldata 交易（私钥来自 env `OPERATOR_KEY`），收据→tx_ref；submit_state_root→StateAnchor.commitRoot。RPC 不可达时返回 `DomainError::Storage`（上层标记 pending 重试，不阻断本地事务——由 intent_engine 包裹 try_anchor）。
测试全部 `#[ignore="需 Polygon CDK(kurtosis-cdk) RPC"]`，README 记录启用步骤。
commit `feat(chain): alloy LedgerPort 适配器（feature-gated）`。

## Task 27: contracts-ext 扩展合约（只开发不测）

**Files:** `contracts-ext/ShieldedRegistry.sol`、`contracts-ext/StateAnchor.sol`

ShieldedRegistry 参照参考合约风格（AccessControl + SHIELDED_OPERATOR_ROLE）：`mapping(bytes32=>bool) commitments/nullifiers`；`commitAndSpend(nf, commitment, encryptedExtra bytes)` 要求 nf 未存在、commitment 未存在；事件 `NoteSpent(nf, commitment)`、`NoteCommitted(commitment, extra)`。StateAnchor：`roots(bytes32)=>bool`、`commitRoot(root,batchRef)` 事件。
不做本地编译部署（用户将在 WSL kurtosis-cdk 环境处理）。
commit `feat(contracts-ext): ShieldedRegistry 与 StateAnchor`。

---

## Task 28: 端到端场景测试

**Files:** `crates/vg-application/tests/e2e_scenarios.rs`

1. `pork_full_chain`: 监管域+Policy v1 注册→企业/检测机构 DID→生产批次→FoodSafety VC→拆分两子批→两次转移→零售→消费者视图（transferCount=3, c2c=0）
2. `crab_c2c`: 单品→Alice→Bob(c2c=true)→Charlie(c2c=true)：c2c_count=2、Owned→Resold 状态链
3. `shielded_flow`: 隐匿转移+接收方扫描+监管解密还原双方 DID
4. `recall_cascade`: revoke VC→RECALLED→重新签发→恢复
5. `idempotent_intent`: 同 intentId 重放零副作用
全部走真实 PG（sqlx::test）。commit `test(e2e): 五大场景`。

## Task 29: 收尾

- `cargo fmt --all` / `cargo clippy --workspace --all-targets -- -D warnings` 清零
- `cargo test --workspace` 全绿
- README.md：架构图（引用设计文档）、启动步骤（PG、.env、`cargo run -p vg-api`）、MCP 接入示例（Claude 配置 JSON）、WSL kurtosis-cdk 启用指引（feature chain-alloy + ignored tests）
- seed demo：`examples/seed_demo.rs` 造演示 DID/Policy
- 最终 commit + 全量 verification-before-completion 自检清单

---

## 风险与对策备忘

| 风险 | 对策 |
|---|---|
| p3-* 版本 API 漂移 | Task10 先锁版本探 API，电路层薄封装隔离 |
| Windows 下 Plonky3 编译慢 | 一次性成本；CI/测试可用 TransparentProver feature |
| sqlx::test 需服务级权限 | Task0 确保 DATABASE_URL 超级用户可用 |
| rmcp transport API 变动 | 以锁定版本 docs 为准，tools 定义与 transport 解耦 |
