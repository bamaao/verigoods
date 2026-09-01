-- VeriGoods 初始 schema（单文件起步，Task 14）。
-- 约定：主键一律 text（ID 为字符串）；金额/数量/计数 bigint（u64 口径）；
-- 时间 timestamptz；哈希一律 bytea 存原始 32 字节（hex 转换属仓储层）。
-- CHECK 白名单取自 vg-domain 各枚举的 snake_case 序列化值全集。
-- 迁移纪律：已合入的迁移不可再改（sqlx checksum 锁定）；schema 变更 =
-- 新增 000N 迁移文件；开发库重置 = dropdb + createdb + migrate()。
-- 冻结时点：Task 15 合入时（1261bb5）；此前变更均已含于本文件，
-- 此后变更一律新增 000N。

-- ============================================================
-- 身份上下文（identity）
-- ============================================================

-- 表：DID 文档。一个主体一行；agent 经 parent_did 挂靠非 agent 主体。
-- kind 白名单 = SubjectKind 7 值全集。
CREATE TABLE IF NOT EXISTS dids (
    id          text PRIMARY KEY,
    kind        text NOT NULL CHECK (kind IN ('enterprise','consumer','regulator','inspector','logistics','agent','device')),
    -- 智能体挂靠的企业主体；非 agent 为 NULL。RESTRICT：删企业不得连带
    -- 抹掉 agent DID 及其能力/方法（历史不可变性优先，取值改软删除）
    parent_did  text REFERENCES dids(id) ON DELETE RESTRICT,
    jurisdiction text NOT NULL,
    created_at  timestamptz NOT NULL,
    -- agent 必须有挂靠，非 agent 禁止挂靠（防嵌套委托由领域层守卫）
    CHECK ((kind = 'agent') = (parent_did IS NOT NULL))
);

-- 表：验证方法。公钥摘要 = keccak(33 字节压缩 sec1)，32 字节 bytea。
-- PK(did, method_id) 保证文档内唯一。CASCADE：主体自身被删时随之清理
-- 合理（密钥绑定随身份消亡）；但 RESTRICT 的 parent_did 使主体删除
-- 实际上很难发生，此级联路径属兜底。
CREATE TABLE IF NOT EXISTS verification_methods (
    did         text NOT NULL REFERENCES dids(id) ON DELETE CASCADE,
    method_id   text NOT NULL,
    key_type    text NOT NULL CHECK (key_type = 'secp256k1'),
    public_key  bytea NOT NULL CHECK (octet_length(public_key) = 32),
    revoked     boolean NOT NULL DEFAULT false,
    PRIMARY KEY (did, method_id)
);

-- 表：能力授权。PK(agent_did, action) 使一个动作至多一条有效授权记录。
-- CASCADE：授权依附主体，主体删除时随之清理（主体删除本身已被
-- parent_did RESTRICT 严控，此级联属兜底）。action 白名单 =
-- identity::Action 10 值全集。
CREATE TABLE IF NOT EXISTS capabilities (
    agent_did   text NOT NULL REFERENCES dids(id) ON DELETE CASCADE,
    action      text NOT NULL CHECK (action IN (
        'read_product','create_batch','request_transfer','transfer_ownership',
        'issue_credential','revoke_credential','register_policy','update_custody',
        'submit_shielded_tx','mass_recall')),
    granted_by  text NOT NULL,
    -- NULL = 永不过期；判定口径 now >= expires_at 即失效（与领域层一致）
    expires_at  timestamptz,
    PRIMARY KEY (agent_did, action)
);

-- ============================================================
-- 凭证上下文（credential）
-- ============================================================

-- 表：可验证凭证。credential_hash 全局唯一（落库前不可变契约）。
-- ctype 白名单 = CredentialType 12 值；status 白名单 = CredStatus 4 值。
CREATE TABLE IF NOT EXISTS credentials (
    id              text PRIMARY KEY,
    issuer          text NOT NULL,
    subject         text NOT NULL,
    ctype           text NOT NULL CHECK (ctype IN (
        'enterprise_license','production_license','origin','food_safety_inspection',
        'quality_inspection','cold_chain','customs','tax','authenticity',
        'ownership','transport','recall')),
    claims          jsonb NOT NULL,
    issued_at       timestamptz NOT NULL,
    -- NULL = 永久有效；now >= expires_at 即失效
    expires_at      timestamptz,
    status          text NOT NULL CHECK (status IN ('valid','suspended','revoked','expired')),
    credential_hash bytea NOT NULL UNIQUE CHECK (octet_length(credential_hash) = 32)
);
CREATE INDEX IF NOT EXISTS idx_credentials_subject ON credentials(subject);
CREATE INDEX IF NOT EXISTS idx_credentials_issuer ON credentials(issuer);

-- ============================================================
-- 商品上下文（commodity）
-- ============================================================

-- 表：商品类型档案。active 为软删除开关；metadata_hash 对应合约 bytes32。
CREATE TABLE IF NOT EXISTS products (
    id            text PRIMARY KEY,
    category      text NOT NULL CHECK (category <> ''),
    metadata_hash bytea NOT NULL CHECK (octet_length(metadata_hash) = 32),
    created_at    timestamptz NOT NULL,
    active        boolean NOT NULL DEFAULT true
);

-- 表：批次。谱系不建列——父子关系走 batch_lineage 边表。
-- product_id RESTRICT：删产品不得抹掉批次审计链（下架走 active 软删）。
-- state 白名单 = LifecycleState 13 值全集（与 assets.state 同一状态机）。
CREATE TABLE IF NOT EXISTS batches (
    id            text PRIMARY KEY,
    product_id    text NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    quantity      bigint NOT NULL CHECK (quantity > 0),
    unit          text NOT NULL CHECK (unit <> ''),
    produced_at   timestamptz NOT NULL,
    producer      text NOT NULL,
    state         text NOT NULL CHECK (state IN (
        'created','produced','inspected','in_transit','in_warehouse','available',
        'delisted','sold','owned','resold','recalled','expired','destroyed')),
    compliance_ok boolean NOT NULL DEFAULT false,
    active        boolean NOT NULL DEFAULT true
);
CREATE INDEX IF NOT EXISTS idx_batches_product ON batches(product_id);

-- 表：批次谱系边。parent = 拆分/合并前的父批，child = 衍生批；
-- PK(parent, child) 防重复边；child 索引服务"子查父"溯源。
CREATE TABLE IF NOT EXISTS batch_lineage (
    parent text NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
    child  text NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
    -- op 白名单 = LineageOp 3 值全集（serde snake_case）
    op     text NOT NULL CHECK (op IN ('split','merge','transform')),
    PRIMARY KEY (parent, child)
);
CREATE INDEX IF NOT EXISTS idx_batch_lineage_child ON batch_lineage(child);

-- 表：单品资产。transfer_count/c2c_count 由所有权上下文回填。
CREATE TABLE IF NOT EXISTS assets (
    id                      text PRIMARY KEY,
    -- RESTRICT 理由同 batches.product_id：审计链不可被产品删除抹掉
    product_id              text NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    manufacturer            text NOT NULL,
    authenticity_commitment bytea NOT NULL CHECK (octet_length(authenticity_commitment) = 32),
    created_at              timestamptz NOT NULL,
    state                   text NOT NULL CHECK (state IN (
        'created','produced','inspected','in_transit','in_warehouse','available',
        'delisted','sold','owned','resold','recalled','expired','destroyed')),
    transfer_count          bigint NOT NULL DEFAULT 0 CHECK (transfer_count >= 0),
    c2c_count               bigint NOT NULL DEFAULT 0 CHECK (c2c_count >= 0)
);

-- ============================================================
-- 所有权/保管上下文（ownership）
-- ============================================================

-- 表：所有权状态。subject 为批次/单品 ID（仓储层负责 SubjectRef 编码）。
-- owner 冗余了商品侧计数字段，转移时与 batches/assets 同事务更新。
CREATE TABLE IF NOT EXISTS ownership_states (
    subject        text PRIMARY KEY,
    owner          text NOT NULL,
    acquired_at    timestamptz NOT NULL,
    transfer_count bigint NOT NULL DEFAULT 0 CHECK (transfer_count >= 0),
    c2c_count      bigint NOT NULL DEFAULT 0 CHECK (c2c_count >= 0)
);
CREATE INDEX IF NOT EXISTS idx_ownership_states_owner ON ownership_states(owner);

-- 表：保管状态。物流/仓储场景下的实际持有人。
CREATE TABLE IF NOT EXISTS custody_states (
    subject   text PRIMARY KEY,
    custodian text NOT NULL,
    since     timestamptz NOT NULL
);

-- 表：转移流水（审计留痕）。不设任何 FK、不级联——历史记录必须
-- 独立于主体存亡而保留；intent_id UNIQUE 保证一个意图至多一条转移（幂等）。
CREATE TABLE IF NOT EXISTS transfers (
    serial    bigserial PRIMARY KEY,
    subject   text NOT NULL,
    from_did  text NOT NULL,
    to_did    text NOT NULL,
    c2c       boolean NOT NULL,
    at        timestamptz NOT NULL,
    intent_id text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_transfers_subject_at ON transfers(subject, at);

-- ============================================================
-- 策略上下文（policy）
-- ============================================================

-- 表：监管域。authority/jurisdiction 的管辖声明，纯数据载体。
CREATE TABLE IF NOT EXISTS regulatory_domains (
    domain_id  text PRIMARY KEY,
    authority  text NOT NULL,
    jurisdiction text NOT NULL,
    product_types jsonb NOT NULL,
    credential_schemas jsonb NOT NULL,
    effective_from timestamptz NOT NULL
);

-- 表：策略版本。PK(policy_id, version) 支撑版本化引用
-- （lifecycle_event.policy_version 即此二元组）。
-- required 结构约定：{"credentials":[ctype...],"proofs":[proof_kind...]}，
-- 值均为 snake_case；transitions 为生命周期转移表（from→[to...]）。
CREATE TABLE IF NOT EXISTS policies (
    policy_id    text NOT NULL,
    version      bigint NOT NULL CHECK (version >= 0),
    -- 签发机构 DID（策略可由非监管域主体签发，故不挂 regulatory_domains）
    authority    text,
    jurisdiction text NOT NULL,
    product_type text NOT NULL,
    required     jsonb NOT NULL,
    transitions  jsonb NOT NULL,
    effective_at timestamptz NOT NULL,
    -- NULL = 长期有效；now >= expires_at 即失效
    expires_at   timestamptz,
    active       boolean NOT NULL DEFAULT true,
    PRIMARY KEY (policy_id, version)
);

-- ============================================================
-- 意图上下文（intent）
-- ============================================================

-- 表：意图管道。幂等两层：PK(id) 冲突 + (actor, nonce) UNIQUE 防重放
-- （Task 8 审查确定的约束）。updated_at 由仓储层在每次状态变更时显式
-- 更新（无触发器）。action/status/risk 白名单分别为
-- IntentAction 13 值 / IntentStatus 12 值 / RiskLevel 4 值全集。
CREATE TABLE IF NOT EXISTS intents (
    id           text PRIMARY KEY,
    action       text NOT NULL CHECK (action IN (
        'create_batch','split_batch','merge_batch','transform_batch','create_item',
        'transfer_product','update_custody','issue_credential','revoke_credential',
        'compliance_check','shielded_transfer','submit_state_root','mass_recall')),
    actor        text NOT NULL,
    -- 代理发起时的被代理企业；直发为 NULL
    on_behalf_of text,
    payload      jsonb NOT NULL,
    nonce        bigint NOT NULL CHECK (nonce >= 0),
    status       text NOT NULL CHECK (status IN (
        'created','validated','authorized','policy_checked','proof_required',
        'proved','approved','submitted','confirmed','rejected','expired','cancelled')),
    risk         text NOT NULL CHECK (risk IN ('l1','l2','l3','l4')),
    -- 仅 Rejected 终态有值
    rejection    text,
    -- 仅 Confirmed 终态有值（如链上交易哈希）
    result_ref   text,
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    updated_at   timestamptz NOT NULL,
    UNIQUE (actor, nonce)
);
CREATE INDEX IF NOT EXISTS idx_intents_status ON intents(status);

-- ============================================================
-- 隐私上下文（Shielded Transactions / Private Validium）
-- ============================================================

-- 表：票据承诺。commitment 为 32 字节原始哈希（hex 转换属仓储层）；
-- owner_ot_addr 同为 32 字节摘要；secret/salt 绝不入库（泄漏即双花）。
CREATE TABLE IF NOT EXISTS notes (
    commitment    bytea PRIMARY KEY CHECK (octet_length(commitment) = 32),
    asset_ref     text NOT NULL,
    owner_ot_addr bytea NOT NULL CHECK (octet_length(owner_ot_addr) = 32),
    amount        bigint NOT NULL CHECK (amount > 0),
    created_tx    text
);
CREATE INDEX IF NOT EXISTS idx_notes_created_tx ON notes(created_tx);

-- 表：已消费 nullifier。PK(nf) 即防双花约束本身。
CREATE TABLE IF NOT EXISTS nullifiers (
    nf        bytea PRIMARY KEY CHECK (octet_length(nf) = 32),
    spent_at  timestamptz NOT NULL,
    intent_id text NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nullifiers_intent ON nullifiers(intent_id);

-- 表：Shielded 交易记录。nf/commitment 各自 UNIQUE 约束消费与产生两侧
-- 的幂等；extra 为监管可解密文（EncryptedExtraData 原始字节）。
-- 与 notes/nullifiers 无 FK：隐私表刻意与明文侧解耦，一致性由应用层
-- 同一事务写入保证。
CREATE TABLE IF NOT EXISTS shielded_txs (
    serial     bigserial PRIMARY KEY,
    nf         bytea NOT NULL UNIQUE CHECK (octet_length(nf) = 32),
    commitment bytea NOT NULL UNIQUE CHECK (octet_length(commitment) = 32),
    extra      bytea,
    at         timestamptz NOT NULL
);

-- 表：数据访问授权（监管按需解密的授权记录）。
CREATE TABLE IF NOT EXISTS data_access_grants (
    grantee text NOT NULL,
    dataset text NOT NULL,
    until   timestamptz NOT NULL,
    PRIMARY KEY (grantee, dataset)
);

-- 表：Validium 批次（私有数据可用性）。root 为状态根（32 字节）；
-- batch_ref 唯一对应链上提交引用。
CREATE TABLE IF NOT EXISTS validium_batches (
    root         bytea PRIMARY KEY CHECK (octet_length(root) = 32),
    batch_ref    text NOT NULL UNIQUE,
    proof_id     text,
    submitted_at timestamptz NOT NULL
);

-- ============================================================
-- 证明上下文（zk）
-- ============================================================

-- 表：证明存档。statement_hash 锁定电路输入承诺；proof 为原始证明字节；
-- publics 为公共输入（FieldElement 数组的 JSON 形）。
CREATE TABLE IF NOT EXISTS proofs (
    proof_id       text PRIMARY KEY,
    circuit_id     text NOT NULL,
    circuit_version bigint NOT NULL CHECK (circuit_version >= 0),
    statement_hash bytea NOT NULL CHECK (octet_length(statement_hash) = 32),
    proof          bytea NOT NULL,
    publics        jsonb NOT NULL,
    verified       boolean NOT NULL DEFAULT false
);

-- ============================================================
-- 审计与事件
-- ============================================================

-- 表：审计事件（追加写，不更新不删除）。时间列允许 now() 默认——
-- 审计时间即写入时刻，与业务时间语义不同。
CREATE TABLE IF NOT EXISTS audit_events (
    id             bigserial PRIMARY KEY,
    actor          text NOT NULL,
    agent          text,
    intent_id      text,
    action         text NOT NULL,
    resource       text NOT NULL,
    -- 决策时命中的策略版本（(policy_id, policy_version) 二元组的拆列形；
    -- 未命中策略时均为 NULL）
    policy_id      text,
    policy_version bigint,
    proof_id       text,
    result         text NOT NULL,
    at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_events_intent ON audit_events(intent_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_at ON audit_events(actor, at);

-- 表：领域事件 outbox。dispatched=false 待投递，投递成功后置 true。
CREATE TABLE IF NOT EXISTS domain_events (
    id         bigserial PRIMARY KEY,
    aggregate  text NOT NULL,
    event_type text NOT NULL,
    payload    jsonb NOT NULL,
    dispatched boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);
-- 部分索引：投递扫描只看待投递行
CREATE INDEX IF NOT EXISTS idx_domain_events_pending
    ON domain_events(dispatched) WHERE NOT dispatched;

-- ============================================================
-- 账本锚定（LedgerPort 持久化侧）
-- ============================================================

-- 表：账本锚。kind 白名单 = LedgerItem 8 类的 serde tag 全集
-- （encrypted_extra 对应 EncryptedExtraData；含 Task 26 状态根）。
-- 部分唯一索引：commitment/nullifier 两类锚的 (kind, ref_hash) 幂等——
-- 同一承诺/零花重复锚定直接违例，其余种类允许多次（如 transfer 流水）。
CREATE TABLE IF NOT EXISTS ledger_anchors (
    id         bigserial PRIMARY KEY,
    kind       text NOT NULL CHECK (kind IN (
        'commitment','nullifier','encrypted_extra','transfer','credential_status',
        'lifecycle_change','policy_registered','state_root')),
    ref_hash   bytea NOT NULL CHECK (octet_length(ref_hash) = 32),
    payload    jsonb NOT NULL,
    tx_ref     text,
    status     text NOT NULL CHECK (status IN ('pending','anchored')),
    created_at timestamptz NOT NULL DEFAULT now(),
    -- NULL = 尚未上链（pending）
    anchored_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_ledger_anchors_idempotent
    ON ledger_anchors(kind, ref_hash)
    WHERE kind IN ('commitment','nullifier');
