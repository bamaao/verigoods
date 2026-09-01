-- 0004：transfers 补记录列 + batch_lineage 补时间列（Task 16）。
--
-- 动机：0001 的 transfers 表按"应用层经 intent 写流水"的旧口径设计，
-- 而所有权上下文重构后（aa058e3）端口 record_transfer 落的是领域值对象
-- TransferRecord——幂等键是 record.id（非 intent_id），且携带计数快照
-- （transfer_count/c2c_count，审计回放核对计数连续性）。0001 无这些列。
-- 迁移纪律：0001 已锁定不可改，故以新增 000N 方式变更；0004 应用后同样锁定。

-- 记录 ID：仓储 record_transfer 的幂等键。应用层（Task 20 组装）直接写
-- transfers 的行可能没有记录 ID，故可空 + 部分唯一（NULL 不参与唯一性）。
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS record_id text;
CREATE UNIQUE INDEX IF NOT EXISTS uq_transfers_record_id
    ON transfers(record_id) WHERE record_id IS NOT NULL;

-- 计数快照：本次转移自增后的累计值（对应合约 OwnershipTransferred 携带的计数）。
-- DEFAULT 0 服务直接裸写流水的旧路径；仓储 record_transfer 一律显式提供。
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS transfer_count bigint NOT NULL DEFAULT 0 CHECK (transfer_count >= 0);
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS c2c_count      bigint NOT NULL DEFAULT 0 CHECK (c2c_count >= 0);

-- intent_id 可空化：TransferRecord 不携带 intent（intent 是写入口径概念，
-- 存在于 intents 表与 lifecycle_events.intent_id，不属于审计事实本体）。
-- 原 UNIQUE 保留——NULL 在 PostgreSQL 唯一索引中互不冲突，旧幂等语义不变。
ALTER TABLE transfers ALTER COLUMN intent_id DROP NOT NULL;

-- 谱系边时间：LineageEdge.at 是领域结构字段（拆分/合并的记账时刻），
-- 0001 无该列会导致回读谱系边丢失时间。存量行（若有）以迁移时刻补齐。
ALTER TABLE batch_lineage ADD COLUMN IF NOT EXISTS at timestamptz NOT NULL DEFAULT now();
