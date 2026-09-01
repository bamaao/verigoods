-- 0003：生命周期事件表（Task 16）。
--
-- 动机：lifecycle 端口 LifecycleRepository 是追加式事件日志，0001 只规划了
-- batches/assets 上的状态快照列，没有事件事实表；history/current_state
-- 均以本表为唯一事实源（current_state = 最后一条事件的 to）。
-- 迁移纪律：0001/0002 已锁定不可改，故以新增 000N 方式变更；0003 应用后同样锁定。

CREATE TABLE IF NOT EXISTS lifecycle_events (
    -- 幂等键：端口 append 按 event.id 去重（ON CONFLICT DO NOTHING）
    id             text PRIMARY KEY,
    -- batch:<id> / asset:<id>（SubjectRef 落库唯一编码，见仓储层 encode_subject）
    subject        text NOT NULL,
    -- from/to 白名单与 0001 batches.state 的 CHECK 完全一致（LifecycleState 13 值）
    from_state     text NOT NULL CHECK (from_state IN (
        'created','produced','inspected','in_transit','in_warehouse','available',
        'delisted','sold','owned','resold','recalled','expired','destroyed')),
    to_state       text NOT NULL CHECK (to_state IN (
        'created','produced','inspected','in_transit','in_warehouse','available',
        'delisted','sold','owned','resold','recalled','expired','destroyed')),
    -- 变更原因（召回公告号等）；可为空
    reason         text,
    -- 触发变更的 Intent（唯一写入口径回溯）
    intent_id      text NOT NULL,
    -- 关联 ZK 证明；可为空
    proof_id       text,
    -- 变更时生效的策略版本；可为空
    policy_version bigint,
    at             timestamptz NOT NULL
);

-- history / current_state 按主体 + 时间扫描
CREATE INDEX IF NOT EXISTS idx_lifecycle_events_subject_at ON lifecycle_events(subject, at);
-- 按 Intent 回查（一个意图至多一次状态变更的影响面排查）
CREATE INDEX IF NOT EXISTS idx_lifecycle_events_intent ON lifecycle_events(intent_id);
