-- 审批待办（Task 19，0006）：L3/L4 风险动作在 Approved 之前的人工审批门。
-- 生命周期：IntentEngine 在 handler 判定 AwaitingApproval 时 upsert 未决行；
-- approve(intent_id, approver) 校验审批人角色后 mark_decided（decided_by/at
-- 一次性写入，之后不再可变——审批结论不可篡改）。
-- CASCADE 可接受：intent 删除连带审批待办清理（intent 本身按审计要求长期保留，
-- 删除路径实际不存在，级联属兜底）。
CREATE TABLE IF NOT EXISTS approvals (
    -- 关联意图（一意图至多一条审批待办）
    intent_id     text PRIMARY KEY REFERENCES intents(id) ON DELETE CASCADE,
    -- 审批人 SubjectKind snake_case（如 regulator/enterprise）；Phase1 审批人
    -- 校验 = SubjectKind 匹配，capability 层面语义由该角色承担
    required_role text NOT NULL,
    -- 审批人 DID；未决 NULL，已决策一次性写入
    decided_by    text,
    -- 决策时刻；未决 NULL
    decided_at    timestamptz
);
