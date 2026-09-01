-- 0005：InProcessLedger 链式状态专用单行表（Task 18）。
--
-- 模拟 Polygon CDK 账本的链根推进状态：root 为当前链根
-- （新根 = keccak(前根 ‖ ref_hash)，初始 32 字节全零），seq 为已
-- 锚定条目序号（tx_ref = "inprocess:<seq>"）。单行表（id=1 恒定），
-- 并发推进由该行上的行锁串行化。
CREATE TABLE IF NOT EXISTS ledger_state (
    id   int PRIMARY KEY CHECK (id = 1),
    root bytea NOT NULL CHECK (octet_length(root) = 32),
    seq  bigint NOT NULL CHECK (seq >= 0)
);

-- 初始行：零根 + 序号 0；decode/repeat 写法不依赖服务端 locale 与
-- 转义配置（standard_conforming_strings），可移植且幂等可重跑。
INSERT INTO ledger_state (id, root, seq)
VALUES (1, decode(repeat('00', 32), 'hex'), 0)
ON CONFLICT DO NOTHING;
