-- 0002：dids.jurisdiction 改为 NULLABLE。
--
-- 动机：领域模型 DidDocument.jurisdiction 为 Option<String>，而 0001 中
-- 该列 NOT NULL 会丢掉 None 语义（只能以空串冒充，污染数据口径）。
-- 迁移纪律：0001 已锁定不可改，故以新增 000N 方式变更；0002 应用后同样锁定。
ALTER TABLE dids ALTER COLUMN jurisdiction DROP NOT NULL;
