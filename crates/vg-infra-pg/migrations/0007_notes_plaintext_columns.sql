-- 0007：notes 表补充扫描与花费所需明文列（Task 21，Shielded Transactions）。
--
-- 私库存储口径：Private Validium 模式下 Note 明文仅存私有 PG（链上只锚
-- 承诺与 nullifier），接收方扫描/后续构造 nullifier 花费均依赖以下列：
-- - addr_point / ephemeral：一次性地址的 33 字节压缩点对（扫描用，
--   StealthMetaAddress 协议的公布值，接收方以 view 私钥做 ECDH 试算）；
-- - secret / salt：Note 花费密钥（接收方日后作为发送方构造 nullifier）。
-- 本阶段 notes 表无存量数据，直接 NOT NULL（无背填问题）。
-- asset_ref 沿用单列 text（crate 统一 encode_subject 口径），不加拆列。
ALTER TABLE notes ADD COLUMN addr_point bytea NOT NULL CHECK (octet_length(addr_point) = 33);
ALTER TABLE notes ADD COLUMN ephemeral bytea NOT NULL CHECK (octet_length(ephemeral) = 33);
ALTER TABLE notes ADD COLUMN secret bytea NOT NULL CHECK (octet_length(secret) = 32);
ALTER TABLE notes ADD COLUMN salt bytea NOT NULL CHECK (octet_length(salt) = 16);
