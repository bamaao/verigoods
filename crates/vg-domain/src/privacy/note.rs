//! 隐私票据（Note）：Shielded Transactions 的核心值对象。
//!
//! 一张 Note 绑定「资产 × 收款方一次性地址 × 金额 × 秘密」，消费时在 ZK 电路内
//! 证明对某张未消费 Note 的知识（note_opening），对链上仅暴露承诺
//! （[commitment](Note::commitment)）与 nullifier（[nullifier](Note::nullifier)）。

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::shared::{DomainError, Hash32, SubjectRef};

/// Note 哈希端口（见 `crate::ports::NoteHasher`，Task 10 的 vg-infra-crypto
/// poseidon.rs 将以 p3-poseidon2（KoalaBear）实现，与电路保持一致）。
use crate::ports::NoteHasher;

/// 隐私票据。
///
/// serde 规范形（JSON）：
/// ```json
/// {
///   "asset_ref": {"type": "batch", "id": "..."},
///   "owner_ot_addr": "<64 hex>",
///   "amount": 10,
///   "secret": "<64 hex>",
///   "salt": "<32 hex>"
/// }
/// ```
/// `owner_ot_addr` / `secret` / `salt` 以 hex 字符串表达；
/// 反序列化为手写实现并委托 [`Note::new`] 校验（禁止 transparent derive）。
///
/// **泄漏警告**：完整 Note JSON 含**明文 secret**——知道 secret 即可构造
/// nullifier 完成双花。严禁将 Note（含其 Debug 表示）写入日志、tracing 或
/// 任何公共载荷；链上/库内只允许承诺与 nullifier 形态，明文 Note 仅存在于
/// 持有者本地。
///
/// 字段全部私有，只能经 [`Note::new`] 构造（保证 amount>0、secret 非全零
/// 的不变量不被结构体字面量绕过），读取走访问器。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Note {
    /// 票据指向的资产（批次或单品）。
    asset_ref: SubjectRef,
    /// 收款方一次性地址摘要（= [`OneTimeAddress::addr_digest`](super::stealth::OneTimeAddress::addr_digest)）。
    owner_ot_addr: Hash32,
    /// 金额（必须 > 0）。
    amount: u64,
    /// 票据秘密（32 字节，不得全零；消费证明的私有 witness 之一）。
    secret: [u8; 32],
    /// 盐（16 字节，保证同参数票据承诺互异）。
    salt: [u8; 16],
}

impl Note {
    /// 构造并校验：`amount > 0` 且 `secret` 非全零。
    ///
    /// `secret` 应**每张票据唯一**：复用同一 secret 会使同一 ctx_domain 下
    /// 的 nullifier 碰撞（观感上一次消费即双双花）。
    pub fn new(
        asset_ref: SubjectRef,
        owner_ot_addr: Hash32,
        amount: u64,
        secret: [u8; 32],
        salt: [u8; 16],
    ) -> Result<Self, DomainError> {
        if amount == 0 {
            return Err(DomainError::InvalidInput("票据金额必须大于 0".into()));
        }
        if secret == [0u8; 32] {
            return Err(DomainError::InvalidInput("票据 secret 不得为全零".into()));
        }
        Ok(Self {
            asset_ref,
            owner_ot_addr,
            amount,
            secret,
            salt,
        })
    }

    /// 票据指向的资产（批次或单品）。
    pub fn asset_ref(&self) -> &SubjectRef {
        &self.asset_ref
    }

    /// 收款方一次性地址摘要。
    pub fn owner_ot_addr(&self) -> Hash32 {
        self.owner_ot_addr
    }

    /// 金额（构造时保证 > 0）。
    pub fn amount(&self) -> u64 {
        self.amount
    }

    /// 票据秘密。**敏感**：知道 secret 即可构造 nullifier，调用方不得将其
    /// 写入日志/公共载荷。
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// 盐。
    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// 承诺前像的规范编码（**规范写死，Task 10 / Task 11 的 Poseidon2
    /// host-hash 与 note_opening 电路必须按同一编码实现**）。
    ///
    /// 返回 6 个 32 字节词（小端编码约定）：
    ///
    /// | 序号 | 内容 |
    /// |------|------|
    /// | 0 | 域分隔标签：`keccak256("vg:note:v1")`（防跨域承诺碰撞） |
    /// | 1 | `keccak256(asset_ref 的 serde 相邻标签规范形 JSON 字节)`，即 `keccak256('{"type":"batch","id":"..."}')` |
    /// | 2 | `owner_ot_addr` 原始 32 字节 |
    /// | 3 | `amount` 单词：32 字节**小端**编码 |
    /// | 4 | `secret` 原始 32 字节 |
    /// | 5 | `salt` 单词：高 16 字节填零、低 16 字节为 salt |
    ///
    /// **32 字节词 → KoalaBear 域元素的规范映射**：KoalaBear 素数约 2^64，
    /// 单个 32 字节词不是单域元素。Task 10（NoteHasher 实现）与 Task 11
    /// （电路）中，每个 32 字节词按确定性映射拆分为 **4 个连续小端 64-bit
    /// limb**（不做归约/拒绝），即词 b[0..32] → u64_le(b[0..8]) .. u64_le(b[24..32])；
    /// 该拆分只存在于 hash/电路内部且两侧必须完全一致。
    ///
    /// **确定性前提**：asset 词依赖 SubjectRef 保持 derive 结构体序列化
    /// （非 map）且各 Id 为纯字符串；未来给 SubjectRef/Id 增加字段前必须
    /// 评估并同步更新承诺编码版本与 golden vector。
    ///
    /// 防漂移锚点：见测试 `commitment_parts_golden_vector`（VC 哈希 golden
    /// vector 7415289d... 先例）——**改动编码必须同步更新该向量与
    /// Task 10/11 实现**。
    pub fn commitment_parts(&self) -> Vec<[u8; 32]> {
        let label = Hash32::keccak(b"vg:note:v1");
        // serde_json 对固定字段的序列化是确定性的（键序固定为 type, id）
        let asset_json =
            serde_json::to_vec(&self.asset_ref).expect("SubjectRef 序列化不可失败");
        let asset_word = Hash32::keccak(&asset_json);

        let mut amount_word = [0u8; 32];
        amount_word[..8].copy_from_slice(&self.amount.to_le_bytes());

        let mut salt_word = [0u8; 32];
        salt_word[16..].copy_from_slice(&self.salt);

        vec![
            *label.as_bytes(),
            *asset_word.as_bytes(),
            *self.owner_ot_addr.as_bytes(),
            amount_word,
            self.secret,
            salt_word,
        ]
    }

    /// 计算票据承诺：`hasher.note_commitment(self.commitment_parts())`。
    ///
    /// plan 原注释签名无 hasher 参数，但 Poseidon2 host-hash 由 Task 10 在
    /// infra 实现、且依赖方向限定 infra → domain，领域层只能以端口注入
    /// （授权签名修正，见 `ports::NoteHasher`）。
    pub fn commitment(&self, hasher: &dyn NoteHasher) -> Hash32 {
        hasher.note_commitment(&self.commitment_parts())
    }

    /// 计算 nullifier：`keccak256(secret ‖ ctx_domain)`。
    ///
    /// 域分隔 `ctx_domain` 防止同一张票据在不同上下文（如不同合约/链/子协议）
    /// 之间被跨域重放双花——不同 ctx 得到不同 nullifier，各自独立消费。
    /// 注意 `secret` 应每票据唯一：复用会使同 ctx 下 nullifier 碰撞
    /// （观感上一次消费即双双花）。
    pub fn nullifier(&self, ctx_domain: &str) -> Hash32 {
        let mut buf = Vec::with_capacity(32 + ctx_domain.len());
        buf.extend_from_slice(&self.secret);
        buf.extend_from_slice(ctx_domain.as_bytes());
        Hash32::keccak(&buf)
    }
}

/// 序列化辅助：定长字节数组 → hex 字符串。
fn ser_bytes<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(bytes))
}

impl Serialize for Note {
    /// 按「规范形」文档中的 JSON 结构序列化（secret/salt/owner 为 hex）。
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Shadow<'a> {
            asset_ref: &'a SubjectRef,
            owner_ot_addr: &'a Hash32,
            amount: u64,
            #[serde(serialize_with = "ser_arr_32")]
            secret: &'a [u8; 32],
            #[serde(serialize_with = "ser_arr_16")]
            salt: &'a [u8; 16],
        }
        fn ser_arr_32<S: Serializer>(v: &&[u8; 32], s: S) -> Result<S::Ok, S::Error> {
            ser_bytes(*v, s)
        }
        fn ser_arr_16<S: Serializer>(v: &&[u8; 16], s: S) -> Result<S::Ok, S::Error> {
            ser_bytes(*v, s)
        }
        Shadow {
            asset_ref: &self.asset_ref,
            owner_ot_addr: &self.owner_ot_addr,
            amount: self.amount,
            secret: &self.secret,
            salt: &self.salt,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Note {
    /// 手写反序列化，强制委托 [`Note::new`] 校验（amount > 0、secret 非全零、
    /// hex 解码与长度检查），非法输入映射为 serde 数据错误。
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Shadow {
            asset_ref: SubjectRef,
            owner_ot_addr: Hash32,
            amount: u64,
            secret: String,
            salt: String,
        }
        /// 定长字节 hex 解码（错误类型走 serde::de::Error，避免借用外层泛型）。
        fn decode_fixed<E: serde::de::Error, const N: usize>(
            s: &str,
            what: &str,
        ) -> Result<[u8; N], E> {
            let bytes = hex::decode(s).map_err(E::custom)?;
            bytes
                .try_into()
                .map_err(|_| E::custom(format!("{what} 必须为 {N} 字节 hex")))
        }
        let raw = Shadow::deserialize(deserializer)?;
        let secret: [u8; 32] = decode_fixed(&raw.secret, "secret")?;
        let salt: [u8; 16] = decode_fixed(&raw.salt, "salt")?;
        Note::new(raw.asset_ref, raw.owner_ot_addr, raw.amount, secret, salt)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::BatchId;

    /// 测试用 stub 哈希器：keccak(所有词顺序拼接)——仅验证调用路径与确定性，
    /// 真实 Poseidon2 由 Task 10 提供。
    struct StubHasher;

    impl NoteHasher for StubHasher {
        fn note_commitment(&self, parts: &[[u8; 32]]) -> Hash32 {
            let mut buf = Vec::with_capacity(parts.len() * 32);
            for p in parts {
                buf.extend_from_slice(p);
            }
            Hash32::keccak(&buf)
        }
    }

    fn sample_note() -> Note {
        let mut secret = [0u8; 32];
        secret[0] = 0xAA;
        let mut salt = [0u8; 16];
        salt[..4].copy_from_slice(&[1, 2, 3, 4]);
        Note::new(
            SubjectRef::Batch(BatchId::new("batch-007")),
            Hash32::keccak(b"ot-addr"),
            10,
            secret,
            salt,
        )
        .expect("样本构造应成功")
    }

    // ---- Note::new 校验 ----

    #[test]
    fn new_rejects_zero_amount_and_zero_secret() {
        let mut secret = [0u8; 32];
        secret[1] = 1;
        let err = Note::new(
            SubjectRef::Batch(BatchId::new("b")),
            Hash32::ZERO,
            0,
            secret,
            [0u8; 16],
        )
        .expect_err("amount == 0 应被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)));

        let err = Note::new(
            SubjectRef::Batch(BatchId::new("b")),
            Hash32::ZERO,
            1,
            [0u8; 32],
            [0u8; 16],
        )
        .expect_err("secret 全零应被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)));
    }

    #[test]
    fn accessors_expose_fields() {
        let note = sample_note();
        assert_eq!(note.asset_ref(), &SubjectRef::Batch(BatchId::new("batch-007")));
        assert_eq!(note.owner_ot_addr(), Hash32::keccak(b"ot-addr"));
        assert_eq!(note.amount(), 10);
        assert_eq!(note.secret().len(), 32);
        assert_eq!(note.salt().len(), 16);
    }

    // ---- nullifier ----

    #[test]
    fn nullifier_domain_separation() {
        let note = sample_note();
        let n1 = note.nullifier("vg:shield:v1");
        let n2 = note.nullifier("vg:validium:v1");

        // 同 Note 不同 ctx → 不同值
        assert_ne!(n1, n2, "不同 ctx_domain 必须产生不同 nullifier");
        // 同 ctx 同 Note → 稳定
        assert_eq!(n1, note.nullifier("vg:shield:v1"));
        // 与 keccak(secret ‖ domain) 直接计算一致
        let mut buf = Vec::new();
        buf.extend_from_slice(note.secret());
        buf.extend_from_slice(b"vg:shield:v1");
        assert_eq!(n1, Hash32::keccak(&buf));
    }

    #[test]
    fn nullifier_changes_with_secret() {
        // 通过 new 构造仅 secret 不同的两张票据，验证 nullifier 依赖 secret
        let base = sample_note();
        let mut other_secret = *base.secret();
        other_secret[31] ^= 0x01;
        let other = Note::new(
            base.asset_ref().clone(),
            base.owner_ot_addr(),
            base.amount(),
            other_secret,
            *base.salt(),
        )
        .expect("仅改 secret 的构造应成功");
        assert_ne!(other.nullifier("ctx"), base.nullifier("ctx"));
    }

    // ---- commitment_parts ----

    #[test]
    fn commitment_parts_deterministic_and_sized() {
        let note = sample_note();
        let p1 = note.commitment_parts();
        let p2 = note.commitment_parts();
        assert_eq!(p1, p2, "同一 Note 的前像编码必须确定");
        // 规范写死：6 个词
        assert_eq!(
            p1.len(),
            6,
            "规范：域标签 + asset + owner + amount + secret + salt"
        );

        // 词 1：asset 词 = keccak(canonical JSON)
        let asset_json = serde_json::to_vec(note.asset_ref()).unwrap();
        assert_eq!(p1[1], *Hash32::keccak(&asset_json).as_bytes());
        // 词 2：owner 原样
        assert_eq!(p1[2], *note.owner_ot_addr().as_bytes());
        // 词 3：amount 小端（低 8 字节）
        let mut expect_amount = [0u8; 32];
        expect_amount[..8].copy_from_slice(&note.amount().to_le_bytes());
        assert_eq!(p1[3], expect_amount);
        // 词 4：secret 原样
        assert_eq!(p1[4], *note.secret());
        // 词 5：salt 高 16 字节填零
        assert_eq!(&p1[5][16..], note.salt());
        assert_eq!(&p1[5][..16], &[0u8; 16]);
    }

    /// **前像黄金向量**（防漂移锚点，对标 VC 哈希 golden vector 7415289d... 先例）：
    /// 全字面量示例 Note 的 6 词完整前像。任何编码改动（词序/编码方式/域标签/
    /// asset 规范形）都会使本测试失败——**改动编码必须同步更新此向量与
    /// Task 10（NoteHasher/Poseidon2）及 Task 11（note_opening 电路）实现**。
    #[test]
    fn commitment_parts_golden_vector() {
        let owner = Hash32::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let mut secret = [0u8; 32];
        secret[0] = 0x22;
        let mut salt = [0u8; 16];
        salt[..4].copy_from_slice(&[0x33, 0x44, 0x55, 0x66]);
        let note = Note::new(
            SubjectRef::Batch(BatchId::new("golden-1")),
            owner,
            7,
            secret,
            salt,
        )
        .expect("黄金向量构造应成功");

        let parts = note.commitment_parts();
        let word = |hex: &str| -> [u8; 32] {
            let b = hex::decode(hex).expect("golden hex 合法");
            b.try_into().expect("golden hex 恰为 32 字节")
        };
        assert_eq!(parts[0], word("a4c41c2383a5fd0b250bce28a902ebfb3480349f8714a9232a3dd279831f061d"), "词 0：域分隔标签 keccak(\"vg:note:v1\")");
        assert_eq!(parts[1], word("0ac2d6796d51fb5318755791b4b3e1e9180d58e74167ea2a71c81b4cbe41be52"), "词 1：asset 词 keccak(canonical JSON of golden-1)");
        assert_eq!(parts[2], word("1111111111111111111111111111111111111111111111111111111111111111"), "词 2：owner 原样");
        assert_eq!(parts[3], word("0700000000000000000000000000000000000000000000000000000000000000"), "词 3：amount=7 小端");
        assert_eq!(parts[4], word("2200000000000000000000000000000000000000000000000000000000000000"), "词 4：secret 原样");
        assert_eq!(parts[5], word("0000000000000000000000000000000033445566000000000000000000000000"), "词 5：salt 高 16 字节填零（低 16 字节 = 33445566 左对齐）");
    }

    #[test]
    fn commitment_parts_change_with_every_field() {
        let base = sample_note();
        let base_parts = base.commitment_parts();

        // 全部通过 Note::new 构造（字段私有），每次只变一个参数
        let with_salt = Note::new(
            base.asset_ref().clone(),
            base.owner_ot_addr(),
            base.amount(),
            *base.secret(),
            {
                let mut s = *base.salt();
                s[0] ^= 0x01;
                s
            },
        )
        .unwrap();
        let with_amount = Note::new(
            base.asset_ref().clone(),
            base.owner_ot_addr(),
            base.amount() + 1,
            *base.secret(),
            *base.salt(),
        )
        .unwrap();
        let with_secret = Note::new(
            base.asset_ref().clone(),
            base.owner_ot_addr(),
            base.amount(),
            {
                let mut s = *base.secret();
                s[7] ^= 0x01;
                s
            },
            *base.salt(),
        )
        .unwrap();
        let with_owner = Note::new(
            base.asset_ref().clone(),
            Hash32::keccak(b"other-owner"),
            base.amount(),
            *base.secret(),
            *base.salt(),
        )
        .unwrap();

        for changed in [
            with_salt.commitment_parts(),
            with_amount.commitment_parts(),
            with_secret.commitment_parts(),
            with_owner.commitment_parts(),
        ] {
            assert_ne!(changed, base_parts, "任一字段变化必须改变前像编码");
        }
    }

    // ---- commitment ----

    #[test]
    fn commitment_via_stub_hasher_is_deterministic() {
        let hasher = StubHasher;
        let note = sample_note();
        let c1 = note.commitment(&hasher);
        let c2 = note.commitment(&hasher);
        assert_eq!(c1, c2, "同 Note 两次承诺必须一致");

        // stub 语义：keccak(parts 拼接) 手算一致（锁定调用路径确实消费 parts）
        let mut buf = Vec::new();
        for p in note.commitment_parts() {
            buf.extend_from_slice(&p);
        }
        assert_eq!(c1, Hash32::keccak(&buf));

        // 不同 Note → 不同承诺
        let other = Note::new(
            note.asset_ref().clone(),
            note.owner_ot_addr(),
            note.amount(),
            *note.secret(),
            {
                let mut s = *note.salt();
                s[15] ^= 0x01;
                s
            },
        )
        .unwrap();
        assert_ne!(other.commitment(&hasher), c1);
    }

    // ---- serde ----

    #[test]
    fn note_serde_roundtrip() {
        let note = sample_note();
        let json = serde_json::to_string(&note).expect("序列化应成功");
        let back: Note = serde_json::from_str(&json).expect("合法输入应往返");
        assert_eq!(back, note);

        // 线上格式：secret/salt 为 hex 字符串、amount 为数字
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["secret"].is_string() && v["secret"].as_str().unwrap().len() == 64);
        assert!(v["salt"].is_string() && v["salt"].as_str().unwrap().len() == 32);
        assert_eq!(v["amount"], serde_json::json!(10));
        assert_eq!(
            v["owner_ot_addr"],
            serde_json::json!(note.owner_ot_addr().to_string())
        );
    }

    #[test]
    fn note_deserialize_rejects_invalid() {
        let note = sample_note();
        let good: serde_json::Value = serde_json::to_value(&note).unwrap();

        // amount == 0（绕过 new 校验的尝试必须失败）
        let mut bad = good.clone();
        bad["amount"] = serde_json::json!(0);
        assert!(serde_json::from_value::<Note>(bad).is_err());

        // secret 全零
        let mut bad = good.clone();
        bad["secret"] = serde_json::json!("00".repeat(32));
        assert!(serde_json::from_value::<Note>(bad).is_err());

        // 坏 hex
        let mut bad = good.clone();
        bad["secret"] = serde_json::json!("nothex!");
        assert!(serde_json::from_value::<Note>(bad).is_err());

        // 长度错误（secret 64→32 hex；salt 32→31 hex）
        let mut bad = good.clone();
        bad["salt"] = serde_json::json!("ab".repeat(31));
        assert!(serde_json::from_value::<Note>(bad).is_err());

        // 缺字段
        let mut bad = good.clone();
        bad.as_object_mut().unwrap().remove("salt");
        assert!(serde_json::from_value::<Note>(bad).is_err());
    }
}
