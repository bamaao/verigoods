//! privacy 上下文：双隐私模式（Shielded Transactions + Private Validium）的领域原语。
//!
//! - [`stealth`]：隐形地址（压缩点 / 元地址 / 一次性地址）；
//! - [`note`]：隐私票据（承诺前像规范编码、nullifier 域分隔）；
//! - [`extra`]：监管可解密的加密附加数据。
//!
//! 实际密码学运算（Poseidon2 host-hash、ECDH 派生/扫描、ECIES）全部位于
//! vg-infra-crypto（Task 10），依赖方向 infra → domain；
//! 领域层只定义数据原语与 [`crate::ports::NoteHasher`] 端口。

pub mod extra;
pub mod note;
pub mod stealth;

pub use extra::EncryptedExtraData;
pub use note::Note;
pub use stealth::{CompressedPoint, OneTimeAddress, StealthMetaAddress};
