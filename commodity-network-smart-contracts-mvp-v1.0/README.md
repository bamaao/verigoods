# Enterprise Verifiable Commodity Network — Smart Contracts MVP

这是一个面向 Polygon CDK 商品生命周期网络的 Solidity 智能合约 MVP。

## 核心模块

- `IdentityRegistry`：DID → 主体身份与操作密钥
- `CredentialRegistry`：VC/凭证的链上哈希、状态、签发与撤销
- `ProductRegistry`：商品类型注册
- `BatchRegistry`：批次创建、拆分、合并与 lineage
- `AssetRegistry`：独立商品/高价值单品登记
- `OwnershipRegistry`：所有权状态与转移
- `LifecycleRegistry`：商品生命周期状态
- `ComplianceRegistry`：ZK 合规证明结果与监管域
- `PolicyRegistry`：监管 Policy 版本锚定
- `ProofRegistry`：通用 ZK proof 验证结果登记
- `CommodityNetwork`：统一门面合约，串联核心状态转换

## 重要设计

1. 原始业务数据、完整 VC、检测报告、IoT 数据不直接上链。
2. 链上保存 ID、Hash/Commitment、状态、事件、Policy 版本和 Proof 状态。
3. 真实 ZK verifier 应在部署时接入 Plonky3 生成的验证器适配层；当前 `ProofRegistry` 提供接口边界与开发期 verifier。
4. 所有权和 Custody 分离；本 MVP 重点实现 Ownership。
5. 合约使用 OpenZeppelin 的 AccessControl / ReentrancyGuard / Pausable。
6. 本代码是架构级 MVP，不应未经安全审计直接用于生产资产托管或大额交易。

## 推荐工程

建议使用 Foundry：

```bash
forge build
forge test
```

部署到 Polygon CDK 时，将各 registry 按网络地址初始化，然后由 `CommodityNetwork` 统一编排。
