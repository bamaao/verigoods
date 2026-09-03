# VeriGoods 后端

可验证商品生命周期网络后端（Phase1+2 范围）：商品从生产、流通到消费的全生命周期，
以 DID 身份 + 可验证凭证 + 生命周期状态机 + 双隐私模式（Shielded Transactions /
Private Validium）+ ZK 证明 + 链上锚定构成可验证、可监管、保护商业隐私的追踪网络。

- 设计文档：[`docs/plans/2026-08-24-verigoods-backend-design.md`](docs/plans/2026-08-24-verigoods-backend-design.md)
- 实施计划（29 任务）：[`docs/plans/2026-08-24-verigoods-backend-plan.md`](docs/plans/2026-08-24-verigoods-backend-plan.md)

## 架构

```text
                ┌────────────────────────────────────────────┐
                │  vg-api（HTTP 入口）                        │
                │  VG-SIG 鉴权中间件 · REST /api/v1 · /mcp    │
                └───────────────────┬────────────────────────┘
                                    │ 唯一写入口径：Intent
                ┌───────────────────▼────────────────────────┐
                │  vg-application（IntentEngine 管道）        │
                │  execute/approve · handlers · services     │
                │  （合规重算 / 隐形转账 / validium 批次）     │
                └───────────────────┬────────────────────────┘
                                    │ 依赖倒置（端口 trait）
                ┌───────────────────▼────────────────────────┐
                │  vg-domain（领域层，零外部依赖）             │
                │  聚合：identity / commodity / ownership /   │
                │  lifecycle / policy / credential / intent / │
                │  privacy · 端口：LedgerPort / ProofProver / │
                │  NoteHasher / 各 Repository                 │
                └───┬──────────┬──────────┬──────────┬────────┘
                    ▼          ▼          ▼          ▼
              vg-infra-pg  vg-infra-crypto vg-infra-zk  vg-infra-chain
              （sqlx 仓储、（k256/keccak/（Plonky3 真实 （alloy → Polygon
              审计/outbox/ Poseidon/ECIES 电路：range/  CDK，feature
              approvals/  隐形地址/可恢 coldchain/note chain-alloy 门控）
              迁移）       复签名）      opening）
```

核心不变式：**任何写动作都是一条 Intent**，经 IntentEngine 管道
（校验 → 授权 → SAVEPOINT 业务段 → 审批门 → 状态推进 → 审计 → outbox）
落地；REST 与 MCP 只是两种触发面。

## 技术栈

| 组件 | 选型 |
| --- | --- |
| 语言 / 运行时 | Rust 1.96 + tokio |
| HTTP | Axum 0.8 |
| 存储 | PostgreSQL 17 + sqlx 0.8（运行时查询，`sqlx::test` 自动隔离库） |
| ZK | Plonky3（p3-* 0.7.0-rc.1，KoalaBear 场） |
| MCP | rmcp 3.2（server + streamable-http transport） |
| 链层 | alloy 2.4（feature `chain-alloy` 门控，默认零编译成本）→ Polygon CDK |
| 密码学 | k256（secp256k1 / keccak 预哈希可恢复签名）、Poseidon2、ECIES（stealth address） |

## 快速启动

```text
# 1) 启动 PostgreSQL（Windows 服务名示例）
net start postgresql-x64-17

# 2) 建库（一次性）
psql "postgres://postgres@localhost:5432/postgres" -c "CREATE DATABASE verigoods"

# 3) .env（项目根目录；已有则跳过）
#    DATABASE_URL=postgres://postgres@localhost:5432/verigoods
#    BIND_ADDR=0.0.0.0:8080
#    RUST_LOG=info,vg_api=debug
#    可选 VG_PROVER=transparent（需 --features transparent，调试用明文证明）

# 4) 启动（bootstrap 自动应用全部迁移）
cargo run -p vg-api

# 5) 冒烟
curl -i http://127.0.0.1:8080/health    # 期望 200
```

### 演示数据

```text
cargo run -p vg-application --example seed_demo
```

注入一套可复用的演示数据（3 个固定私钥 DID、CN/food 监管域与 2 条策略、
产品/批次、食品安全 VC），并现场打印一条可复制的 VG-SIG 签名头示例
（ts/nonce 时效 ±300 秒且 nonce 一次性，演示头约 5 分钟内有效）。
幂等可重跑（已存在即跳过）。

## 测试

```text
# 全量（sqlx::test 为每个测试自动建隔离临时库）
DATABASE_URL=postgres://postgres@localhost:5432/verigoods cargo test --workspace

# feature 组合
cargo test -p vg-api --features mcp-mock-auth   # MCP 场景（测试专用 actor 直通，严禁生产）
cargo test -p vg-api --features transparent     # 明文证明模式
cargo clippy -p vg-infra-chain --features chain-alloy -- -D warnings
```

链上集成测试（alloy 适配器，需 WSL kurtosis-cdk 环境，见下）默认 `#[ignore]`：

```text
cargo test -p vg-infra-chain --features chain-alloy -- --ignored
```

## 鉴权（VG-SIG）

除免签白名单外，所有请求必须携带 `VG-SIG` 请求头：

```text
VG-SIG: did="did:vg:<64hex>", sig="0x<130hex>", ts=<unix秒>, nonce="<随机串>"

待签名消息 = "vg:sig:v1\n{METHOD}\n{path}\n{ts}\n{nonce}"
sig = ecdsa_recoverable(keccak256(msg))，编码为 65 字节 r||s||v hex（0x 前缀）
v 取 27/28（服务端解析时归一化为 RecoveryId 0/1）
```

- `path` 不含 query；ts 漂移 ±300s 外拒绝；nonce 一次性（重放即 401）。
- 公钥比对口径：`keccak256(33 字节压缩 sec1)` 与 DID 文档活跃验证方法的摘要一致。

免签端点白名单：

| 端点 | 说明 |
| --- | --- |
| `GET /health` | 存活探针 |
| `GET /api/v1/consumer`、`GET /api/v1/consumer/*` | 消费者只读视图（精确段匹配） |
| `POST /api/v1/dids` | DID 注册引导（insert-only + did 自派生绑定，重复注册 409） |

密钥轮换走 `PUT /api/v1/dids`（需签名）。

## MCP 接入

服务端点：`http://127.0.0.1:8080/mcp`（rmcp streamable-http）。
Claude 配置示例：

```json
{
  "mcpServers": {
    "verigoods": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:8080/mcp"
    }
  }
}
```

> **已知限制（Phase1）**：标准 MCP 客户端（含 Claude）不支持为 streamable-http
> 端点注入自定义 `VG-SIG` 头，因此无法直接通过生产鉴权。需要自研客户端或
> 在网关侧注入签名头。测试可用 `--features mcp-mock-auth` 放行（固定测试
> actor，**严禁生产构建开启**）。

## 链层启用（WSL kurtosis-cdk，Polygon CDK）

合约仅开发不本地编译部署（`contracts-ext/`：ShieldedRegistry 与 StateAnchor，
ABI 已被 `vg-infra-chain` 的 selector 锁定测试引用）。真实链联调在 WSL 内用
kurtosis-cdk 拉起本地 Polygon CDK 栈后进行：

```text
# 1) WSL 内启动 kurtosis-cdk（得到 L2 RPC 等端点后部署合约，
#    记录 ShieldedRegistry / StateAnchor 地址与 chain id）

# 2) 以链层 feature 编译并配置 env
cargo build -p vg-api --features chain-alloy

export CHAIN_RPC_URL=http://<kurtosis-l2-rpc>
export OPERATOR_KEY=0x<私钥>
export SHIELDED_REGISTRY_ADDR=0x<合约地址>
export STATE_ANCHOR_ADDR=0x<合约地址>
export CHAIN_ID=<链 id>

cargo run -p vg-api --features chain-alloy
# CHAIN_RPC_URL 非空时自动装配 AlloyLedger；为空回落 InProcessLedger（本地账本）

# 3) ignored 链上集成测试
cargo test -p vg-infra-chain --features chain-alloy -- --ignored
```

## 已知限制与 Phase2 方向

1. **MCP 鉴权桥**：标准 MCP 客户端无法注入 VG-SIG 头，生产接入需自研客户端/
   网关（见上）；`mcp-mock-auth` 仅为测试后门。
2. **悬挂锚对账**：ledger 锚定提交与业务提交跨事务，失败窗口内可能产生悬挂锚
   （已落链但业务已回滚），Phase2 需对账/补偿任务。
3. **owner 全量重算**：批量转移后合规/权属重算为全量路径，数据量大时需增量化。
4. **spend 电路**：shielded 转账当前依赖 note_opening + range 电路组合，
   独立 nullifier-friendly spend 电路留待 Phase2。
5. **会话绑定**：VG-SIG 为单请求签名，无会话/token 机制；连续操作需逐请求签名。
6. **nonce 防重放为内存级**（进程内 LRU，重启后旧 nonce 可重放；ts ±300s 窗口
   实际限制了可重放时长）。
7. **策略 jurisdiction 粗粒度**：管理端点仅校验主体类型为 Regulator，
   辖区级（jurisdiction 精确匹配）鉴权待接 IAM。
8. **VC 哈希契约不可变**：凭证 JSON 树递归键排序后 keccak256（golden vector
   已锁定），任何序列化变更都会破坏链上一致性，升级需迁移方案。
