
---

## 利用关联类型（Associated Types）解耦

为了保持 Domain 层的纯洁性，我们可以利用 Rust 的特性——**关联类型（Associated Types）**。在 Domain 层定义接口时，抽象出一个 `Context`（上下文），在 Infrastructure 层再用真实的事务类型去实现它。

### 1. Domain 层（纯业务，无技术依赖）

```rust
pub trait OrderRepository {
    // 定义一个关联类型，用来代表事务或连接上下文
    type Context;

    async fn save(&self, ctx: &mut Self::Context, order: &Order) -> Result<(), DomainError>;
}

```

### 2. Infrastructure 层（技术实现）

```rust
pub struct OrderRepositoryImpl;

impl OrderRepository for OrderRepositoryImpl {
    // 绑定具体的 sqlx 事务类型
    type Context = sqlx::Transaction<'static, sqlx::Postgres>;

    async fn save(&self, ctx: &mut Self::Context, order: &Order) -> Result<(), DomainError> {
        sqlx::query!("INSERT INTO orders ...", order.id)
            .execute(ctx) // 注入事务
            .await
            .map_err(|_| DomainError::StorageError)?;
        Ok(())
    }
}

```

### 3. Application 层（编排事务）

在 Application 层，通过泛型或者直接组合，利用具体的实现来管理事务：

```rust
impl OrderApplicationService {
    pub async fn create_order(&self, cmd: CreateOrderCommand) -> Result<(), AppError> {
        let mut tx = self.pool.begin().await?; // 获取具体事务
        
        let order = Order::new(cmd.id, cmd.customer_id);
        // 这里的 tx 完美契合 RepositoryImpl 的 Context 类型
        self.order_repo.save(&mut tx, &order).await?; 
        
        tx.commit().await?;
        Ok(())
    }
}

```

---