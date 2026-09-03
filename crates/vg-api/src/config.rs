//! 环境变量配置。
//!
//! 读取前先执行 `dotenvy::dotenv()`（.env 存在则加载，缺失不报错），
//! 使 `cargo run` / 测试环境无需手工导出变量。

/// ZK 证明器模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProverKind {
    /// 真实 Plonky3 证明（默认，`ProverDispatcher`）。
    Plonky,
    /// 透明回执模式（`TransparentProver`，需 `transparent` feature）。
    Transparent,
}

/// 服务配置（bootstrap 一次性读取）。
#[derive(Debug, Clone)]
pub struct Config {
    /// PostgreSQL 连接串（`DATABASE_URL`，必填）。
    pub database_url: String,
    /// 监听地址（`BIND_ADDR`，默认 `0.0.0.0:8080`）。
    pub bind_addr: String,
    /// 证明器模式（`VG_PROVER`，默认 `plonky`）。
    pub prover: ProverKind,
}

/// 配置缺失错误（bootstrap 直接 panic 前的可展示消息）。
#[derive(Debug, thiserror::Error)]
#[error("配置错误：{0}")]
pub struct ConfigError(String);

impl Config {
    /// 从环境变量构造（含 dotenvy 加载）。
    pub fn from_env() -> Result<Self, ConfigError> {
        // .env 缺失时 dotenv() 返回 Err，属正常情况，忽略
        let _ = dotenvy::dotenv();

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| ConfigError("缺少必填环境变量 DATABASE_URL（可写入 .env）".into()))?;
        let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
        let prover = match std::env::var("VG_PROVER").unwrap_or_else(|_| "plonky".into()) {
            v if v.eq_ignore_ascii_case("plonky") => ProverKind::Plonky,
            v if v.eq_ignore_ascii_case("transparent") => ProverKind::Transparent,
            v => {
                return Err(ConfigError(format!(
                    "VG_PROVER 取值非法：`{v}`（可选 plonky / transparent）"
                )))
            }
        };
        Ok(Self {
            database_url,
            bind_addr,
            prover,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// from_env 在 DATABASE_URL 缺失时报错。
    ///
    /// 隔离措施：切换到系统临时目录（避免 dotenvy 读到工作区的 .env）
    /// 并临时清除进程内变量后恢复。环境变量全局可变，本测试不与
    /// 其他 from_env 测试并行执行依赖（无其他同类测试）。
    #[test]
    fn missing_database_url_is_error() {
        let saved = std::env::var("DATABASE_URL").ok();
        let saved_cwd = std::env::current_dir().unwrap();
        let tmp = std::env::temp_dir();
        std::env::set_current_dir(&tmp).expect("切换临时目录应成功");
        std::env::remove_var("DATABASE_URL");
        let result = Config::from_env();
        let err = result.expect_err("无 .env 且变量被清除时应报错");
        assert!(
            err.to_string().contains("DATABASE_URL"),
            "错误消息应点名 DATABASE_URL：{err}"
        );
        std::env::set_current_dir(saved_cwd).expect("切回原目录应成功");
        if let Some(v) = saved {
            std::env::set_var("DATABASE_URL", v);
        }
    }
}
