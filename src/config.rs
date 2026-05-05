use anyhow::{Context, Result};
use serde::Deserialize;
use std::{env, fs, path::Path};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub app: AppConfig,
    pub log: LogConfig,
    pub window: WindowConfig,
    pub baseline: BaselineConfig,
    pub thresholds: ThresholdConfig,
    pub blocking: BlockingConfig,
    pub slack: SlackConfig,
    pub dashboard: DashboardConfig,
    pub audit: AuditConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AppConfig {
    pub log_level: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LogConfig {
    pub path: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WindowConfig {
    pub seconds: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BaselineConfig {
    pub history_seconds: usize,
    pub recalc_interval_seconds: i64,
    pub min_samples_per_hour: usize,
    pub floor_mean: f64,
    pub floor_stddev: f64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ThresholdConfig {
    pub zscore: f64,
    pub rate_multiplier: f64,
    pub tightening_factor: f64,
    pub error_multiplier: f64,
    pub error_floor_mean: f64,
    pub error_floor_stddev: f64,
    pub global_alert_cooldown_seconds: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BlockingConfig {
    pub dry_run: bool,
    pub iptables_chain: String,
    pub ban_minutes: Vec<i64>,
    pub ban_hours_final: i64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SlackConfig {
    pub enabled: bool,
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default)]
    pub channel: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DashboardConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuditConfig {
    pub path: String,
}

#[derive(Clone, Debug)]
pub struct DashboardAuth {
    pub email: String,
    pub password: String,
}

pub fn load_config(path: &Path) -> Result<Config> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    let mut config: Config = serde_yaml::from_str(&raw).context("failed to parse config yaml")?;
    apply_env_overrides(&mut config)?;
    Ok(config)
}

pub fn load_dotenv(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read dotenv {}", path.display()))?;
    for line in raw.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let mut parts = line.splitn(2, '=');
        let key = parts.next().unwrap_or_default().trim();
        let value = parts
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches('"')
            .trim_matches('\'');
        if env::var_os(key).is_none() {
            env::set_var(key, value);
        }
    }
    Ok(())
}

pub fn load_dashboard_auth() -> Result<DashboardAuth> {
    let email = env::var("EMAIL")
        .context("EMAIL must be set in .env or the process environment for dashboard auth")?;
    let password = env::var("PASSWORD")
        .context("PASSWORD must be set in .env or the process environment for dashboard auth")?;

    let email = email.trim().to_owned();
    let password = password.trim().to_owned();
    if email.is_empty() {
        anyhow::bail!("EMAIL must not be empty");
    }
    if password.is_empty() {
        anyhow::bail!("PASSWORD must not be empty");
    }

    Ok(DashboardAuth { email, password })
}

fn apply_env_overrides(config: &mut Config) -> Result<()> {
    if let Ok(path) = env::var("LOG_PATH") {
        if !path.trim().is_empty() {
            config.log.path = path.trim().to_owned();
        }
    }
    if let Ok(path) = env::var("AUDIT_LOG_PATH") {
        if !path.trim().is_empty() {
            config.audit.path = path.trim().to_owned();
        }
    }
    if let Ok(webhook) = env::var("WEB_HOOK_URL") {
        if !webhook.trim().is_empty() {
            config.slack.webhook_url = webhook.trim().to_owned();
        }
    }
    if let Ok(channel) = env::var("CHANNEL") {
        if !channel.trim().is_empty() {
            config.slack.channel = channel.trim().to_owned();
        }
    }
    if let Ok(enabled) = env::var("ENABLE_SLACK_NOTIFICATION") {
        if !enabled.trim().is_empty() {
            config.slack.enabled = parse_bool_env("ENABLE_SLACK_NOTIFICATION", &enabled)?;
        }
    }
    if let Ok(dry_run) = env::var("DRY_RUN") {
        if !dry_run.trim().is_empty() {
            config.blocking.dry_run = parse_bool_env("DRY_RUN", &dry_run)?;
        }
    }
    Ok(())
}

fn parse_bool_env(name: &str, value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "y" | "on" => Ok(true),
        "false" | "0" | "no" | "n" | "off" => Ok(false),
        _ => anyhow::bail!("{name} must be a boolean value such as true or false"),
    }
}
