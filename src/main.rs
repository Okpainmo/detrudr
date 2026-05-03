mod baseline;
mod blocker;
mod config;
#[path = "dashboard/dashboard.rs"]
mod dashboard;
mod engine;
mod monitor;
mod notifier;

use crate::{
    config::{load_config, load_dashboard_auth, load_dotenv},
    dashboard::start_dashboard,
    engine::DetectionEngine,
    monitor::follow_log_file,
};
use anyhow::Result;
use log::info;
use parking_lot::Mutex;
use std::{
    env,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::Duration,
};

fn main() -> Result<()> {
    let config_path = parse_config_path();
    let env_path = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".env");
    load_dotenv(&env_path)?;
    let config = load_config(&config_path)?;
    let dashboard_auth = load_dashboard_auth()?;
    configure_logging(&config.app.log_level);

    let engine = Arc::new(Mutex::new(DetectionEngine::new(config.clone())?));
    start_dashboard(
        &config.dashboard.host,
        config.dashboard.port,
        Arc::clone(&engine),
        dashboard_auth,
    )?;
    start_tick_loop(Arc::clone(&engine));

    info!("Detector started. Watching {}", config.log.path);
    let log_path = PathBuf::from(config.log.path);
    follow_log_file(&log_path, Duration::from_millis(250), move |entry| {
        engine.lock().process_entry(entry);
    });
}

fn parse_config_path() -> PathBuf {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            if let Some(path) = args.next() {
                return PathBuf::from(path);
            }
        }
    }
    PathBuf::from("config.yaml")
}

fn configure_logging(level: &str) {
    let level = match level.to_ascii_lowercase().as_str() {
        "trace" => "trace",
        "debug" => "debug",
        "warn" | "warning" => "warn",
        "error" => "error",
        _ => "info",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();
}

fn start_tick_loop(engine: Arc<Mutex<DetectionEngine>>) {
    thread::Builder::new()
        .name("tick-loop".to_owned())
        .spawn(move || loop {
            {
                let mut engine = engine.lock();
                engine.tick();
                engine.run_unban_checks();
            }
            thread::sleep(Duration::from_secs(1));
        })
        .expect("failed to start tick loop");
}
