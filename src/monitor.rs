use chrono::{DateTime, Utc};
use log::error;
use serde::Deserialize;
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Seek, SeekFrom},
    path::Path,
    thread,
    time::Duration,
};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub source_ip: String,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub response_size: u64,
}

#[derive(Debug, Deserialize)]
struct RawLogEntry {
    source_ip: Option<String>,
    timestamp: Option<String>,
    method: Option<String>,
    path: Option<String>,
    status: Option<serde_json::Value>,
    response_size: Option<serde_json::Value>,
}

pub fn parse_timestamp(raw_timestamp: &str) -> DateTime<Utc> {
    if raw_timestamp.trim().is_empty() {
        return Utc::now();
    }
    DateTime::parse_from_rfc3339(&raw_timestamp.replace('Z', "+00:00"))
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

pub fn parse_log_line(line: &str) -> Option<LogEntry> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let raw: RawLogEntry = serde_json::from_str(line).ok()?;
    Some(LogEntry {
        source_ip: raw.source_ip.unwrap_or_else(|| "unknown".to_owned()),
        timestamp: raw
            .timestamp
            .as_deref()
            .map(parse_timestamp)
            .unwrap_or_else(Utc::now),
        method: raw.method.unwrap_or_else(|| "GET".to_owned()),
        path: raw.path.unwrap_or_else(|| "/".to_owned()),
        status: value_to_u64(raw.status).unwrap_or_default() as u16,
        response_size: value_to_u64(raw.response_size).unwrap_or_default(),
    })
}

pub fn follow_log_file<F>(path: &Path, sleep: Duration, mut on_entry: F) -> !
where
    F: FnMut(LogEntry),
{
    loop {
        if !path.exists() {
            thread::sleep(sleep);
            continue;
        }
        if path.is_dir() {
            error!(
                "Configured log path is a directory, not a file: {}",
                path.display()
            );
            thread::sleep(sleep);
            continue;
        }

        let Ok(file) = File::open(path) else {
            thread::sleep(sleep);
            continue;
        };
        let mut reader = BufReader::new(file);
        let _ = reader.seek(SeekFrom::End(0));

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    if fs::metadata(path).is_err() {
                        break;
                    }
                    thread::sleep(sleep);
                }
                Ok(_) => {
                    if let Some(entry) = parse_log_line(&line) {
                        on_entry(entry);
                    }
                }
                Err(_) => break,
            }
        }
    }
}

fn value_to_u64(value: Option<serde_json::Value>) -> Option<u64> {
    match value? {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_access_log() {
        let entry = parse_log_line(
            r#"{"source_ip":"1.2.3.4","timestamp":"2026-05-02T10:00:00Z","method":"POST","path":"/x","status":404,"response_size":12}"#,
        )
        .unwrap();
        assert_eq!(entry.source_ip, "1.2.3.4");
        assert_eq!(entry.status, 404);
        assert_eq!(entry.response_size, 12);
    }
}
