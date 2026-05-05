use chrono::{DateTime, Utc};
use log::error;
use serde::Deserialize;
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileMarker {
    dev: u64,
    ino: u64,
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
        status: value_to_u64(raw.status)
            .and_then(|status| u16::try_from(status).ok())
            .unwrap_or_default(),
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
        let Ok(metadata) = file.metadata() else {
            thread::sleep(sleep);
            continue;
        };
        let mut marker = file_marker(&metadata);
        let mut reader = BufReader::new(file);
        let _ = reader.seek(SeekFrom::End(0));

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    let position = reader.stream_position().unwrap_or(metadata.len());
                    match fs::metadata(path) {
                        Ok(current_metadata)
                            if should_reopen(marker, position, &current_metadata) =>
                        {
                            let Ok(file) = File::open(path) else {
                                break;
                            };
                            let Ok(current_metadata) = file.metadata() else {
                                break;
                            };
                            marker = file_marker(&current_metadata);
                            reader = BufReader::new(file);
                            let _ = reader.seek(SeekFrom::Start(0));
                        }
                        Ok(_) => {
                            thread::sleep(sleep);
                        }
                        Err(_) => {
                            break;
                        }
                    }
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

fn file_marker(metadata: &fs::Metadata) -> FileMarker {
    FileMarker {
        dev: metadata.dev(),
        ino: metadata.ino(),
    }
}

fn should_reopen(marker: FileMarker, position: u64, metadata: &fs::Metadata) -> bool {
    file_marker(metadata) != marker || metadata.len() < position
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

    #[test]
    fn oversized_status_defaults_instead_of_wrapping() {
        let entry = parse_log_line(
            r#"{"source_ip":"1.2.3.4","timestamp":"2026-05-02T10:00:00Z","method":"GET","path":"/x","status":70000,"response_size":12}"#,
        )
        .unwrap();

        assert_eq!(entry.status, 0);
    }

    #[test]
    fn detects_log_replacement_by_file_marker_change() {
        let marker = FileMarker { dev: 1, ino: 10 };
        let temp = tempfile::NamedTempFile::new().unwrap();
        let metadata = temp.as_file().metadata().unwrap();

        assert!(should_reopen(marker, 0, &metadata));
    }

    #[test]
    fn detects_log_truncation_by_size_decrease() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let metadata = temp.as_file().metadata().unwrap();
        let marker = file_marker(&metadata);

        assert!(should_reopen(marker, 100, &metadata));
    }
}
