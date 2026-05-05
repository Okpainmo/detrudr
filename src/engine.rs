use crate::{
    baseline::{round2, RollingBaseline},
    blocker::IptablesBlocker,
    config::{BaselineConfig, Config},
    monitor::LogEntry,
    notifier::SlackNotifier,
};
use chrono::{DateTime, Duration, Timelike, Utc};
use log::info;
use serde::Serialize;
use serde_json::json;
use std::{
    collections::{HashMap, VecDeque},
    fs,
    io::Write,
    path::PathBuf,
};

#[derive(Clone, Debug)]
struct BanRecord {
    ip: String,
    strike_count: usize,
    condition: String,
    expires_at: Option<DateTime<Utc>>,
    duration_label: String,
}

#[derive(Clone, Debug)]
struct StrikeRecord {
    count: usize,
    last_seen: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct BannedIpSnapshot {
    ip: String,
    until: String,
    strikes: usize,
}

#[derive(Debug, Serialize)]
struct TopIpSnapshot {
    ip: String,
    requests: usize,
}

pub struct DetectionEngine {
    config: Config,
    started_at: DateTime<Utc>,
    window_seconds: i64,
    zscore_threshold: f64,
    multiplier_threshold: f64,
    tightening_factor: f64,
    error_multiplier: f64,
    audit_path: PathBuf,
    global_baseline: RollingBaseline,
    ip_baselines: HashMap<String, RollingBaseline>,
    error_baseline: RollingBaseline,
    global_requests: VecDeque<DateTime<Utc>>,
    global_errors: VecDeque<DateTime<Utc>>,
    ip_requests: HashMap<String, VecDeque<DateTime<Utc>>>,
    ip_errors: HashMap<String, VecDeque<DateTime<Utc>>>,
    top_ip_counter: HashMap<String, usize>,
    current_second_requests: usize,
    current_second_errors: usize,
    last_flushed_second: Option<DateTime<Utc>>,
    blocker: IptablesBlocker,
    notifier: SlackNotifier,
    ban_durations: Vec<Duration>,
    banned_ips: HashMap<String, BanRecord>,
    strike_counts: HashMap<String, StrikeRecord>,
    last_global_alert_at: Option<DateTime<Utc>>,
    global_alert_cooldown_seconds: i64,
    last_cpu_sample: Option<CpuSample>,
}

impl DetectionEngine {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let audit_path = PathBuf::from(&config.audit.path);
        if let Some(parent) = audit_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let baseline_cfg = &config.baseline;
        let global_baseline = Self::baseline_from_config(
            baseline_cfg,
            baseline_cfg.floor_mean,
            baseline_cfg.floor_stddev,
        );
        let error_baseline = Self::baseline_from_config(
            baseline_cfg,
            config.thresholds.error_floor_mean,
            config.thresholds.error_floor_stddev,
        );
        let blocker = IptablesBlocker::new(
            config.blocking.iptables_chain.clone(),
            config.blocking.dry_run,
        );
        let notifier = SlackNotifier::new(
            config.slack.enabled,
            config.slack.webhook_url.clone(),
            config.slack.channel.clone(),
        );

        let mut ban_durations = Vec::new();
        for minutes in &config.blocking.ban_minutes {
            ban_durations.push(Duration::minutes(*minutes));
        }
        ban_durations.push(Duration::hours(config.blocking.ban_hours_final));

        Ok(Self {
            started_at: Utc::now(),
            window_seconds: config.window.seconds,
            zscore_threshold: config.thresholds.zscore,
            multiplier_threshold: config.thresholds.rate_multiplier,
            tightening_factor: config.thresholds.tightening_factor,
            error_multiplier: config.thresholds.error_multiplier,
            audit_path,
            global_baseline,
            ip_baselines: HashMap::new(),
            error_baseline,
            global_requests: VecDeque::new(),
            global_errors: VecDeque::new(),
            ip_requests: HashMap::new(),
            ip_errors: HashMap::new(),
            top_ip_counter: HashMap::new(),
            current_second_requests: 0,
            current_second_errors: 0,
            last_flushed_second: None,
            blocker,
            notifier,
            ban_durations,
            banned_ips: HashMap::new(),
            strike_counts: HashMap::new(),
            last_global_alert_at: None,
            global_alert_cooldown_seconds: config.thresholds.global_alert_cooldown_seconds,
            last_cpu_sample: None,
            config,
        })
    }

    pub fn process_entry(&mut self, entry: LogEntry) {
        let event_time = entry.timestamp;
        let ip_address = entry.source_ip;
        let status = entry.status;

        self.flush_until(event_time);
        self.global_requests.push_back(event_time);
        self.ip_requests
            .entry(ip_address.clone())
            .or_default()
            .push_back(event_time);
        *self.top_ip_counter.entry(ip_address.clone()).or_default() += 1;
        self.current_second_requests += 1;

        if (400..=599).contains(&status) {
            self.global_errors.push_back(event_time);
            self.ip_errors
                .entry(ip_address.clone())
                .or_default()
                .push_back(event_time);
            self.current_second_errors += 1;
        }

        self.evict_old(event_time);
        self.detect_global(event_time);
        self.detect_ip(&ip_address, event_time);
        self.maybe_recalculate(event_time);
    }

    pub fn tick(&mut self) {
        let now = Utc::now();
        self.flush_until(now);
        self.evict_old(now);
        self.prune_expired_strikes(now);
        self.maybe_recalculate(now);
    }

    pub fn run_unban_checks(&mut self) {
        let now = Utc::now();
        let expired: Vec<_> = self
            .banned_ips
            .values()
            .filter(|record| {
                record
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= now)
            })
            .cloned()
            .collect();

        for record in expired {
            if self.blocker.unblock(&record.ip) {
                self.banned_ips.remove(&record.ip);
                self.audit(
                    "UNBAN",
                    &record.ip,
                    &record.condition,
                    0.0,
                    self.global_baseline.current.mean,
                    &record.duration_label,
                );
                self.notifier.notify(
                    &format!("IP unbanned: {}", record.ip),
                    &record.condition,
                    now,
                    0.0,
                    self.global_baseline.current.mean,
                    Some(&record.duration_label),
                    Some(&record.ip),
                    None,
                );
            }
        }
    }

    pub fn snapshot(&mut self) -> serde_json::Value {
        let now = Utc::now();
        self.evict_old(now);
        let global_rate = round2(self.global_requests.len() as f64 / self.window_seconds as f64);
        let banned_ips: Vec<_> = self
            .banned_ips
            .values()
            .map(|record| BannedIpSnapshot {
                ip: record.ip.clone(),
                until: record
                    .expires_at
                    .map(|timestamp| timestamp.to_rfc3339())
                    .unwrap_or_else(|| "permanent".to_owned()),
                strikes: record.strike_count,
            })
            .collect();

        let mut top_pairs: Vec<_> = self.top_ip_counter.iter().collect();
        top_pairs.sort_by(|left, right| right.1.cmp(left.1).then_with(|| left.0.cmp(right.0)));
        let top_ips: Vec<_> = top_pairs
            .into_iter()
            .filter_map(|(ip, _)| {
                self.ip_requests.get(ip).map(|requests| TopIpSnapshot {
                    ip: ip.clone(),
                    requests: requests.len(),
                })
            })
            .take(10)
            .collect();

        let cpu_percent = self.cpu_percent();

        json!({
            "uptime": format_duration(now - self.started_at),
            "global_requests_last_60s": self.global_requests.len(),
            "global_req_per_sec": global_rate,
            "current_second_requests": self.current_second_requests,
            "global_baseline": self.global_baseline.snapshot(),
            "error_baseline": self.error_baseline.snapshot(),
            "top_ips": top_ips,
            "banned_ips": banned_ips,
            "cpu_percent": cpu_percent,
            "memory_mb": process_memory_mb(),
            "audit_tail": self.tail_audit(),
        })
    }

    fn detect_global(&mut self, now: DateTime<Utc>) {
        let current_rate = self.global_requests.len() as f64 / self.window_seconds as f64;
        let baseline = self.global_baseline.current.clone();
        if self.is_anomalous(current_rate, baseline.mean, baseline.stddev)
            && self.can_emit_global_alert(now)
        {
            self.audit(
                "GLOBAL_ALERT",
                "global",
                "global_rate",
                current_rate,
                baseline.mean,
                "-",
            );
            self.notifier.notify(
                "Global traffic anomaly detected",
                "global_rate",
                now,
                current_rate,
                baseline.mean,
                None,
                None,
                None,
            );
            self.last_global_alert_at = Some(now);
        }
    }

    fn detect_ip(&mut self, ip_address: &str, now: DateTime<Utc>) {
        if self.banned_ips.contains_key(ip_address) {
            return;
        }
        if !self.ip_baselines.contains_key(ip_address) {
            self.ip_baselines
                .insert(ip_address.to_owned(), self.new_ip_baseline());
        }

        let request_count = self
            .ip_requests
            .get(ip_address)
            .map(VecDeque::len)
            .unwrap_or_default();
        let rate = request_count as f64 / self.window_seconds as f64;
        let error_count = self
            .ip_errors
            .get(ip_address)
            .map(VecDeque::len)
            .unwrap_or_default();
        let error_rate = if request_count > 0 {
            error_count as f64 / request_count as f64
        } else {
            0.0
        };
        let tightened = error_rate
            >= (self.error_baseline.current.mean * self.error_multiplier)
                .max(self.config.thresholds.error_floor_mean * self.error_multiplier);

        let ip_baseline = self
            .ip_baselines
            .get(ip_address)
            .expect("baseline inserted");
        let baseline_mean = ip_baseline.current.mean;
        let baseline_stddev = ip_baseline.current.stddev;
        let zscore = zscore(rate, baseline_mean, baseline_stddev);
        let divisor = if tightened {
            self.tightening_factor
        } else {
            1.0
        };
        let multiplier = self.multiplier_threshold / divisor;
        let z_limit = self.zscore_threshold / divisor;

        if zscore > z_limit || rate > ip_baseline.current.mean * multiplier {
            self.ban_ip(
                ip_address,
                now,
                rate,
                baseline_mean,
                if tightened {
                    "ip_rate_tight"
                } else {
                    "ip_rate"
                },
            );
        }
    }

    fn ban_ip(
        &mut self,
        ip_address: &str,
        now: DateTime<Utc>,
        rate: f64,
        baseline: f64,
        condition: &str,
    ) {
        let strike = self
            .strike_counts
            .entry(ip_address.to_owned())
            .or_insert(StrikeRecord {
                count: 0,
                last_seen: now,
            });
        strike.count += 1;
        strike.last_seen = now;
        let strike_count = strike.count;

        let (expires_at, duration_label) =
            if let Some(duration) = self.ban_durations.get(strike_count - 1) {
                (Some(now + *duration), format_ban_duration(*duration))
            } else {
                (None, "permanent".to_owned())
            };

        if !self.blocker.block(ip_address) {
            return;
        }

        let record = BanRecord {
            ip: ip_address.to_owned(),
            strike_count,
            condition: condition.to_owned(),
            expires_at,
            duration_label: duration_label.clone(),
        };
        self.banned_ips.insert(ip_address.to_owned(), record);
        self.audit(
            "BAN",
            ip_address,
            condition,
            rate,
            baseline,
            &duration_label,
        );
        self.notifier.notify(
            &format!("IP banned: {ip_address}"),
            condition,
            now,
            rate,
            baseline,
            Some(&duration_label),
            Some(ip_address),
            Some(strike_count),
        );
    }

    fn maybe_recalculate(&mut self, now: DateTime<Utc>) {
        if self.global_baseline.should_recalculate(now) {
            let stats = self.global_baseline.recalculate(now);
            self.error_baseline.recalculate(now);
            let stale: Vec<_> = self
                .ip_baselines
                .iter_mut()
                .filter_map(|(ip, baseline)| {
                    baseline.recalculate(now);
                    if self
                        .ip_requests
                        .get(ip)
                        .map(VecDeque::is_empty)
                        .unwrap_or(true)
                    {
                        Some(ip.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for ip in stale {
                self.ip_baselines.remove(&ip);
            }
            self.audit(
                "BASELINE",
                "global",
                "recalculated",
                stats.mean,
                stats.mean,
                &stats.hour_slot,
            );
        }
    }

    fn flush_until(&mut self, now: DateTime<Utc>) {
        let current_second = now.with_nanosecond(0).unwrap_or(now);
        let Some(mut last) = self.last_flushed_second else {
            self.last_flushed_second = Some(current_second);
            return;
        };

        while last < current_second {
            let sample_time = last;
            self.global_baseline
                .add_sample(sample_time, self.current_second_requests as f64);
            let total = self.current_second_requests.max(1);
            let error_ratio = if self.current_second_requests > 0 {
                self.current_second_errors as f64 / total as f64
            } else {
                0.0
            };
            self.error_baseline.add_sample(sample_time, error_ratio);
            let ip_counts: Vec<_> = self
                .ip_requests
                .iter()
                .map(|(ip, requests)| (ip.clone(), count_second(requests, sample_time)))
                .collect();
            for (ip, count) in ip_counts {
                if !self.ip_baselines.contains_key(&ip) {
                    self.ip_baselines.insert(ip.clone(), self.new_ip_baseline());
                }
                if let Some(baseline) = self.ip_baselines.get_mut(&ip) {
                    baseline.add_sample(sample_time, count as f64);
                }
            }
            self.current_second_requests = 0;
            self.current_second_errors = 0;
            last += Duration::seconds(1);
            self.last_flushed_second = Some(last);
        }
    }

    fn evict_old(&mut self, now: DateTime<Utc>) {
        let cutoff = now - Duration::seconds(self.window_seconds);
        pop_older_than(&mut self.global_requests, cutoff);
        pop_older_than(&mut self.global_errors, cutoff);

        let mut stale_ips = Vec::new();
        for (ip, requests) in self.ip_requests.iter_mut() {
            pop_older_than(requests, cutoff);
            if let Some(errors) = self.ip_errors.get_mut(ip) {
                pop_older_than(errors, cutoff);
            }
            if requests.is_empty() && !self.banned_ips.contains_key(ip) {
                stale_ips.push(ip.clone());
            }
        }
        for ip in stale_ips {
            self.ip_requests.remove(&ip);
            self.ip_errors.remove(&ip);
            self.top_ip_counter.remove(&ip);
        }
    }

    fn prune_expired_strikes(&mut self, now: DateTime<Utc>) {
        let decay_hours = self.config.blocking.strike_decay_hours;
        if decay_hours <= 0 {
            return;
        }

        let cutoff = now - Duration::hours(decay_hours);
        self.strike_counts
            .retain(|ip, record| should_retain_strike(ip, record, &self.banned_ips, cutoff));
    }

    fn audit(
        &self,
        action: &str,
        ip_address: &str,
        condition: &str,
        rate: f64,
        baseline: f64,
        duration: &str,
    ) {
        let line = format!(
            "[{}] {action} {ip_address} | {condition} | {rate:.2} | {baseline:.2} | {duration}\n",
            Utc::now().to_rfc3339()
        );
        if let Some(parent) = self.audit_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_path)
        {
            Ok(mut file) => {
                let _ = file.write_all(line.as_bytes());
            }
            Err(error) => info!(
                "failed to write audit log {}: {error}",
                self.audit_path.display()
            ),
        }
        info!("{}", line.trim_end());
    }

    fn tail_audit(&self) -> Vec<String> {
        let Ok(raw) = fs::read_to_string(&self.audit_path) else {
            return Vec::new();
        };
        let lines: Vec<_> = raw.lines().map(str::to_owned).collect();
        let start = lines.len().saturating_sub(12);
        lines[start..].to_vec()
    }

    fn is_anomalous(&self, rate: f64, baseline_mean: f64, baseline_stddev: f64) -> bool {
        zscore(rate, baseline_mean, baseline_stddev) > self.zscore_threshold
            || rate > baseline_mean * self.multiplier_threshold
    }

    fn can_emit_global_alert(&self, now: DateTime<Utc>) -> bool {
        self.last_global_alert_at
            .map(|last| (now - last).num_seconds() >= self.global_alert_cooldown_seconds)
            .unwrap_or(true)
    }

    fn new_ip_baseline(&self) -> RollingBaseline {
        Self::baseline_from_config(
            &self.config.baseline,
            self.config.baseline.floor_mean,
            self.config.baseline.floor_stddev,
        )
    }

    fn baseline_from_config(
        config: &BaselineConfig,
        floor_mean: f64,
        floor_stddev: f64,
    ) -> RollingBaseline {
        RollingBaseline::new(
            config.history_seconds,
            config.recalc_interval_seconds,
            config.min_samples_per_hour,
            floor_mean,
            floor_stddev,
        )
    }

    fn cpu_percent(&mut self) -> f64 {
        let Some(current) = read_cpu_sample() else {
            return 0.0;
        };
        let Some(previous) = self.last_cpu_sample.replace(current) else {
            return 0.0;
        };
        let total_delta = current.total.saturating_sub(previous.total);
        let idle_delta = current.idle.saturating_sub(previous.idle);
        if total_delta == 0 {
            return 0.0;
        }
        round2((total_delta.saturating_sub(idle_delta) as f64 / total_delta as f64) * 100.0)
    }
}

#[derive(Clone, Copy)]
struct CpuSample {
    idle: u64,
    total: u64,
}

fn pop_older_than(items: &mut VecDeque<DateTime<Utc>>, cutoff: DateTime<Utc>) {
    while items.front().is_some_and(|timestamp| *timestamp < cutoff) {
        items.pop_front();
    }
}

fn count_second(requests: &VecDeque<DateTime<Utc>>, second_mark: DateTime<Utc>) -> usize {
    let next_mark = second_mark + Duration::seconds(1);
    requests
        .iter()
        .filter(|timestamp| **timestamp >= second_mark && **timestamp < next_mark)
        .count()
}

fn should_retain_strike(
    ip: &str,
    record: &StrikeRecord,
    banned_ips: &HashMap<String, BanRecord>,
    cutoff: DateTime<Utc>,
) -> bool {
    banned_ips.contains_key(ip) || record.last_seen >= cutoff
}

fn zscore(rate: f64, baseline_mean: f64, baseline_stddev: f64) -> f64 {
    if baseline_stddev <= 0.0 {
        0.0
    } else {
        (rate - baseline_mean) / baseline_stddev
    }
}

fn format_ban_duration(duration: Duration) -> String {
    let minutes = duration.num_minutes();
    if minutes < 60 {
        format!("{minutes}m")
    } else {
        format!("{}h", minutes / 60)
    }
}

fn format_duration(duration: Duration) -> String {
    let total = duration.num_seconds().max(0);
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;
    format!("{hours}:{minutes:02}:{seconds:02}")
}

fn process_memory_mb() -> f64 {
    let Ok(statm) = fs::read_to_string("/proc/self/statm") else {
        return 0.0;
    };
    let Some(pages) = statm
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<f64>().ok())
    else {
        return 0.0;
    };
    round2(pages * 4096.0 / (1024.0 * 1024.0))
}

fn read_cpu_sample() -> Option<CpuSample> {
    let raw = fs::read_to_string("/proc/stat").ok()?;
    let first = raw.lines().next()?;
    let values: Vec<u64> = first
        .split_whitespace()
        .skip(1)
        .filter_map(|value| value.parse().ok())
        .collect();
    if values.len() < 4 {
        return None;
    }
    let idle =
        values.get(3).copied().unwrap_or_default() + values.get(4).copied().unwrap_or_default();
    let total = values.iter().sum();
    Some(CpuSample { idle, total })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn strike_records_decay_after_cutoff_when_not_banned() {
        let cutoff = Utc.with_ymd_and_hms(2026, 5, 2, 12, 0, 0).unwrap();
        let record = StrikeRecord {
            count: 1,
            last_seen: cutoff - Duration::seconds(1),
        };
        let banned_ips = HashMap::new();

        assert!(!should_retain_strike(
            "198.51.100.10",
            &record,
            &banned_ips,
            cutoff
        ));
    }

    #[test]
    fn strike_records_stay_when_recent_or_banned() {
        let cutoff = Utc.with_ymd_and_hms(2026, 5, 2, 12, 0, 0).unwrap();
        let recent = StrikeRecord {
            count: 1,
            last_seen: cutoff,
        };
        let old = StrikeRecord {
            count: 1,
            last_seen: cutoff - Duration::hours(1),
        };
        let mut banned_ips = HashMap::new();
        banned_ips.insert(
            "198.51.100.20".to_owned(),
            BanRecord {
                ip: "198.51.100.20".to_owned(),
                strike_count: 1,
                condition: "ip_rate".to_owned(),
                expires_at: Some(cutoff + Duration::minutes(10)),
                duration_label: "10m".to_owned(),
            },
        );

        assert!(should_retain_strike(
            "198.51.100.10",
            &recent,
            &banned_ips,
            cutoff
        ));
        assert!(should_retain_strike(
            "198.51.100.20",
            &old,
            &banned_ips,
            cutoff
        ));
    }
}
