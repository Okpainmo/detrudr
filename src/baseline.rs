use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};

#[derive(Clone, Debug, Serialize)]
pub struct BaselineStats {
    pub mean: f64,
    pub stddev: f64,
    pub sample_size: usize,
    pub hour_slot: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BaselineHistoryEntry {
    pub timestamp: String,
    pub effective_mean: f64,
    pub effective_stddev: f64,
    pub sample_size: usize,
    pub hour_slot: String,
}

#[derive(Clone, Debug)]
pub struct RollingBaseline {
    history_seconds: usize,
    recalc_interval_seconds: i64,
    min_samples_per_hour: usize,
    floor_mean: f64,
    floor_stddev: f64,
    hourly_samples: HashMap<String, VecDeque<f64>>,
    pub current: BaselineStats,
    last_recalculated_at: Option<DateTime<Utc>>,
    history: Vec<BaselineHistoryEntry>,
}

impl RollingBaseline {
    pub fn new(
        history_seconds: usize,
        recalc_interval_seconds: i64,
        min_samples_per_hour: usize,
        floor_mean: f64,
        floor_stddev: f64,
    ) -> Self {
        Self {
            history_seconds,
            recalc_interval_seconds,
            min_samples_per_hour,
            floor_mean,
            floor_stddev,
            hourly_samples: HashMap::new(),
            current: BaselineStats {
                mean: floor_mean,
                stddev: floor_stddev,
                sample_size: 0,
                hour_slot: "bootstrap".to_owned(),
            },
            last_recalculated_at: None,
            history: Vec::new(),
        }
    }

    pub fn add_sample(&mut self, sample_time: DateTime<Utc>, value: f64) {
        self.prune_stale_buckets(sample_time);

        let hour_slot = sample_time.format("%Y-%m-%dT%H").to_string();
        let bucket = self.hourly_samples.entry(hour_slot).or_default();
        bucket.push_back(value);
        while bucket.len() > self.history_seconds {
            bucket.pop_front();
        }
        self.hourly_samples.retain(|_, samples| !samples.is_empty());
    }

    pub fn recalculate(&mut self, now: DateTime<Utc>) -> BaselineStats {
        let current_hour = now.format("%Y-%m-%dT%H").to_string();
        let preferred: Vec<f64> = self
            .hourly_samples
            .get(&current_hour)
            .map(|samples| samples.iter().copied().collect())
            .unwrap_or_default();

        let (selected, slot_used) = if preferred.len() >= self.min_samples_per_hour {
            (
                preferred
                    .iter()
                    .rev()
                    .take(self.history_seconds)
                    .copied()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>(),
                current_hour.clone(),
            )
        } else {
            (self.merge_recent_samples(), "rolling".to_owned())
        };

        let computed_mean = mean(&selected).unwrap_or(self.floor_mean);
        let variance = variance(&selected, computed_mean).unwrap_or(0.0);
        let stats = BaselineStats {
            mean: computed_mean.max(self.floor_mean),
            stddev: variance.sqrt().max(self.floor_stddev),
            sample_size: selected.len(),
            hour_slot: slot_used,
        };
        self.current = stats.clone();
        self.last_recalculated_at = Some(now);
        self.history.push(BaselineHistoryEntry {
            timestamp: now.to_rfc3339(),
            effective_mean: round4(stats.mean),
            effective_stddev: round4(stats.stddev),
            sample_size: stats.sample_size,
            hour_slot: stats.hour_slot.clone(),
        });
        if self.history.len() > 180 {
            let keep_from = self.history.len() - 180;
            self.history.drain(0..keep_from);
        }
        stats
    }

    pub fn should_recalculate(&self, now: DateTime<Utc>) -> bool {
        match self.last_recalculated_at {
            None => true,
            Some(previous) => (now - previous).num_seconds() >= self.recalc_interval_seconds,
        }
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let start = self.history.len().saturating_sub(60);
        serde_json::json!({
            "mean": round4(self.current.mean),
            "stddev": round4(self.current.stddev),
            "sample_size": self.current.sample_size,
            "hour_slot": self.current.hour_slot,
            "history": self.history[start..],
        })
    }

    fn merge_recent_samples(&self) -> Vec<f64> {
        let mut slots: Vec<_> = self.hourly_samples.keys().cloned().collect();
        slots.sort_by(|a, b| b.cmp(a));
        let mut merged = Vec::new();
        for slot in slots {
            let Some(samples) = self.hourly_samples.get(&slot) else {
                continue;
            };
            let needed = self.history_seconds.saturating_sub(merged.len());
            if needed == 0 {
                break;
            }
            let mut chunk: Vec<f64> = samples.iter().rev().take(needed).copied().collect();
            chunk.reverse();
            chunk.extend(merged);
            merged = chunk;
        }
        let start = merged.len().saturating_sub(self.history_seconds);
        merged[start..].to_vec()
    }

    fn prune_stale_buckets(&mut self, sample_time: DateTime<Utc>) {
        let cutoff = sample_time - Duration::seconds(self.history_seconds as i64);
        self.hourly_samples.retain(|slot, samples| {
            !samples.is_empty()
                && parse_hour_slot(slot)
                    .map(|hour_start| hour_start + Duration::hours(1) > cutoff)
                    .unwrap_or(false)
        });
    }
}

fn parse_hour_slot(slot: &str) -> Option<DateTime<Utc>> {
    let raw = format!("{slot}:00:00");
    NaiveDateTime::parse_from_str(&raw, "%Y-%m-%dT%H:%M:%S")
        .ok()
        .map(|time| DateTime::from_naive_utc_and_offset(time, Utc))
}

fn mean(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<f64>() / values.len() as f64)
    }
}

fn variance(values: &[f64], avg: f64) -> Option<f64> {
    if values.len() < 2 {
        return Some(0.0);
    }
    Some(
        values
            .iter()
            .map(|value| (value - avg).powi(2))
            .sum::<f64>()
            / values.len() as f64,
    )
}

pub fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

pub fn round4(value: f64) -> f64 {
    (value * 10000.0).round() / 10000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn baseline_uses_floor_values_when_empty() {
        let mut baseline = RollingBaseline::new(1800, 60, 300, 1.0, 0.5);
        let stats = baseline.recalculate(Utc.with_ymd_and_hms(2026, 5, 2, 12, 0, 0).unwrap());
        assert_eq!(stats.mean, 1.0);
        assert_eq!(stats.stddev, 0.5);
    }

    #[test]
    fn add_sample_prunes_hour_buckets_outside_history_window() {
        let mut baseline = RollingBaseline::new(1800, 60, 300, 1.0, 0.5);

        baseline.add_sample(Utc.with_ymd_and_hms(2026, 5, 2, 10, 0, 0).unwrap(), 100.0);
        baseline.add_sample(Utc.with_ymd_and_hms(2026, 5, 2, 12, 45, 0).unwrap(), 2.0);

        assert!(!baseline.hourly_samples.contains_key("2026-05-02T10"));
        let stats = baseline.recalculate(Utc.with_ymd_and_hms(2026, 5, 2, 12, 45, 0).unwrap());
        assert_eq!(stats.sample_size, 1);
        assert_eq!(stats.mean, 2.0);
    }

    #[test]
    fn add_sample_keeps_bucket_that_overlaps_history_window() {
        let mut baseline = RollingBaseline::new(1800, 60, 300, 1.0, 0.5);

        baseline.add_sample(Utc.with_ymd_and_hms(2026, 5, 2, 12, 0, 0).unwrap(), 3.0);
        baseline.add_sample(Utc.with_ymd_and_hms(2026, 5, 2, 12, 45, 0).unwrap(), 5.0);

        assert!(baseline.hourly_samples.contains_key("2026-05-02T12"));
    }

    #[test]
    fn recalculate_labels_merged_samples_as_rolling() {
        let mut baseline = RollingBaseline::new(1800, 60, 300, 1.0, 0.5);

        baseline.add_sample(Utc.with_ymd_and_hms(2026, 5, 2, 11, 59, 0).unwrap(), 4.0);
        baseline.add_sample(Utc.with_ymd_and_hms(2026, 5, 2, 12, 0, 0).unwrap(), 6.0);

        let stats = baseline.recalculate(Utc.with_ymd_and_hms(2026, 5, 2, 12, 0, 0).unwrap());

        assert_eq!(stats.hour_slot, "rolling");
        assert_eq!(stats.sample_size, 2);
    }
}
