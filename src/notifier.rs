use chrono::{DateTime, Utc};
use log::{error, info};
use serde_json::json;

#[derive(Clone, Debug)]
pub struct SlackNotifier {
    enabled: bool,
    webhook_url: String,
    channel: String,
    client: reqwest::blocking::Client,
}

impl SlackNotifier {
    pub fn new(enabled: bool, webhook_url: String, channel: String) -> Self {
        Self {
            enabled,
            webhook_url,
            channel,
            client: reqwest::blocking::Client::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn notify(
        &self,
        title: &str,
        condition: &str,
        timestamp: DateTime<Utc>,
        current_rate: f64,
        baseline: f64,
        duration: Option<&str>,
        ip_address: Option<&str>,
        strike_count: Option<usize>,
    ) {
        let is_unban = current_rate == 0.0;
        let is_global = ip_address.is_none();

        let (header_text, emoji) = if is_unban {
            ("Detrudr Notice: IP Unbanned", "✅")
        } else if is_global {
            ("Detrudr Alert: Global Traffic Anomaly", "⚠️")
        } else {
            ("Detrudr Alert: IP Banned", "🚨")
        };

        let mut blocks = vec![
            json!({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": format!("{} {}", emoji, header_text),
                    "emoji": true
                }
            }),
            json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": title
                }
            }),
        ];

        let mut fields = Vec::new();

        if let Some(ip) = ip_address {
            fields.push(json!({
                "type": "mrkdwn",
                "text": format!("*IP Address:*\n<https://www.abuseipdb.com/check/{0}|{0}>", ip)
            }));
        } else {
            fields.push(json!({
                "type": "mrkdwn",
                "text": "*Trigger:*\n`global_rate`"
            }));
        }

        if !is_global {
            let mut cond_text = format!("`{}`", condition);
            if let Some(strike) = strike_count {
                cond_text.push_str(&format!(" (Strike: {})", strike));
            }
            fields.push(json!({
                "type": "mrkdwn",
                "text": format!("*Condition:*\n{}", cond_text)
            }));
        }

        if let Some(dur) = duration {
            fields.push(json!({
                "type": "mrkdwn",
                "text": format!("*Ban Duration:*\n{}", dur)
            }));
        }

        blocks.push(json!({
            "type": "section",
            "fields": fields
        }));

        if !is_unban {
            let mut baseline_ext = format!("{:.1} req/s", baseline);
            if baseline > 0.0 {
                let multiplier = current_rate / baseline;
                baseline_ext.push_str(&format!(" _({:.1}x higher)_", multiplier));
            }

            blocks.push(json!({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!("*Traffic Stats:*\n• *Current Rate:* {:.1} req/s\n• *Baseline:* {}", current_rate, baseline_ext)
                }
            }));
        }

        blocks.push(json!({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": format!("🛡️ *Detrudr* | {}", timestamp.format("%Y-%m-%d %H:%M UTC"))
                }
            ]
        }));

        let payload = json!({
            "channel": &self.channel,
            "text": title,
            "blocks": blocks,
        });

        if !self.enabled {
            info!("Slack disabled. Skipping notification: {title}");
            return;
        }
        if self.webhook_url.trim().is_empty() {
            error!("Slack enabled but webhook URL is empty");
            return;
        }

        if let Err(error) = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .and_then(|response| response.error_for_status())
        {
            error!("Slack notification failed: {error}");
        }
    }
}
