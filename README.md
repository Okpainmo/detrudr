# Detrudr

`detrudr` is a Rust HTTP traffic-anomaly and DDoS counter engine. It tails nginx JSON access logs in
real time, learns rolling request baselines, detects suspicious spikes, blocks abusive source IPs
with `iptables`, sends Slack alerts, writes an audit trail, and serves a live dashboard.

This is a Rust rewrite of the original Python daemon. The runtime behavior is intentionally kept
close to the Python implementation: 60-second sliding windows, 30-minute per-second baselines,
z-score and multiplier detection, per-IP error-ratio threshold tightening, escalating ban durations,
Slack notification payloads, and the same `/metrics` dashboard contract.

## What The Daemon Does

- Tails `/var/log/nginx/hng-access.log` or `LOG_PATH`.
- Parses JSON fields: `source_ip`, `timestamp`, `method`, `path`, `status`, and `response_size`.
- Maintains global and per-IP 60-second sliding windows with `VecDeque`.
- Recomputes rolling baselines every 60 seconds from the last 30 minutes of per-second samples.
- Detects anomalies with z-score `> 3.0` or request rate `> 5x` baseline mean.
- Tightens per-IP thresholds when an IP's 4xx/5xx ratio is above `3x` the learned error baseline.
- Blocks anomalous IPs using `iptables`.
- Unbans on a backoff schedule: `10 minutes`, `30 minutes`, `2 hours`, then permanent.
- Sends Slack alerts for bans, unbans, and global anomaly events.
- Serves a dashboard on `0.0.0.0:8080` by default.
- Writes audit records as `[timestamp] ACTION ip | condition | rate | baseline | duration`.

## Repository Structure

```text
src/
  main.rs
  config.rs
  monitor.rs
  baseline.rs
  engine.rs
  blocker.rs
  notifier.rs
  dashboard.rs
  dashboard/pages/
nginx/
  nginx.conf
traffic-simulation/
config.yaml
.env.sample
Dockerfile
docker-compose.yaml
```

## Configuration

Static settings live in `config.yaml`. Runtime values can be provided in `.env`:

```env
####################################################################
# Slack
####################################################################
WEB_HOOK_URL='https://hooks.slack.com/services/...'
CHANNEL='#channel-name'
ENABLE_SLACK_NOTIFICATION=false
LOG_PATH='/var/log/nginx/detrudr-stream.log'
AUDIT_LOG_PATH='/var/log/detrudr/audit.log'

####################################################################
# Auth
####################################################################
EMAIL='hello@email.com'
PASSWORD='supersecret'

####################################################################
# IP Blocking(For Prod, Set To `false` Else IP Blocking will fail)
####################################################################
DRY_RUN=true
```

Environment overrides match the Python version:

- `LOG_PATH` overrides `log.path`.
- `AUDIT_LOG_PATH` overrides `audit.path`.
- `WEB_HOOK_URL` overrides `slack.webhook_url`.
- `CHANNEL` overrides `slack.channel`.
- `ENABLE_SLACK_NOTIFICATION` overrides `slack.enabled`.
- `DRY_RUN` overrides `blocking.dry_run`.
- `EMAIL` and `PASSWORD` are required for dashboard login.

For systemd deployments, prefer a persistent audit path such as `/var/log/detrudr/audit.log`. The
service can let systemd create the directory with the right ownership:

```ini
[Service]
User=your-user-name
Group=your-group-name
LogsDirectory=detrudr
```

## Run Locally

```bash
cargo run -- --config config.yaml
```

The dashboard is available at `http://localhost:8080`, and machine-readable metrics are available at
`http://localhost:8080/metrics`.

## Docker

```bash
cp .env.sample .env
docker compose up -d --build
```

The detector container uses host networking and `NET_ADMIN` so it can see host nginx logs and manage
`iptables` rules.

## Expected nginx JSON Log Format

```nginx
log_format json_combined escape=json
'{'
  '"source_ip":"$remote_addr",'
  '"timestamp":"$time_iso8601",'
  '"method":"$request_method",'
  '"path":"$request_uri",'
  '"status":$status,'
  '"response_size":$body_bytes_sent'
'}';

access_log /var/log/nginx/hng-access.log json_combined;
```
