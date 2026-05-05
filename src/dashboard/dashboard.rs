use crate::{config::DashboardAuth, engine::DetectionEngine};
use log::{error, info};
use parking_lot::Mutex;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    net::{IpAddr, ToSocketAddrs},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const DASHBOARD_HTML: &str = include_str!("pages/index.html");
const AUTH_HTML: &str = include_str!("pages/auth.html");
const SESSION_SECONDS: u64 = 60 * 60;

// Max failed attempts before lockout, and the window + lockout durations.
const MAX_ATTEMPTS: u32 = 5;
const ATTEMPT_WINDOW: Duration = Duration::from_secs(60);
const LOCKOUT_DURATION: Duration = Duration::from_secs(30);

// --- Session store: token -> expiry instant ---
type Sessions = Arc<Mutex<HashMap<String, Instant>>>;

// --- Login rate limiter: ip -> attempt state ---
type LoginLimiter = Arc<Mutex<HashMap<String, LoginAttempt>>>;

#[derive(Clone, Debug)]
struct LoginAttempt {
    failure_count: u32,
    window_start: Instant,
    lockout_until: Option<Instant>,
}

pub fn start_dashboard(
    host: &str,
    port: u16,
    trusted_proxies: Vec<String>,
    engine: Arc<Mutex<DetectionEngine>>,
    auth: DashboardAuth,
) -> anyhow::Result<()> {
    let address = format!("{host}:{port}");
    let bind = address
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid dashboard bind address {address}"))?;
    let server = Server::http(bind).map_err(|error| anyhow::anyhow!("{error}"))?;

    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let limiter: LoginLimiter = Arc::new(Mutex::new(HashMap::new()));
    let trusted_proxies = parse_trusted_proxies(trusted_proxies);

    thread::Builder::new()
        .name("dashboard".to_owned())
        .spawn(move || {
            info!("Dashboard listening on http://{bind}");
            for request in server.incoming_requests() {
                if let Err(error) = handle_request(
                    request,
                    &engine,
                    &auth,
                    &sessions,
                    &limiter,
                    &trusted_proxies,
                ) {
                    error!("dashboard request failed: {error}");
                }
            }
        })?;
    Ok(())
}

fn handle_request(
    request: Request,
    engine: &Arc<Mutex<DetectionEngine>>,
    auth: &DashboardAuth,
    sessions: &Sessions,
    limiter: &LoginLimiter,
    trusted_proxies: &HashSet<IpAddr>,
) -> anyhow::Result<()> {
    let path = request.url().to_owned();
    let method = request.method().clone();

    if method == Method::Post && path == "/auth" {
        return handle_login(request, auth, sessions, limiter, trusted_proxies);
    }

    if path == "/logout" {
        // Revoke the session token if present.
        if let Some(token) = extract_session_cookie(&request) {
            sessions.lock().remove(&token);
        }
        let response = redirect_response("/").with_header(delete_cookie_header("session"));
        request.respond(response)?;
        return Ok(());
    }

    if path == "/public/logo.png" {
        let response = Response::from_data(include_bytes!("public/logo.png").as_ref())
            .with_header(Header::from_bytes("Content-Type", "image/png").unwrap());
        request.respond(response)?;
        return Ok(());
    }

    if !is_authenticated(&request, sessions) {
        if path == "/metrics" {
            let response = unauthorized_json_response();
            request.respond(response)?;
            return Ok(());
        }
        return respond_auth(request, StatusCode(200), None);
    }

    if path == "/metrics" {
        let snapshot = engine.lock().snapshot();
        match serde_json::to_string(&snapshot) {
            Ok(body) => {
                let response = Response::from_string(body).with_header(json_header());
                request.respond(response)?;
            }
            Err(error) => {
                let response =
                    Response::from_string("serialization error").with_status_code(StatusCode(500));
                request.respond(response)?;
                error!("failed to serialize metrics: {error}");
            }
        }
        return Ok(());
    }

    let response = Response::from_string(DASHBOARD_HTML).with_header(html_header());
    request.respond(response)?;
    Ok(())
}

fn handle_login(
    mut request: Request,
    auth: &DashboardAuth,
    sessions: &Sessions,
    limiter: &LoginLimiter,
    trusted_proxies: &HashSet<IpAddr>,
) -> anyhow::Result<()> {
    let forwarded_for = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("X-Forwarded-For"))
        .map(|h| h.value.as_str());
    let remote_ip = request.remote_addr().map(|address| address.ip());
    let ip = vetted_client_ip(remote_ip, forwarded_for, trusted_proxies);

    // Check rate limit before even reading the body.
    if is_rate_limited(&ip, limiter) {
        return respond_auth(
            request,
            StatusCode(429),
            Some("Too many failed attempts. Please wait 30 seconds."),
        );
    }

    let mut body = String::new();
    request.as_reader().read_to_string(&mut body)?;
    let form = parse_form_body(&body);
    let email = form.get("email").map(String::as_str).unwrap_or_default();
    let password = form.get("password").map(String::as_str).unwrap_or_default();

    if email == auth.email && password == auth.password {
        // Reset any accumulated failures for this IP on success.
        limiter.lock().remove(&ip);

        let token = generate_token()?;
        let expiry = Instant::now() + Duration::from_secs(SESSION_SECONDS);
        sessions.lock().insert(token.clone(), expiry);

        let response = redirect_response("/").with_header(session_cookie_header(&token));
        request.respond(response)?;
        return Ok(());
    }

    // Record this failure.
    record_failure(&ip, limiter);
    respond_auth(
        request,
        StatusCode(401),
        Some("Invalid email or password. Try again."),
    )
}

fn respond_auth(
    request: Request,
    status: StatusCode,
    error_message: Option<&str>,
) -> anyhow::Result<()> {
    let (error_text, error_hidden) = match error_message {
        Some(msg) => (msg, ""),
        None => ("", "hidden"),
    };
    let html = AUTH_HTML
        .replace("{{error_hidden}}", error_hidden)
        .replace("{{error}}", error_text);
    let response = Response::from_string(html)
        .with_status_code(status)
        .with_header(html_header());
    request.respond(response)?;
    Ok(())
}

fn is_authenticated(request: &Request, sessions: &Sessions) -> bool {
    let Some(token) = extract_session_cookie(request) else {
        return false;
    };
    let mut store = sessions.lock();
    match store.get(&token) {
        Some(&expiry) if Instant::now() < expiry => true,
        _ => {
            // Token missing or expired — clean it up.
            store.remove(&token);
            false
        }
    }
}

fn extract_session_cookie(request: &Request) -> Option<String> {
    request
        .headers()
        .iter()
        .filter(|h| h.field.equiv("Cookie"))
        .flat_map(|h| parse_cookie_header(h.value.as_str()))
        .find_map(|(k, v)| if k == "session" { Some(v) } else { None })
}

fn parse_trusted_proxies(raw: Vec<String>) -> HashSet<IpAddr> {
    raw.into_iter()
        .filter_map(|proxy| proxy.trim().parse::<IpAddr>().ok())
        .collect()
}

fn vetted_client_ip(
    remote_ip: Option<IpAddr>,
    forwarded_for: Option<&str>,
    trusted_proxies: &HashSet<IpAddr>,
) -> String {
    if let Some(remote_ip) = remote_ip {
        if trusted_proxies.contains(&remote_ip) {
            if let Some(forwarded_ip) = first_forwarded_for_ip(forwarded_for) {
                return forwarded_ip.to_string();
            }
        }
        return remote_ip.to_string();
    }

    String::new()
}

fn first_forwarded_for_ip(raw: Option<&str>) -> Option<IpAddr> {
    raw?.split(',')
        .next()
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
        .and_then(|ip| ip.parse::<IpAddr>().ok())
}

fn is_rate_limited(ip: &str, limiter: &LoginLimiter) -> bool {
    let mut store = limiter.lock();
    let now = Instant::now();
    prune_limiter(&mut store, now);
    let mut remove_entry = false;

    if let Some(entry) = store.get_mut(ip) {
        if let Some(lockout_until) = entry.lockout_until {
            if now < lockout_until {
                return true;
            }
            entry.lockout_until = None;
        }

        if now.duration_since(entry.window_start) > ATTEMPT_WINDOW {
            remove_entry = true;
        }
    }

    if remove_entry {
        store.remove(ip);
    }

    false
}

fn record_failure(ip: &str, limiter: &LoginLimiter) {
    let mut store = limiter.lock();
    let now = Instant::now();
    prune_limiter(&mut store, now);
    let entry = store.entry(ip.to_owned()).or_insert(LoginAttempt {
        failure_count: 0,
        window_start: now,
        lockout_until: None,
    });

    // Reset window if the previous attempt window has expired.
    if now.duration_since(entry.window_start) > ATTEMPT_WINDOW {
        *entry = LoginAttempt {
            failure_count: 0,
            window_start: now,
            lockout_until: None,
        };
    }

    entry.failure_count += 1;
    if entry.failure_count >= MAX_ATTEMPTS {
        entry.lockout_until = Some(now + LOCKOUT_DURATION);
    }
}

fn prune_limiter(store: &mut HashMap<String, LoginAttempt>, now: Instant) {
    store.retain(|_, entry| {
        let lockout_active = entry.lockout_until.is_some_and(|until| now < until);
        let in_window = now.duration_since(entry.window_start) <= ATTEMPT_WINDOW;
        lockout_active || in_window
    });
}

/// Generates a 128-bit random hex token from /dev/urandom — no extra dependency needed.
fn generate_token() -> anyhow::Result<String> {
    let mut buf = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn parse_cookie_header(raw: &str) -> HashMap<String, String> {
    raw.split(';')
        .filter_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            Some((key.trim().to_owned(), percent_decode(value.trim())))
        })
        .collect()
}

fn parse_form_body(raw: &str) -> HashMap<String, String> {
    raw.split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((percent_decode(key), percent_decode(value)))
        })
        .collect()
}

fn percent_decode(raw: &str) -> String {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut iter = raw.as_bytes().iter().copied();
    while let Some(byte) = iter.next() {
        match byte {
            b'+' => bytes.push(b' '),
            b'%' => {
                let first = iter.next();
                let second = iter.next();
                if let (Some(first), Some(second)) = (first, second) {
                    if let Ok(value) =
                        u8::from_str_radix(&String::from_utf8_lossy(&[first, second]), 16)
                    {
                        bytes.push(value);
                        continue;
                    }
                }
                bytes.push(byte);
            }
            _ => bytes.push(byte),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn redirect_response(location: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string("")
        .with_status_code(StatusCode(303))
        .with_header(Header::from_bytes("Location", location).expect("valid header"))
}

fn session_cookie_header(token: &str) -> Header {
    let cookie =
        format!("session={token}; Max-Age={SESSION_SECONDS}; Path=/; HttpOnly; SameSite=Lax");
    Header::from_bytes("Set-Cookie", cookie).expect("valid header")
}

fn delete_cookie_header(name: &str) -> Header {
    let cookie = format!("{name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax");
    Header::from_bytes("Set-Cookie", cookie).expect("valid header")
}

fn json_header() -> Header {
    Header::from_bytes("Content-Type", "application/json").expect("valid header")
}

fn unauthorized_json_response() -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(r#"{"error":"unauthorized"}"#)
        .with_status_code(StatusCode(401))
        .with_header(json_header())
}

fn html_header() -> Header {
    Header::from_bytes("Content-Type", "text/html; charset=utf-8").expect("valid header")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cookie_header() {
        let cookies = parse_cookie_header("session=abc123; other=val");
        assert_eq!(cookies.get("session"), Some(&"abc123".to_owned()));
    }

    #[test]
    fn parses_form_body() {
        let form = parse_form_body("email=admin%40example.com&password=hello+world");
        assert_eq!(form.get("email"), Some(&"admin@example.com".to_owned()));
        assert_eq!(form.get("password"), Some(&"hello world".to_owned()));
    }

    #[test]
    fn rate_limiter_blocks_after_max_attempts() {
        let limiter: LoginLimiter = Arc::new(Mutex::new(HashMap::new()));
        for _ in 0..MAX_ATTEMPTS {
            assert!(!is_rate_limited("1.2.3.4", &limiter));
            record_failure("1.2.3.4", &limiter);
        }
        assert!(is_rate_limited("1.2.3.4", &limiter));
    }

    #[test]
    fn rate_limiter_uses_lockout_until_instead_of_window_start() {
        let limiter: LoginLimiter = Arc::new(Mutex::new(HashMap::new()));
        limiter.lock().insert(
            "1.2.3.4".to_owned(),
            LoginAttempt {
                failure_count: MAX_ATTEMPTS,
                window_start: Instant::now() - LOCKOUT_DURATION,
                lockout_until: Some(Instant::now() + LOCKOUT_DURATION),
            },
        );

        assert!(is_rate_limited("1.2.3.4", &limiter));
    }

    #[test]
    fn rate_limiter_clears_expired_lockout() {
        let limiter: LoginLimiter = Arc::new(Mutex::new(HashMap::new()));
        limiter.lock().insert(
            "1.2.3.4".to_owned(),
            LoginAttempt {
                failure_count: MAX_ATTEMPTS,
                window_start: Instant::now(),
                lockout_until: Some(Instant::now() - Duration::from_secs(1)),
            },
        );

        assert!(!is_rate_limited("1.2.3.4", &limiter));
        assert_eq!(
            limiter
                .lock()
                .get("1.2.3.4")
                .and_then(|entry| entry.lockout_until),
            None
        );
    }

    #[test]
    fn rate_limiter_prunes_stale_entries() {
        let now = Instant::now();
        let mut store = HashMap::new();
        store.insert(
            "stale".to_owned(),
            LoginAttempt {
                failure_count: 1,
                window_start: now - ATTEMPT_WINDOW - Duration::from_secs(1),
                lockout_until: None,
            },
        );
        store.insert(
            "in-window".to_owned(),
            LoginAttempt {
                failure_count: 1,
                window_start: now,
                lockout_until: None,
            },
        );
        store.insert(
            "locked".to_owned(),
            LoginAttempt {
                failure_count: MAX_ATTEMPTS,
                window_start: now - ATTEMPT_WINDOW - Duration::from_secs(1),
                lockout_until: Some(now + LOCKOUT_DURATION),
            },
        );

        prune_limiter(&mut store, now);

        assert!(!store.contains_key("stale"));
        assert!(store.contains_key("in-window"));
        assert!(store.contains_key("locked"));
    }

    #[test]
    fn client_ip_ignores_forwarded_for_from_untrusted_peer() {
        let trusted = HashSet::new();
        let ip = vetted_client_ip(
            Some("203.0.113.10".parse().unwrap()),
            Some("198.51.100.20"),
            &trusted,
        );

        assert_eq!(ip, "203.0.113.10");
    }

    #[test]
    fn client_ip_uses_forwarded_for_from_trusted_proxy() {
        let trusted = HashSet::from(["127.0.0.1".parse().unwrap()]);
        let ip = vetted_client_ip(
            Some("127.0.0.1".parse().unwrap()),
            Some("198.51.100.20, 203.0.113.10"),
            &trusted,
        );

        assert_eq!(ip, "198.51.100.20");
    }

    #[test]
    fn generate_token_is_32_chars() {
        let token = generate_token().unwrap();
        assert_eq!(token.len(), 32);
    }
}
