use rand::{RngExt, distr::Alphanumeric};
use std::{env, fmt, fs::File, path::Path};

/// Minimum accepted length for a user-supplied `JWT_SECRET`. HS256 session
/// tokens are exactly as strong as this secret, so a short value makes every
/// session forgeable offline.
const MIN_JWT_SECRET_LEN: usize = 32;

/// Upper bound on the session lifetime. A longer-lived admin cookie only widens
/// the window in which a leaked token remains useful.
const MAX_TOKEN_MAXAGE_SECS: i64 = 24 * 60 * 60;

#[derive(Clone)]
pub struct Config {
    pub postgres_connection_string: String,
    pub jwt_secret: String,
    pub jwt_max_age: i64,
    pub google_oauth_client_id: String,
    pub google_oauth_client_secret: String,
    pub google_oauth_redirect_url: String,
    pub allowed_emails: Vec<String>,
    pub cookie_secure: bool,
}

/// Never let secrets reach a log line through a stray `{:?}`.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("postgres_connection_string", &"<redacted>")
            .field("jwt_secret", &"<redacted>")
            .field("jwt_max_age", &self.jwt_max_age)
            .field("google_oauth_client_id", &self.google_oauth_client_id)
            .field("google_oauth_client_secret", &"<redacted>")
            .field("google_oauth_redirect_url", &self.google_oauth_redirect_url)
            .field("allowed_emails", &self.allowed_emails)
            .field("cookie_secure", &self.cookie_secure)
            .finish()
    }
}

impl Config {
    pub fn init() -> Config {
        let jwt_secret = match env::var("JWT_SECRET") {
            Ok(secret) if secret.len() >= MIN_JWT_SECRET_LEN => secret,
            Ok(_) => fatal(&format!(
                "JWT_SECRET is too short; provide at least {MIN_JWT_SECRET_LEN} characters of random data"
            )),
            Err(_) => {
                log::warn!(
                    "JWT_SECRET not set; generating an ephemeral secret. All sessions will \
                     be invalidated on restart — set JWT_SECRET to a fixed random value in \
                     production."
                );
                random_token(64)
            }
        };

        let jwt_max_age: i64 = require_env("TOKEN_MAXAGE")
            .parse()
            .unwrap_or_else(|_| fatal("TOKEN_MAXAGE is not a number"));
        if !(1..=MAX_TOKEN_MAXAGE_SECS).contains(&jwt_max_age) {
            fatal(&format!(
                "TOKEN_MAXAGE must be between 1 and {MAX_TOKEN_MAXAGE_SECS} seconds"
            ));
        }

        let google_oauth_redirect_url = require_env("GOOGLE_OAUTH_REDIRECT_URI");
        match url::Url::parse(&google_oauth_redirect_url) {
            Ok(u) if u.scheme() == "https" => {}
            Ok(u) if u.scheme() == "http" => {
                log::warn!(
                    "GOOGLE_OAUTH_REDIRECT_URI uses plain http; only acceptable for local development"
                );
            }
            _ => fatal("GOOGLE_OAUTH_REDIRECT_URI must be an absolute http(s) URL"),
        }

        let allowed_emails: Vec<String> = env::var("ALLOWED_EMAILS")
            .unwrap_or_default()
            .split(',')
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty())
            .collect();
        if allowed_emails.is_empty() {
            log::warn!(
                "ALLOWED_EMAILS is empty; sign-in is restricted to accounts already present in user_db.json"
            );
        }

        let cookie_secure = env::var("COOKIE_SECURE")
            .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);
        if !cookie_secure {
            log::warn!(
                "COOKIE_SECURE is off; session cookies will be sent over plain HTTP. Only acceptable for local development"
            );
        }

        let config = Config {
            postgres_connection_string: require_env("POSTGRES_CONNECTION_STRING"),
            jwt_secret,
            jwt_max_age,
            google_oauth_client_id: require_env("GOOGLE_OAUTH_CLIENT_ID"),
            google_oauth_client_secret: require_env("GOOGLE_OAUTH_CLIENT_SECRET"),
            google_oauth_redirect_url,
            allowed_emails,
            cookie_secure,
        };
        log::info!("config initialised from environment");
        config
    }
}

fn fatal(message: &str) -> ! {
    log::error!("{message}");
    std::process::exit(1)
}

fn require_env(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| fatal(&format!("{key} not set")))
}

pub fn load_env_file(path: &str) {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"').trim_matches('\'');
        if key.is_empty() || env::var_os(key).is_some() {
            continue;
        }
        // SAFETY: called once during startup, before any worker threads are
        // spawned, so there is no concurrent access to the environment.
        unsafe { env::set_var(key, value) };
    }
}

/// Create (or truncate) a file that is readable and writable only by the
/// owning user. The mode is applied at creation time so there is no window in
/// which the file exists with default (world-readable) permissions.
pub fn create_private_file(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    // Belt and braces for a pre-existing file whose mode was wider.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
            log::warn!("could not restrict secrets file permissions: {e}");
        }
    }
    Ok(file)
}

/// Cryptographically random alphanumeric string. `rand::rng()` is a
/// ChaCha-based CSPRNG seeded from the OS, so this is suitable for session
/// identifiers, OAuth `state`, PKCE verifiers and CSP nonces.
pub fn random_token(len: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .map(char::from)
        .take(len)
        .collect()
}
