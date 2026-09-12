use rand::{RngExt, distr::Alphanumeric};
use std::{env, fs::File};

#[derive(Debug, Clone)]
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

impl Config {
    pub fn init() -> Config {
        let config = Config {
            postgres_connection_string: require_env("POSTGRES_CONNECTION_STRING"),
            jwt_secret: env::var("JWT_SECRET").unwrap_or_else(|_| {
                log::warn!(
                    "JWT_SECRET not set; generating an ephemeral secret. All sessions will \
                     be invalidated on restart — set JWT_SECRET to a fixed random value in \
                     production."
                );
                generate_secret()
            }),
            jwt_max_age: require_env("TOKEN_MAXAGE")
                .parse()
                .expect("TOKEN_MAXAGE not a number"),
            google_oauth_client_id: require_env("GOOGLE_OAUTH_CLIENT_ID"),
            google_oauth_client_secret: require_env("GOOGLE_OAUTH_CLIENT_SECRET"),
            google_oauth_redirect_url: require_env("GOOGLE_OAUTH_REDIRECT_URI"),
            allowed_emails: env::var("ALLOWED_EMAILS")
                .unwrap_or_default()
                .split(',')
                .map(|e| e.trim().to_lowercase())
                .filter(|e| !e.is_empty())
                .collect(),
            cookie_secure: env::var("COOKIE_SECURE")
                .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false),
        };
        log::info!("config initialised from environment");
        config
    }
}

fn require_env(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("{key} not set"))
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

pub fn restrict_permissions(file: &File) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
            log::warn!("could not restrict secrets file permissions: {e}");
        }
    }
}

pub fn generate_secret() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .map(char::from)
        .filter(|&c| c.is_ascii_lowercase() || c.is_ascii_uppercase() || c.is_ascii_digit())
        .take(64)
        .collect::<String>()
}
