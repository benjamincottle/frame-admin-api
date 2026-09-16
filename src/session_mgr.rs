//! Two small pieces of server-side state that back the cookie-based auth flow.
//!
//! * `SESSION_MGR` holds short-lived *login handshake* sessions: the OAuth
//!   `state`, PKCE verifier and OIDC nonce between `/oauth/authorise` and the
//!   `/oauth/google` callback. Values are read exactly once and the session is
//!   discarded when the callback completes.
//! * `REVOKED_TOKENS` is a deny-list of app session tokens (by `jti`) that were
//!   logged out before their natural expiry, so logout actually ends a session
//!   rather than only clearing the browser cookie.

use crate::config::random_token;
use std::{
    collections::HashMap,
    ops::Deref,
    sync::{LazyLock, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tiny_http::Request;

/// Lifetime of a login-handshake session. It only needs to cover the round trip
/// to Google's consent screen.
pub const OAUTH_SESSION_TTL_SECS: u64 = 600;

/// Hard cap on concurrent handshake sessions so unauthenticated hits on
/// `/oauth/login` cannot grow memory without bound inside the container's
/// memory limit. The soonest-to-expire session is evicted when full.
const MAX_SESSIONS: usize = 256;

/// Name of the handshake cookie (scoped to `/frame_admin/oauth`).
pub const SESSION_COOKIE: &str = "session";

static SECURE_COOKIES: OnceLock<bool> = OnceLock::new();

/// Record once at startup whether cookies are issued with the `Secure`
/// attribute. Read by every handler that sets or looks up cookies.
pub fn set_secure_cookies(secure: bool) {
    let _ = SECURE_COOKIES.set(secure);
}

pub fn secure_cookies() -> bool {
    *SECURE_COOKIES.get().unwrap_or(&false)
}

/// Name of the auth cookie. When cookies are `Secure` the `__Host-` prefix is
/// used, which makes the browser refuse the cookie unless it was set by this
/// exact host over HTTPS with `Path=/` and no `Domain` — so a sibling
/// subdomain cannot plant or overwrite it.
pub fn token_cookie_name() -> &'static str {
    if secure_cookies() {
        "__Host-token"
    } else {
        "token"
    }
}

pub static SESSION_MGR: LazyLock<SharedSessionManager> = LazyLock::new(|| {
    let session_mgr = SessionManager {
        sessions: HashMap::new(),
        session_duration: Duration::from_secs(OAUTH_SESSION_TTL_SECS),
    };
    log::info!("session manager created");
    SharedSessionManager(Mutex::new(session_mgr))
});
static REVOKED_TOKENS: LazyLock<Mutex<HashMap<String, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub struct SharedSessionManager(Mutex<SessionManager>);

impl Deref for SharedSessionManager {
    type Target = Mutex<SessionManager>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SharedSessionManager {
    #[allow(unused_must_use)]
    pub fn initialise(&self) {
        self.lock().unwrap_or_else(|e| e.into_inner());
    }

    pub fn create_session(&self) -> SessionID {
        let mut session_mgr = self.lock().unwrap_or_else(|e| e.into_inner());
        let now = SystemTime::now();
        session_mgr.sessions.retain(|_, session| session.expires > now);
        if session_mgr.sessions.len() >= MAX_SESSIONS {
            let victim = session_mgr
                .sessions
                .iter()
                .min_by_key(|(_, session)| session.expires)
                .map(|(id, _)| id.clone());
            if let Some(victim) = victim {
                log::warn!("(session) handshake session cap reached; evicting oldest");
                session_mgr.sessions.remove(&victim);
            }
        }
        let session_id = random_token(64);
        let session = Session::new(session_mgr.session_duration);
        session_mgr.sessions.insert(session_id.clone(), session);
        session_id
    }

    pub fn get_session_id(&self, request: &Request) -> Result<SessionID, SessionError> {
        let mut session_mgr = self.lock().unwrap_or_else(|e| e.into_inner());
        // Drop abandoned sessions on access so the in-memory map can't grow
        // between the cleanups in create_session.
        let now = SystemTime::now();
        session_mgr.sessions.retain(|_, session| session.expires > now);
        let cookie = request
            .headers()
            .iter()
            .find(|header| header.field.equiv("Cookie"))
            .ok_or(SessionError::MissingCookie)?
            .value
            .to_string();
        let session_id = cookie_value(&cookie, SESSION_COOKIE).ok_or(SessionError::InvalidCookie)?;
        match session_mgr.sessions.get(session_id) {
            Some(session) if session.expires > now => Ok(session_id.to_string()),
            Some(_) => {
                session_mgr.sessions.remove(session_id);
                Err(SessionError::ExpiredSession)
            }
            None => Err(SessionError::InvalidSession),
        }
    }

    pub fn set_session_data(&self, session_id: &str, key: &str, value: &str) {
        let mut session_mgr = self.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(session) = session_mgr.sessions.get_mut(session_id) {
            session.data.insert(key.to_string(), value.to_string());
        }
    }

    /// Read *and remove* a value, so handshake secrets (`state`, PKCE verifier,
    /// nonce) can be consumed exactly once and a replayed callback fails.
    pub fn take_session_data(&self, session_id: &str, key: &str) -> Option<Value> {
        let mut session_mgr = self.lock().unwrap_or_else(|e| e.into_inner());
        session_mgr
            .sessions
            .get_mut(session_id)
            .and_then(|session| session.data.remove(key))
    }

    pub fn remove_session(&self, session_id: &str) {
        let mut session_mgr = self.lock().unwrap_or_else(|e| e.into_inner());
        session_mgr.sessions.remove(session_id);
    }

    pub fn generate_state(&self) -> String {
        random_token(64)
    }
}

/// Extract a named cookie from a `Cookie` header value. Tolerates whitespace
/// and any ordering (browsers send `a=1; b=2`, so a naive `starts_with` only
/// ever matched the first cookie).
pub fn cookie_value<'a>(header_value: &'a str, name: &str) -> Option<&'a str> {
    header_value.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key.trim() == name).then(|| value.trim())
    })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Mark an app token as logged out until it would have expired anyway.
pub fn revoke_token_id(jti: &str, exp: u64) {
    let mut revoked = REVOKED_TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    let now = now_unix();
    revoked.retain(|_, token_exp| *token_exp > now);
    if exp > now {
        revoked.insert(jti.to_string(), exp);
    }
}

pub fn is_token_revoked(jti: &str) -> bool {
    let revoked = REVOKED_TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    revoked
        .get(jti)
        .is_some_and(|token_exp| *token_exp > now_unix())
}

#[derive(Debug)]
pub enum SessionError {
    MissingCookie,
    InvalidCookie,
    InvalidSession,
    ExpiredSession,
}

type Key = String;
type Value = String;
type SessionID = String;

#[derive(Clone)]
struct Session {
    data: HashMap<Key, Value>,
    expires: SystemTime,
}

impl Session {
    fn new(session_duration: Duration) -> Self {
        Self {
            data: HashMap::new(),
            expires: SystemTime::now() + session_duration,
        }
    }
}

pub struct SessionManager {
    sessions: HashMap<SessionID, Session>,
    session_duration: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_value_finds_any_position_and_trims() {
        let header = "a=1; session=abc ; __Host-token=xyz";
        assert_eq!(cookie_value(header, "session"), Some("abc"));
        assert_eq!(cookie_value(header, "__Host-token"), Some("xyz"));
        assert_eq!(cookie_value(header, "a"), Some("1"));
        assert_eq!(cookie_value(header, "token"), None);
        assert_eq!(cookie_value("sessionx=1", "session"), None);
    }

    #[test]
    fn revocation_expires() {
        revoke_token_id("past", 1);
        assert!(!is_token_revoked("past"));
        revoke_token_id("future", now_unix() + 3600);
        assert!(is_token_revoked("future"));
        assert!(!is_token_revoked("unknown"));
    }
}
