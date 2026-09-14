use crate::{
    model::{AppState, TokenClaims, User},
    session_mgr::{cookie_value, is_token_revoked, token_cookie_name},
};

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json;
use std::{
    collections::HashMap,
    error::Error,
    fmt,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tiny_http::Request;

const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";

#[derive(Deserialize, Clone, Serialize)]
pub struct OAuthCreds {
    pub access_token: String,
    pub expires_in: u64,
    pub id_token: Option<String>,
    pub scope: String,
    pub token_type: String,
    pub refresh_token: Option<String>,
}

/// Never let bearer tokens reach a log line through a stray `{:?}`.
impl fmt::Debug for OAuthCreds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthCreds")
            .field("access_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .field("scope", &self.scope)
            .field("token_type", &self.token_type)
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// The subset of Google's OpenID Connect `id_token` claims we rely on. These
/// come from a token whose RS256 signature, issuer, audience and expiry have
/// been verified, so unlike the `userinfo` endpoint they cannot be spoofed by
/// anything short of Google's signing key.
#[derive(Deserialize)]
pub struct GoogleIdClaims {
    pub sub: String,
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    pub name: Option<String>,
    pub nonce: Option<String>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Exchange the authorization code for tokens, verify the identity Google
/// asserts, enforce the allowlist, and upsert the local user record. Returns
/// the local user id on success.
pub fn request_token(
    app_data: &AppState,
    authorization_code: &str,
    code_verifier: &str,
    expected_nonce: &str,
) -> Result<String, Box<dyn Error>> {
    let env = app_data.env.lock().unwrap_or_else(|e| e.into_inner());
    let redirect_url = env.google_oauth_redirect_url.to_owned();
    let client_secret = env.google_oauth_client_secret.to_owned();
    let client_id = env.google_oauth_client_id.to_owned();
    let allowed_emails = env.allowed_emails.clone();
    drop(env);

    // `send_form` percent-encodes every value, so a code or secret containing
    // reserved characters can neither break the request nor be misread.
    let response = ureq::post(GOOGLE_TOKEN_URL)
        .send_form([
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", authorization_code),
            ("code_verifier", code_verifier),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_url.as_str()),
        ])
        .map_err(|e| -> Box<dyn Error> {
            log::error!("(request_token) token exchange failed: {e}");
            "An error occurred while trying to retrieve the access token".into()
        })?;
    let oauth_creds = response.into_body().read_json::<OAuthCreds>()?;

    // Validate the id_token that came back with the token response instead of
    // trusting its shape. A missing id_token or a token that fails signature/
    // audience/issuer validation must be a clean error, not a worker panic.
    let parser = JWTParser::new(&client_id)?;
    let id_token = oauth_creds
        .id_token
        .clone()
        .ok_or_else(|| -> Box<dyn Error> { "token response contained no id_token".into() })?;
    let claims = parser
        .parse::<GoogleIdClaims>(&id_token)
        .map_err(|e| -> Box<dyn Error> { format!("id_token validation failed: {e}").into() })?;

    // The nonce binds this id_token to the handshake session that requested it.
    if claims.nonce.as_deref() != Some(expected_nonce) {
        return Err(From::from("id_token nonce mismatch"));
    }
    // Google accounts can carry an unverified (non-Gmail) address. Without this
    // check anyone could register a Google account claiming an allowlisted
    // address and sign in without ever proving they control it.
    if !claims.email_verified {
        log::warn!("(request_token) sign-in blocked: Google reports the email as unverified");
        return Err(From::from("email not verified, not authorised"));
    }
    let email = claims.email.trim().to_lowercase();
    if email.is_empty() {
        return Err(From::from("id_token contained no email"));
    }

    let mut user_db = app_data.db.lock().unwrap_or_else(|e| e.into_inner());
    let user = user_db.iter_mut().find(|user| user.email == email);
    // Access control: an explicit allowlist gates who may sign in. When the
    // allowlist is empty we fall back to allowing only pre-existing users so an
    // unconfigured deployment can't be hijacked by open self-registration.
    if allowed_emails.is_empty() {
        if user.is_none() {
            log::warn!("(request_token) sign-in blocked: empty allowlist and no existing user for {email}");
            return Err(From::from("email not authorised"));
        }
    } else if !allowed_emails.contains(&email) {
        log::warn!("(request_token) sign-in blocked: {email} not in allowlist");
        return Err(From::from("email not authorised"));
    }

    let current_datetime = Utc::now();
    let expires_in = unix_now() + oauth_creds.expires_in;
    let user_id: String;
    if let Some(user) = user {
        user_id = user.id.clone();
        user.updatedAt = current_datetime;
        if let Some(name) = claims.name {
            user.name = name;
        }
        user.verified = true;
        // Google only returns a refresh token on the first consent; keep the
        // one we already have when the new response omits it.
        let refresh_token = oauth_creds
            .refresh_token
            .clone()
            .or_else(|| user.credentials.refresh_token.clone());
        user.credentials = OAuthCreds {
            access_token: oauth_creds.access_token.clone(),
            expires_in,
            id_token: None,
            scope: oauth_creds.scope.clone(),
            token_type: oauth_creds.token_type,
            refresh_token,
        };
    } else {
        user_id = claims.sub;
        let user_data = User {
            id: user_id.clone(),
            name: claims.name.unwrap_or_else(|| email.clone()),
            email,
            verified: true,
            credentials: OAuthCreds {
                access_token: oauth_creds.access_token.clone(),
                expires_in,
                id_token: None,
                scope: oauth_creds.scope.clone(),
                token_type: oauth_creds.token_type.clone(),
                refresh_token: oauth_creds.refresh_token,
            },
            createdAt: current_datetime,
            updatedAt: current_datetime,
        };
        user_db.push(user_data);
    };
    drop(user_db);
    app_data.save("secrets/");

    Ok(user_id)
}

pub fn refresh_token(app_data: &AppState, user: &User) -> Result<OAuthCreds, Box<dyn Error>> {
    let env = app_data.env.lock().unwrap_or_else(|e| e.into_inner());
    let client_secret = env.google_oauth_client_secret.to_owned();
    let client_id = env.google_oauth_client_id.to_owned();
    drop(env);
    let refresh_token = user
        .credentials
        .refresh_token
        .to_owned()
        .ok_or_else(|| -> Box<dyn Error> { "no refresh token available for user".into() })?;
    let response = ureq::post(GOOGLE_TOKEN_URL)
        .send_form([
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
        ])
        .map_err(|e| -> Box<dyn Error> {
            log::error!("(refresh_token) refresh failed: {e}");
            "An error occurred while trying to refresh the access token".into()
        })?;
    let mut oauth_creds = response.into_body().read_json::<OAuthCreds>()?;
    oauth_creds.refresh_token = user.credentials.refresh_token.clone();
    oauth_creds.id_token = None;
    oauth_creds.expires_in += unix_now();
    let mut user_db = app_data.db.lock().unwrap_or_else(|e| e.into_inner());
    // The user could have been removed between the auth check and here; treat
    // that as an error rather than panicking the worker.
    let user_to_update = user_db
        .iter_mut()
        .find(|user_to_update| user_to_update.id == user.id)
        .ok_or_else(|| -> Box<dyn Error> { "user no longer exists".into() })?;
    user_to_update.credentials = oauth_creds.clone();
    user_to_update.updatedAt = Utc::now();
    drop(user_db);
    app_data.save("secrets/");
    Ok(oauth_creds)
}

/// Disconnect the app from the user's Google account. Revoking the refresh
/// token (when we hold one) revokes the whole grant, including any live access
/// token; revoking only the access token would leave the refresh token usable.
/// Local credentials are cleared even if Google rejects the call (typically
/// because the token is already invalid) so the user's intent is honoured.
pub fn revoke_token(app_data: &AppState, user: &User) -> Result<(), Box<dyn Error>> {
    let token = user
        .credentials
        .refresh_token
        .as_deref()
        .unwrap_or(user.credentials.access_token.as_str());
    if let Err(e) = ureq::post(GOOGLE_REVOKE_URL).send_form([("token", token)]) {
        log::warn!("(revoke_token) Google rejected the revocation (clearing local credentials anyway): {e}");
    }
    let mut user_db = app_data.db.lock().unwrap_or_else(|e| e.into_inner());
    let user_to_update = user_db
        .iter_mut()
        .find(|user_to_update| user_to_update.id == user.id)
        .ok_or_else(|| -> Box<dyn Error> { "user no longer exists".into() })?;
    user_to_update.credentials.access_token = String::new();
    user_to_update.credentials.expires_in = 0;
    user_to_update.credentials.refresh_token = None;
    user_to_update.credentials.id_token = None;
    user_to_update.updatedAt = Utc::now();
    drop(user_db);
    app_data.save("secrets/");
    log::info!("(handle_revoke) revoked access/refresh token");
    Ok(())
}

#[derive(Debug, Serialize)]
pub enum AuthError {
    MissingToken,
    InvalidToken,
}

pub type AuthGuard<T> = Result<T, AuthError>;

#[derive(Serialize)]
pub struct ValidUser {
    pub user: User,
    /// Claims of the presented session token; `jti`/`exp` are needed to revoke
    /// it on logout.
    pub claims: TokenClaims,
}

impl ValidUser {
    pub fn from_request(app_data: &AppState, request: &Request) -> AuthGuard<ValidUser> {
        // The session token is accepted from the auth cookie only. (An earlier
        // version also accepted `Authorization: Bearer`, which nothing used.)
        let token = request
            .headers()
            .iter()
            .find(|header| header.field.equiv("Cookie"))
            .and_then(|h| cookie_value(h.value.as_str(), token_cookie_name()).map(str::to_owned));

        let Some(token) = token else {
            log::debug!("missing token, user not logged in");
            return Err(AuthError::MissingToken);
        };
        let (jwt_secret, allowed_emails) = {
            let env = app_data.env.lock().unwrap_or_else(|e| e.into_inner());
            (env.jwt_secret.to_owned(), env.allowed_emails.clone())
        };
        let mut validation = Validation::new(Algorithm::HS256);
        validation.required_spec_claims.insert("jti".to_string());
        let claims = match decode::<TokenClaims>(
            &token,
            &DecodingKey::from_secret(jwt_secret.as_ref()),
            &validation,
        ) {
            Ok(data) => data.claims,
            Err(e) => {
                log::warn!("invalid session token: {e}");
                return Err(AuthError::InvalidToken);
            }
        };
        if is_token_revoked(&claims.jti) {
            log::warn!("session token was logged out");
            return Err(AuthError::InvalidToken);
        }

        let user_opt = {
            let user_db = app_data.db.lock().unwrap_or_else(|e| e.into_inner());
            user_db
                .iter()
                .find(|user| user.id == claims.sub)
                .cloned()
        };
        let Some(mut user) = user_opt else {
            log::warn!("user belonging to this token no longer exists");
            return Err(AuthError::InvalidToken);
        };
        // Re-check the allowlist on every request so removing an address from
        // ALLOWED_EMAILS takes effect immediately, not at the next login.
        if !allowed_emails.is_empty() && !allowed_emails.contains(&user.email) {
            log::warn!("(auth) {} is no longer in the allowlist", user.email);
            return Err(AuthError::InvalidToken);
        }

        let needs_refresh = unix_now() + 60 > user.credentials.expires_in;
        if needs_refresh {
            if user.credentials.refresh_token.is_some() {
                match refresh_token(app_data, &user) {
                    Ok(updated_creds) => {
                        user.credentials = updated_creds;
                    }
                    Err(e) => {
                        log::warn!("(auth) token refresh failed: {:?}", e);
                    }
                }
            } else {
                log::debug!("(auth) Google token expiring but no refresh token available");
            }
        }

        Ok(ValidUser { user, claims })
    }
}

// JWT Stuff

#[derive(Deserialize, Clone)]
pub struct GoogleKeys {
    keys: Vec<GoogleKey>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct GoogleKey {
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug)]
pub enum GoogleKeyProviderError {
    KeyNotFound(String),
    FetchError(String),
    ParseError(String),
    CreateKeyError(String),
}

#[derive(Debug)]
pub enum JWTParserError {
    WrongHeader,
    UnknownKid,
    KeyProvider(GoogleKeyProviderError),
    WrongToken(jsonwebtoken::errors::Error),
}

impl fmt::Display for GoogleKeyProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GoogleKeyProviderError::KeyNotFound(msg) => write!(f, "key not found: {}", msg),
            GoogleKeyProviderError::FetchError(msg) => write!(f, "fetch error: {}", msg),
            GoogleKeyProviderError::ParseError(msg) => write!(f, "parse error: {}", msg),
            GoogleKeyProviderError::CreateKeyError(msg) => write!(f, "key creation error: {}", msg),
        }
    }
}

impl fmt::Display for JWTParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JWTParserError::WrongHeader => write!(f, "wrong JWT header"),
            JWTParserError::UnknownKid => write!(f, "unknown key id"),
            JWTParserError::KeyProvider(e) => write!(f, "key provider error: {}", e),
            JWTParserError::WrongToken(e) => write!(f, "invalid token: {}", e),
        }
    }
}

pub struct JWTParser {
    client_id: String,
    key_provider: Arc<Mutex<GooglePublicKeyProvider>>,
}

impl JWTParser {
    pub fn new(client_id: &str) -> Result<Self, Box<dyn Error>> {
        let oidc_config_url = "https://accounts.google.com/.well-known/openid-configuration";
        let oidc_config_resp = ureq::get(oidc_config_url).call()?;
        let oidc_config: serde_json::Value = oidc_config_resp.into_body().read_json()?;
        let jwks_uri = oidc_config["jwks_uri"]
            .as_str()
            .ok_or_else(|| -> Box<dyn Error> {
                "OIDC discovery document had no jwks_uri".into()
            })?;
        // The discovery document is fetched over TLS from Google, but never
        // follow it somewhere else: the key set must come from Google as well.
        if !jwks_uri.starts_with("https://www.googleapis.com/") {
            return Err(From::from("OIDC discovery document pointed jwks_uri off-domain"));
        }
        Ok(Self {
            client_id: client_id.to_owned(),
            key_provider: Arc::new(Mutex::new(GooglePublicKeyProvider::new(jwks_uri))),
        })
    }

    pub fn parse<T: DeserializeOwned>(&self, token: &str) -> Result<T, JWTParserError> {
        let mut provider = self.key_provider.lock().unwrap_or_else(|e| e.into_inner());
        match jsonwebtoken::decode_header(token) {
            Ok(header) => match header.kid {
                None => Result::Err(JWTParserError::UnknownKid),
                Some(kid) => match provider.get_key(kid.as_str()) {
                    Ok(key) => {
                        let aud = vec![self.client_id.to_owned()];
                        let mut validation = Validation::new(Algorithm::RS256);
                        validation.set_audience(&aud);
                        validation.set_issuer(&[
                            "https://accounts.google.com".to_string(),
                            "accounts.google.com".to_string(),
                        ]);
                        validation.validate_exp = true;
                        validation.validate_nbf = false;
                        let result = jsonwebtoken::decode::<T>(token, &key, &validation);
                        match result {
                            Result::Ok(token_data) => Result::Ok(token_data.claims),
                            Result::Err(error) => Result::Err(JWTParserError::WrongToken(error)),
                        }
                    }
                    Err(e) => {
                        let error = JWTParserError::KeyProvider(e);
                        Result::Err(error)
                    }
                },
            },
            Err(_) => Result::Err(JWTParserError::WrongHeader),
        }
    }
}

#[derive(Debug)]
pub struct GooglePublicKeyProvider {
    url: String,
    keys: HashMap<String, GoogleKey>,
    expiration_time: Option<Instant>,
}

impl GooglePublicKeyProvider {
    pub fn new(public_key_url: &str) -> Self {
        Self {
            url: public_key_url.to_owned(),
            keys: Default::default(),
            expiration_time: None,
        }
    }

    pub fn reload(&mut self) -> Result<(), GoogleKeyProviderError> {
        match ureq::get(&self.url).call() {
            Ok(r) => {
                let expiration_time = r
                    .headers()
                    .get("cache-control")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| {
                        v.split(',')
                            .find(|s| s.contains("max-age"))
                            .and_then(|s| s.split('=').nth(1))
                            .and_then(|s| s.trim().parse::<u64>().ok())
                    })
                    .map(|s| Instant::now() + std::time::Duration::from_secs(s));
                match r.into_body().read_json::<GoogleKeys>() {
                    Ok(google_keys) => {
                        self.keys.clear();
                        for key in google_keys.keys.into_iter() {
                            self.keys.insert(key.kid.clone(), key);
                        }
                        self.expiration_time = expiration_time;
                        Result::Ok(())
                    }
                    Err(e) => Result::Err(GoogleKeyProviderError::ParseError(format!("{:?}", e))),
                }
            }
            Err(e) => Result::Err(GoogleKeyProviderError::FetchError(format!("{:?}", e))),
        }
    }

    pub fn is_expire(&self) -> bool {
        if let Some(expire) = self.expiration_time {
            Instant::now() > expire
        } else {
            false
        }
    }

    pub fn get_key(&mut self, kid: &str) -> Result<DecodingKey, GoogleKeyProviderError> {
        if self.expiration_time.is_none() || self.is_expire() {
            self.reload()?
        }
        match self.keys.get(kid) {
            None => Result::Err(GoogleKeyProviderError::KeyNotFound(
                "couldn't match kid".to_string(),
            )),
            Some(key) => DecodingKey::from_rsa_components(key.n.as_str(), key.e.as_str())
                .map_err(|e| GoogleKeyProviderError::CreateKeyError(e.to_string())),
        }
    }
}
