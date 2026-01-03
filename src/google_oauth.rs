use crate::model::{AppState, TokenClaims, User};

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

#[derive(Deserialize, Debug, Clone, Serialize)]
pub struct OAuthCreds {
    pub access_token: String,
    pub expires_in: u64,
    pub id_token: Option<String>,
    pub scope: String,
    pub token_type: String,
    pub refresh_token: Option<String>,
}

#[derive(Deserialize)]
pub struct GoogleUserResult {
    pub email: String,
    pub verified_email: bool,
    pub name: String,
}

pub fn request_token(
    app_data: &AppState,
    authorization_code: &str,
) -> Result<String, Box<dyn Error>> {
    let env = app_data.env.lock().unwrap();
    let redirect_url = env.google_oauth_redirect_url.to_owned();
    let client_secret = env.google_oauth_client_secret.to_owned();
    let client_id = env.google_oauth_client_id.to_owned();
    drop(env);
    let response = ureq::post("https://oauth2.googleapis.com/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(format!(
            "client_id={}&client_secret={}&code={}&grant_type=authorization_code&redirect_uri={}",
            client_id, client_secret, authorization_code, redirect_url
        ));
    if response.is_ok() {
        let oauth_creds = response
            .expect("response is ok")
            .into_body()
            .read_json::<OAuthCreds>()?;
        let parser = JWTParser::new(&client_id).expect("couldn't create JWTParser");
        let claims = parser
            .parse::<TokenClaims>(&oauth_creds.id_token.clone().expect("id_token is some"))
            .expect("couldn't parse jwt token");
        let google_user = get_google_user(&oauth_creds.access_token)?;
        let mut user_db = app_data.db.lock().unwrap();
        let email = google_user.email.to_lowercase();
        let user = user_db.iter_mut().find(|user| user.email == email);
        let current_datetime = Utc::now();
        let expires_in = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
            + oauth_creds.expires_in;
        let user_id: String;
        if let Some(user) = user {
            user_id = user.id.clone();
            email.clone_into(&mut user.email);
            user.updatedAt = current_datetime;
            let refresh_token = match oauth_creds.refresh_token.clone() {
                Some(refresh_token) => Some(refresh_token),
                None => user.credentials.refresh_token.clone(),
            };
            user.credentials = OAuthCreds {
                access_token: oauth_creds.access_token.clone(),
                expires_in,
                id_token: oauth_creds.id_token.clone(),
                scope: oauth_creds.scope.clone(),
                token_type: oauth_creds.token_type,
                refresh_token,
            };
        } else {
            user_id = claims.sub;
            let user_data = User {
                id: user_id.clone(),
                name: google_user.name,
                email,
                verified: google_user.verified_email,
                credentials: OAuthCreds {
                    access_token: oauth_creds.access_token.clone(),
                    expires_in,
                    id_token: oauth_creds.id_token.clone(),
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
    } else {
        let message = "An error occurred while trying to retrieve the access token";
        Err(From::from(message))
    }
}

pub fn refresh_token(app_data: &AppState, user: &User) -> Result<OAuthCreds, Box<dyn Error>> {
    let env = app_data.env.lock().unwrap();
    let client_secret = env.google_oauth_client_secret.to_owned();
    let client_id = env.google_oauth_client_id.to_owned();
    drop(env);
    let refresh_token = user
        .credentials
        .refresh_token
        .to_owned()
        .expect("refresh token should be present");
    let response = ureq::post("https://oauth2.googleapis.com/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(format!(
            "client_id={}&client_secret={}&grant_type=refresh_token&refresh_token={}",
            client_id, client_secret, refresh_token
        ));
    if response.is_ok() {
        let mut oauth_creds = response
            .expect("response is ok")
            .into_body()
            .read_json::<OAuthCreds>()?;
        oauth_creds.refresh_token = user.credentials.refresh_token.clone();
        let expires_in = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
            + oauth_creds.expires_in;
        oauth_creds.expires_in = expires_in;
        let mut user_db = app_data.db.lock().unwrap();
        let user_to_update = user_db
            .iter_mut()
            .find(|user_to_update| user_to_update.id == user.id)
            .expect("auth_guard was Ok");
        user_to_update
            .credentials
            .access_token
            .clone_from(&oauth_creds.access_token);
        user_to_update.credentials.expires_in = oauth_creds.expires_in;
        user_to_update
            .credentials
            .scope
            .clone_from(&oauth_creds.scope);
        user_to_update
            .credentials
            .token_type
            .clone_from(&oauth_creds.token_type);
        user_to_update.credentials.refresh_token = oauth_creds.refresh_token.clone();
        user_to_update.updatedAt = Utc::now();
        drop(user_db);
        app_data.save("secrets/");
        Ok(oauth_creds)
    } else {
        let message = "An error occurred while trying to refresh the access token";
        Err(From::from(message))
    }
}

pub fn revoke_token(app_data: &AppState, user: &User) -> Result<(), Box<ureq::Error>> {
    ureq::post("https://oauth2.googleapis.com/revoke")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(format!("token={}", user.credentials.access_token))?;
    let mut user_db = app_data.db.lock().unwrap();
    let user_to_update = user_db
        .iter_mut()
        .find(|user_to_update| user_to_update.id == user.id)
        .expect("auth_guard was Ok");
    user_to_update.credentials.expires_in = 0;
    user_to_update.credentials.refresh_token = None;
    user_to_update.credentials.id_token = None;
    user_to_update.updatedAt = Utc::now();
    drop(user_db);
    app_data.save("secrets/");
    log::info!("(handle_revoke) revoked access/refresh token");
    Ok(())
}

pub fn get_google_user(access_token: &str) -> Result<GoogleUserResult, Box<dyn Error>> {
    let response = ureq::get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", access_token).as_str())
        .call();

    if response.is_ok() {
        let user_info: GoogleUserResult = response?.into_body().read_json()?;
        Ok(user_info)
    } else {
        let message = "An error occurred while trying to retrieve user information.";
        Err(From::from(message))
    }
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
}

impl ValidUser {
    pub fn from_request(app_data: &AppState, request: &Request) -> AuthGuard<ValidUser> {
        let token = request
            .headers()
            .iter()
            .find(|header| header.field.equiv("Cookie"))
            .and_then(|h| {
                h.value
                    .as_str()
                    .split(';')
                    .find(|cookie| cookie.trim().starts_with("token="))
                    .map(|c| c.trim().trim_start_matches("token="))
            })
            .or_else(|| {
                request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("Authorization"))
                    .map(|c| c.value.as_str().trim_start_matches("Bearer "))
            });

        if token.is_none() {
            log::warn!("missing token, user not logged in");
            return Err(AuthError::MissingToken);
        }
        let token = token.expect("token is some");
        let env = app_data.env.lock().unwrap();
        let jwt_secret = env.jwt_secret.to_owned();
        drop(env);
        let decode = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_ref()),
            &Validation::new(Algorithm::HS256),
        );

        match decode {
            Ok(token) => {
                let user_opt = {
                    let user_db = app_data.db.lock().unwrap();
                    user_db
                        .iter()
                        .find(|user| user.id == token.claims.sub)
                        .cloned()
                };
                if user_opt.is_none() {
                    log::warn!("user belonging to this token no longer exists");
                    return Err(AuthError::InvalidToken);
                }
                let mut user = user_opt.expect("user is some");
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs();
                let needs_refresh = now_secs + 60 > user.credentials.expires_in;
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
                        log::warn!("(auth) token expiring but no refresh token available");
                    }
                }

                Ok(ValidUser { user })
            }
            Err(_) => {
                log::warn!("invalid token or user doesn't exist");
                Err(AuthError::InvalidToken)
            }
        }
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
            .expect("can't get jwks_uri as str");
        Ok(Self {
            client_id: client_id.to_owned(),
            key_provider: Arc::new(Mutex::new(GooglePublicKeyProvider::new(jwks_uri))),
        })
    }

    pub fn parse<T: DeserializeOwned>(&self, token: &str) -> Result<T, JWTParserError> {
        let mut provider = self.key_provider.lock().unwrap();
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
                            .and_then(|s| s.parse::<u64>().ok())
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
