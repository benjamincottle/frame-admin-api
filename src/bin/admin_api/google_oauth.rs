use chrono::Duration;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    error::Error,
    fs::{remove_file, File},
    io::{BufReader, BufWriter},
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tiny_http::Request;

use crate::model::{AppState, TokenClaims};

#[derive(Deserialize, Serialize)]
struct Credentials {
    access_token: Option<String>,
    expires_in: Option<u64>,
    id_token: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
    token_type: Option<String>,
}

impl Default for Credentials {
    fn default() -> Self {
        Credentials {
            access_token: None,
            expires_in: None,
            id_token: None,
            refresh_token: None,
            scope: None,
            token_type: None,
        }
    }
}

// TODO create custom error enum for token errors
impl Credentials {
    fn save(&self) -> std::io::Result<()> {
        let file = File::create("secrets/token.json")?;
        let writer = BufWriter::new(file);
        ureq::serde_json::to_writer(writer, self)?;
        Ok(())
    }

    fn load() -> Self {
        let credentials = match File::open("secrets/token.json") {
            Ok(file) => {
                let reader = BufReader::new(file);
                ureq::serde_json::from_reader(reader).expect("Unable to parse JSON")
            }
            Err(_error) => Credentials::default(),
        };
        credentials
    }

    fn expired(&self) -> bool {
        match self.expires_in {
            Some(expires_in) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs();
                now > expires_in
            }
            None => true,
        }
    }

    fn retrieve_tokens(&self, code: &str) -> Result<Self, ureq::Error> {
        let response = ureq::post("https://oauth2.googleapis.com/token")
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&format!(
            "client_id={}&client_secret={}&code={}&grant_type=authorization_code&redirect_uri={}",
            &env::var("GOOGLE_OAUTH_CLIENT_ID").expect("This should never fail"),
            &env::var("GOOGLE_OAUTH_CLIENT_SECRET").expect("This should never fail"),
            code,
            &env::var("GOOGLE_OAUTH_REDIRECT_URI").expect("This should never fail")
        ))?;
        let new_credentials: Credentials = response.into_json()?;
        let refresh_token = match new_credentials.refresh_token {
            Some(refresh_token) => Some(refresh_token),
            None => self.refresh_token.clone(),
        };
        let expires_in = match new_credentials.expires_in {
            Some(expires_in) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs();
                Some(now + expires_in)
            }
            None => None,
        };
        let credentials = Credentials {
            access_token: new_credentials.access_token,
            expires_in,
            id_token: new_credentials.id_token,
            refresh_token,
            scope: new_credentials.scope,
            token_type: new_credentials.token_type,
        };
        credentials.save()?;
        Ok(credentials)
    }

    fn refresh_access_token(&self) -> Result<Self, ureq::Error> {
        let refresh_token = self
            .refresh_token
            .clone()
            .expect("current_credentials should contain a refresh_token");
        let response = ureq::post("https://oauth2.googleapis.com/token")
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&format!(
                "client_id={}&client_secret={}&grant_type=refresh_token&refresh_token={}",
                &env::var("GOOGLE_OAUTH_CLIENT_ID").expect("This should never fail"),
                &env::var("GOOGLE_OAUTH_CLIENT_SECRET").expect("This should never fail"),
                refresh_token
            ))?;
        let new_credentials: Credentials = response.into_json()?;
        let expires_in = match new_credentials.expires_in {
            Some(expires_in) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs();
                Some(now + expires_in)
            }
            None => None,
        };
        let credentials = Credentials {
            access_token: new_credentials.access_token,
            expires_in,
            id_token: new_credentials.id_token,
            refresh_token: Some(refresh_token),
            scope: new_credentials.scope,
            token_type: new_credentials.token_type,
        };
        credentials.save()?;
        Ok(credentials)
    }

    pub fn revoke(&self) -> Result<(), ureq::Error> {
        let access_token = self
            .access_token
            .clone()
            .expect("current_credentials should contain an access_token");
        ureq::post("https://oauth2.googleapis.com/revoke")
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&format!("token={}", access_token))?;
        remove_file("token.json")?;
        Ok(())
    }
}

#[derive(Deserialize, Debug, Clone, Serialize)]
pub struct OAuthResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub id_token: Option<String>,
    pub scope: String,
    pub token_type: String,
    pub refresh_token: Option<String>,
}

#[derive(Deserialize)]
pub struct GoogleUserResult {
    pub id: String,
    pub email: String,
    pub verified_email: bool,
    pub name: String,
    pub given_name: String,
    pub family_name: String,
    pub picture: String,
    pub locale: String,
}

pub fn request_token(
    app_data: &AppState,
    authorization_code: &str,
) -> Result<OAuthResponse, Box<dyn Error>> {
    let redirect_url = app_data.env.google_oauth_redirect_url.to_owned();
    let client_secret = app_data.env.google_oauth_client_secret.to_owned();
    let client_id = app_data.env.google_oauth_client_id.to_owned();
    let response = ureq::post("https://oauth2.googleapis.com/token")
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&format!(
            "client_id={}&client_secret={}&code={}&grant_type=authorization_code&redirect_uri={}",
            client_id, client_secret, authorization_code, redirect_url
        ));
    if response.is_ok() {
        let oauth_response = response.unwrap().into_json::<OAuthResponse>()?;
        Ok(oauth_response)
    } else {
        let message = "An error occurred while trying to retrieve the access token";
        Err(From::from(message))
    }
}

pub fn refresh_token(
    app_data: &AppState,
    refresh_token: &str,
) -> Result<OAuthResponse, Box<dyn Error>> {
    let client_secret = app_data.env.google_oauth_client_secret.to_owned();
    let client_id = app_data.env.google_oauth_client_id.to_owned();
    let response = ureq::post("https://oauth2.googleapis.com/token")
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&format!(
            "client_id={}&client_secret={}&grant_type=refresh_token&refresh_token={}",
            client_id, client_secret, refresh_token
        ));
    if response.is_ok() {
        let oauth_response = response.unwrap().into_json::<OAuthResponse>()?;
        Ok(oauth_response)
    } else {
        let message = "An error occurred while trying to refresh the access token";
        Err(From::from(message))
    }
}

pub fn revoke_token(access_token: &str) -> Result<(), ureq::Error> {
    ureq::post("https://oauth2.googleapis.com/revoke")
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&format!("token={}", access_token))?;
    Ok(())
}

pub fn get_google_user(access_token: &str) -> Result<GoogleUserResult, Box<dyn Error>> {
    let response = ureq::get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json")
        .set("Content-Type", "application/json")
        .set("Authorization", format!("Bearer {}", access_token).as_str())
        .call();

    if response.is_ok() {
        let user_info: GoogleUserResult = response?.into_json()?;
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
    pub user_id: String,
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
                    .and_then(|c| Some(c.trim().trim_start_matches("token=")))
            })
            .or_else(|| {
                request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("Authorization"))
                    .and_then(|c| {
                        let t = c.value.as_str().trim_start_matches("Bearer ");
                        Some(t)
                    })
            });
        if token.is_none() {
            log::warn!("Missing token, user not logged in");
            return Err(AuthError::MissingToken);
        }
        let token = token.unwrap();
        let jwt_secret = app_data.env.jwt_secret.to_owned();
        let decode = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_ref()),
            &Validation::new(Algorithm::HS256),
        );

        match decode {
            Ok(token) => {
                let vec = app_data.db.lock().unwrap();
                let user = vec
                    .iter()
                    .find(|user| user.id == token.claims.sub.to_owned());

                if user.is_none() {
                    log::warn!("User belonging to this token no longer exists");
                    return Err(AuthError::InvalidToken);
                }

                Ok(ValidUser {
                    user_id: token.claims.sub,
                })
            }
            Err(_) => {
                log::warn!("Invalid token or user doesn't exist");
                return Err(AuthError::InvalidToken);
            }
        }
    }
}

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
pub enum ParserError {
    WrongHeader,
    UnknownKid,
    KeyProvider(GoogleKeyProviderError),
    WrongToken(jsonwebtoken::errors::Error),
}

pub struct Parser {
    client_id: String,
    key_provider: Arc<Mutex<GooglePublicKeyProvider>>,
}

impl Parser {
    pub fn new(client_id: &str) -> Result<Self, Box<dyn Error>> {
        let oidc_config_url = "https://accounts.google.com/.well-known/openid-configuration";
        let oidc_config_resp = ureq::get(oidc_config_url).call()?;
        let oidc_config: ureq::serde_json::Value = oidc_config_resp.into_json()?;
        let jwks_uri = oidc_config["jwks_uri"].as_str().unwrap();
        Ok(Parser::new_with_custom_cert_url(client_id, jwks_uri))
    }

    pub fn new_with_custom_cert_url(client_id: &str, public_key_url: &str) -> Self {
        Self {
            client_id: client_id.to_owned(),
            key_provider: Arc::new(Mutex::new(GooglePublicKeyProvider::new(public_key_url))),
        }
    }

    pub fn parse<T: DeserializeOwned>(&self, token: &str) -> Result<T, ParserError> {
        let mut provider = self.key_provider.lock().unwrap();
        match jsonwebtoken::decode_header(token) {
            Ok(header) => match header.kid {
                None => Result::Err(ParserError::UnknownKid),
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
                            Result::Err(error) => Result::Err(ParserError::WrongToken(error)),
                        }
                    }
                    Err(e) => {
                        let error = ParserError::KeyProvider(e);
                        Result::Err(error)
                    }
                },
            },
            Err(_) => Result::Err(ParserError::WrongHeader),
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
                let expiration_time = r.header("cache-control").and_then(|v| {
                    v.split(",")
                        .find(|s| s.contains("max-age"))
                        .and_then(|s| s.split("=").nth(1))
                        .and_then(|s| s.parse::<u64>().ok())
                        .map(|s| Instant::now() + std::time::Duration::from_secs(s))
                });
                match r.into_json::<GoogleKeys>() {
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
        match self.keys.get(&kid.to_owned()) {
            None => Result::Err(GoogleKeyProviderError::KeyNotFound(
                "couldn't match kid".to_string(),
            )),
            Some(key) => DecodingKey::from_rsa_components(key.n.as_str(), key.e.as_str())
                .map_err(|e| GoogleKeyProviderError::CreateKeyError(e.to_string())),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityTokenClaims {
    pub email: String,
    pub aud: String,
    pub iss: String,
    pub exp: u64,
    pub iat: u64,
    pub sub: String,
}
