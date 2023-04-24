use serde::{Deserialize, Serialize};
use std::{
    env,
    error::Error,
    fs::{remove_file, File},
    io::{BufReader, BufWriter},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::model::AppState;

#[derive(Deserialize, Serialize)]
pub struct Credentials {
    pub access_token: Option<String>,
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

    pub fn load() -> Self {
        let credentials = match File::open("secrets/token.json") {
            Ok(file) => {
                let reader = BufReader::new(file);
                ureq::serde_json::from_reader(reader).expect("Unable to parse JSON")
            }
            Err(_error) => Credentials::default(),
        };
        credentials
    }

    pub fn expired(&self) -> bool {
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

    pub fn retrieve_tokens(&self, code: &str) -> Result<Self, ureq::Error> {
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

    pub fn refresh_access_token(&self) -> Result<Self, ureq::Error> {
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

#[derive(Deserialize)]
pub struct OAuthResponse {
    pub access_token: String,
    pub id_token: String,
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
    authorization_code: &str,
    app_data: &AppState,
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

pub fn get_google_user(
    access_token: &str,
) -> Result<GoogleUserResult, Box<dyn Error>> {
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
