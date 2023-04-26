use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::{config, google_oauth::OAuthResponse};

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub credentials: OAuthResponse,
    pub photo: String,
    pub verified: bool,
    pub createdAt: DateTime<Utc>,
    pub updatedAt: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Vec<User>>>,
    pub env: config::Config,
}

impl AppState {
    pub fn init() -> AppState {
        AppState {
            db: Arc::new(Mutex::new(Vec::new())),
            env: config::Config::init(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Deserialize)]
struct QueryCode {
    code: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct RegisterUserSchema {
    name: String,
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct LoginUserSchema {
    email: String,
    password: String,
}
