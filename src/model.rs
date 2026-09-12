use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use crate::{config, google_oauth::OAuthCreds};

#[derive(Debug, Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Vec<User>>>,
    pub env: Arc<Mutex<config::Config>>,
}

impl AppState {
    pub fn init(config_dir: &str) -> AppState {
        // Only the user database is persisted on disk now; configuration is read
        // from the environment. `config_dir` locates `user_db.json`.
        let config_path = PathBuf::from(config_dir).join("user_db.json");
        let db = match File::open(config_path) {
            Ok(f) => {
                let reader = BufReader::new(f);
                serde_json::from_reader(reader).expect("couldn't deserialise db")
            }
            Err(e) => {
                log::warn!("couldn't open user_db file: {}", e);
                Vec::new()
            }
        };
        log::info!("appstate initialised");
        AppState {
            db: Arc::new(Mutex::new(db)),
            env: Arc::new(Mutex::new(config::Config::init())),
        }
    }

    pub fn save(&self, config_dir: &str) {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let config_path = PathBuf::from(config_dir).join("user_db.json");
        let file = File::create(config_path).expect("couldn't create user_db file");
        // Contains users' Google OAuth access and refresh tokens.
        config::restrict_permissions(&file);
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &db.clone()).expect("couldn't write user_db to file");
        drop(db);
        log::info!("user_db saved");
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub credentials: OAuthCreds,
    pub verified: bool,
    pub createdAt: DateTime<Utc>,
    pub updatedAt: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}
