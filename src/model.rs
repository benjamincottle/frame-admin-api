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
        let config_path = PathBuf::from(config_dir).join("user_db.json");
        match File::open(config_path) {
            Ok(f) => {
                let reader = BufReader::new(f);
                let db = serde_json::from_reader(reader).expect("couldn't deserialise db");
                log::info!("appstate initialised");
                AppState {
                    db: Arc::new(Mutex::new(db)),
                    env: Arc::new(Mutex::new(config::Config::init(config_dir))),
                }
            }
            Err(e) => {
                log::warn!("couldn't open user_db file: {}", e);
                AppState {
                    db: Arc::new(Mutex::new(Vec::new())),
                    env: Arc::new(Mutex::new(config::Config::init(config_dir))),
                }
            }
        }
    }

    pub fn save(&self, config_dir: &str) {
        let db = self.db.lock().unwrap();
        let config_path = PathBuf::from(config_dir).join("user_db.json");
        let file = File::create(config_path).expect("couldn't create user_db file");
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &db.clone()).expect("couldn't write user_db to file");
        drop(db);
        let env = self.env.lock().unwrap();
        env.save(config_dir);
        drop(env);
        log::info!("appstate saved");
    }
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub credentials: OAuthCreds,
    pub photo: String,
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
