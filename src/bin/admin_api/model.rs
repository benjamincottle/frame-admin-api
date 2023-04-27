use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufReader, BufWriter},
    sync::{Arc, Mutex},
};

use crate::{config, google_oauth::OAuthCreds};

#[derive(Debug, Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Vec<User>>>,
    pub env: config::Config,
}

impl AppState {
    pub fn init(filename: &str) -> AppState {
        match File::open(filename) {
            Ok(f) => {
                let reader = BufReader::new(f);
                let db = ureq::serde_json::from_reader(reader).unwrap();
                AppState {
                    db: Arc::new(Mutex::new(db)),
                    env: config::Config::init(),
                }
            }
            Err(e) => {
                log::info!("couldn't open user_db file: {}", e);
                AppState {
                    db: Arc::new(Mutex::new(Vec::new())),
                    env: config::Config::init(),
                }
            }
        }
    }

    pub fn save(&self, filename: &str) {
        let db = self.db.lock().unwrap();
        let file = File::create(filename).expect("couldn't create user_db file");
        let writer = BufWriter::new(file);
        ureq::serde_json::to_writer_pretty(writer, &db.clone())
            .expect("couldn't write user_db to file");
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
