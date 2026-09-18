use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Write},
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
        let db = match File::open(&config_path) {
            Ok(f) => {
                let reader = BufReader::new(f);
                // Fail closed: a corrupt user database must not silently become an
                // empty one (which would drop every known account).
                serde_json::from_reader(reader).unwrap_or_else(|e| {
                    log::error!("could not parse {}: {e}", config_path.display());
                    std::process::exit(1);
                })
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

    /// Persist the user database. Failures are logged rather than propagated:
    /// the in-memory state is still authoritative for this process and a
    /// request handler must not panic because the disk is briefly unavailable.
    pub fn save(&self, config_dir: &str) {
        if let Err(e) = self.try_save(config_dir) {
            log::error!("could not persist user_db: {e}");
        } else {
            log::info!("user_db saved");
        }
    }

    /// Write atomically: serialise to a private temp file in the same directory,
    /// fsync it, then rename over the live file. A crash mid-write can therefore
    /// never leave a truncated `user_db.json` that would stop the next start.
    /// The db lock is held throughout so concurrent saves are serialised.
    fn try_save(&self, config_dir: &str) -> std::io::Result<()> {
        let db = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let dir = PathBuf::from(config_dir);
        let final_path = dir.join("user_db.json");
        let tmp_path = dir.join(".user_db.json.tmp");
        // Contains users' Google OAuth access and refresh tokens: owner-only mode.
        let file = config::create_private_file(&tmp_path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &*db).map_err(std::io::Error::other)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        drop(writer);
        std::fs::rename(&tmp_path, &final_path)?;
        Ok(())
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

/// Claims carried by the app's own HS256 session token.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
    /// Unique token id, used to revoke this specific token on logout.
    pub jti: String,
}
