use rand::{Rng, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{env, fs::File, io::BufReader, path::PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub postgres_connection_string: String,
    // pub google_photos_album_ids: Vec<String>,
    pub jwt_secret: String,
    pub jwt_max_age: i64,
    pub google_oauth_client_id: String,
    pub google_oauth_client_secret: String,
    pub google_oauth_redirect_url: String,
}

impl Config {
    pub fn init(config_dir: &str) -> Config {
        let config_path = PathBuf::from(config_dir).join("config.json");
        match File::open(config_path) {
            Ok(f) => {
                let reader = BufReader::new(f);
                let config = serde_json::from_reader(reader).expect("couldn't deserialise config");
                log::info!("config initialised");
                config
            }
            Err(e) => {
                log::warn!("couldn't open config file: {} empty config initialised", e);
                Config {
                    postgres_connection_string: env::var("POSTGRES_CONNECTION_STRING")
                        .expect("POSTGRES_CONNECTION_STRING not set"),
                    // google_photos_album_ids: vec![],
                    jwt_secret: generate_secret(),
                    jwt_max_age: env::var("TOKEN_MAXAGE")
                        .expect("TOKEN_MAXAGE not set")
                        .parse()
                        .expect("TOKEN_MAXAGE not a number"),
                    google_oauth_client_id: env::var("GOOGLE_OAUTH_CLIENT_ID")
                        .expect("GOOGLE_OAUTH_CLIENT_ID not set"),
                    google_oauth_client_secret: env::var("GOOGLE_OAUTH_CLIENT_SECRET")
                        .expect("GOOGLE_OAUTH_CLIENT_SECRET not set"),
                    google_oauth_redirect_url: env::var("GOOGLE_OAUTH_REDIRECT_URI")
                        .expect("GOOGLE_OAUTH_REDIRECT_URI not set"),
                }
            }
        }
    }

    pub fn save(&self, config_dir: &str) {
        let config_path = PathBuf::from(config_dir).join("config.json");
        let config_file = std::fs::File::create(config_path).expect("couldn't create config file");
        let writer = std::io::BufWriter::new(config_file);
        serde_json::to_writer_pretty(writer, &self.clone()).expect("couldn't write config to file");
        log::info!("config saved");
    }
}

pub fn generate_secret() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .map(char::from)
        .filter(|&c| c.is_ascii_lowercase() || c.is_ascii_uppercase() || c.is_ascii_digit())
        .take(64)
        .collect::<String>()
}
