use serde::{Deserialize, Serialize};
use std::{fs::File, io::BufReader, path::PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub postgres_connection_string: String,
    pub google_photos_album_id: String,
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
                let config = ureq::serde_json::from_reader(reader).unwrap();
                log::info!("config initialised");
                config
            }
            Err(e) => {
                log::warn!("couldn't open config file: {} empty config initialised", e);
                Config {
                    postgres_connection_string: String::new(),
                    google_photos_album_id: String::new(),
                    jwt_secret: String::new(),
                    jwt_max_age: 3600,
                    google_oauth_client_id: String::new(),
                    google_oauth_client_secret: String::new(),
                    google_oauth_redirect_url: String::new(),
                }
            }
        }
    }

    pub fn save(&self, config_dir: &str) {
        let config_path = PathBuf::from(config_dir).join("config.json");
        let config_file = std::fs::File::create(config_path).expect("couldn't create config file");
        let writer = std::io::BufWriter::new(config_file);
        ureq::serde_json::to_writer_pretty(writer, &self.clone())
            .expect("couldn't write config to file");
        log::info!("config saved");
    }
}
