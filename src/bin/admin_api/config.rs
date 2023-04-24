use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub postgres_connection_string: String,
    pub google_photos_album_id: String,
    pub jwt_secret: String,
    pub jwt_expires_in: String,
    pub jwt_max_age: i64,
    pub google_oauth_client_id: String,
    pub google_oauth_client_secret: String,
    pub google_oauth_redirect_url: String,
}

impl Config {
    pub fn init() -> Config {
        let postgres_connection_string = env::var("POSTGRES_CONNECTION_STRING").expect("POSTGRES_CONNECTION_STRING must be set");
        let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let jwt_expires_in = env::var("TOKEN_EXPIRED_IN").expect("TOKEN_EXPIRED_IN must be set");
        let jwt_max_age = env::var("TOKEN_MAXAGE").expect("TOKEN_MAXAGE must be set");
        let google_photos_album_id =
        env::var("GOOGLE_PHOTOS_ALBUM_ID").expect("GOOGLE_PHOTOS_ALBUM_ID must be set");
        let google_oauth_client_id =
            env::var("GOOGLE_OAUTH_CLIENT_ID").expect("GOOGLE_OAUTH_CLIENT_ID must be set");
        let google_oauth_client_secret =
            env::var("GOOGLE_OAUTH_CLIENT_SECRET").expect("GOOGLE_OAUTH_CLIENT_SECRET must be set");
        let google_oauth_redirect_url =
            env::var("GOOGLE_OAUTH_REDIRECT_URI").expect("GOOGLE_OAUTH_REDIRECT_URI must be set");

        Config {
            postgres_connection_string,
            google_photos_album_id,
            jwt_secret,
            jwt_expires_in,
            jwt_max_age: jwt_max_age.parse::<i64>().unwrap_or(60),
            google_oauth_client_id,
            google_oauth_client_secret,
            google_oauth_redirect_url,
        }
    }
}
