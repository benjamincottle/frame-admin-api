#![allow(non_snake_case)]
use image::DynamicImage;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, env, io::Read};

#[derive(Deserialize, Serialize, Eq, Hash, PartialEq, Debug, Clone)]
pub struct MediaItem {
    pub id: String,
    pub productUrl: String,
    baseUrl: String,
    filename: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SearchResult {
    mediaItems: Vec<MediaItem>,
    nextPageToken: Option<String>,
}

pub fn get_mediaitems(access_token: &str) -> Result<HashSet<MediaItem>, ureq::Error> {
    let mut media_item_list: HashSet<MediaItem> = HashSet::new();
    let mut page_token = "".to_string();
    loop {
        let body = ureq::json!({
            "albumId": &env::var("GOOGLE_PHOTOS_ALBUM_ID").expect("This should never fail"),
            "pageToken": page_token,
            "pageSize": 100,
        });
        let response: SearchResult =
            ureq::post("https://photoslibrary.googleapis.com/v1/mediaItems:search")
                .set("Authorization", format!("Bearer {}", access_token).as_str())
                .set("Content-Type", "Content-type: application/json")
                .send_json(&body)?
                .into_json()?;

        for media_item in response.mediaItems {
            media_item_list.insert(media_item);
        }
        match response.nextPageToken.is_some() {
            true => page_token = response.nextPageToken.expect("This should never fail"),
            false => break,
        }
    }
    Ok(media_item_list)
}

pub fn get_photo(media_item: &MediaItem) -> Result<DynamicImage, Box<dyn std::error::Error>> {
    let path = format!("{}=w600-h448-d", media_item.baseUrl);
    let resp = ureq::get(&path).call()?;
    let dimage = match resp
        .header("Content-Length")
        .and_then(|s| s.parse::<usize>().ok())
        .and_then(|d| {
            let mut buf: Vec<u8> = Vec::with_capacity(d);
            resp.into_reader()
                .take(10_000_000)
                .read_to_end(&mut buf)
                .ok();
            Some(buf)
        })
        .and_then(|buf| image::load_from_memory(buf.as_slice()).ok())
    {
        Some(dimage) => dimage,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "(get_photo) Failed to dowload image",
            )
            .into())
        }
    };
    Ok(dimage)
}
