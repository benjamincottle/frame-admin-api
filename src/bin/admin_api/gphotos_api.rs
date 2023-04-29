#![allow(non_snake_case)]
use image::DynamicImage;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, io::Read};

#[derive(Deserialize, Serialize, Eq, Hash, PartialEq, Debug, Clone)]
pub struct MediaItem {
    pub id: String,
    pub productUrl: String,
    baseUrl: String,
    filename: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SearchResult<T> {
    #[serde(alias = "albums", alias = "mediaItems")]
    result: Vec<T>,
    nextPageToken: Option<String>,
}

pub fn get_mediaitems(
    access_token: &str,
    album_id: &str,
) -> Result<HashSet<MediaItem>, ureq::Error> {
    let mut media_item_list: HashSet<MediaItem> = HashSet::new();
    let mut page_token = "".to_string();
    loop {
        let body = ureq::json!({
            "albumId": album_id,
            "pageToken": page_token,
            "pageSize": 100,
        });
        let response: SearchResult<MediaItem> =
            ureq::post("https://photoslibrary.googleapis.com/v1/mediaItems:search")
                .set("Authorization", format!("Bearer {}", access_token).as_str())
                .set("Content-Type", "Content-type: application/json")
                .send_json(&body)?
                .into_json()?;

        for media_item in response.result {
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

#[derive(Debug, Deserialize, Serialize)]
pub struct PhotoAlbum {
    id: String,
    title: String,
    productUrl: String,
    coverPhotoBaseUrl: String,
    coverPhotoMediaItemId: String,
    mediaItemsCount: String
}

pub fn get_album_list(access_token: &str) -> Result<Vec<PhotoAlbum>, ureq::Error> {
    let mut album_list = Vec::new();
    let mut page_token = "".to_string();
    loop {
        let response: SearchResult<PhotoAlbum> =
            ureq::get("https://photoslibrary.googleapis.com/v1/albums")
                .set("Authorization", format!("Bearer {}", access_token).as_str())
                .set("Content-Type", "Content-type: application/json")
                .query_pairs(vec![
                    ("pageToken", page_token.as_str()),
                    ("pageSize", "50"),
                ])
                .call()?
                .into_json()?;
        for album in response.result {
            album_list.push(album);
        }
        match response.nextPageToken.is_some() {
            true => page_token = response.nextPageToken.expect("This should never fail"),
            false => break,
        }
    }
    Ok(album_list)
}
