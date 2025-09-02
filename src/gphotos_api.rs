#![allow(non_snake_case)]
use image::DynamicImage;
use serde::{Deserialize, Serialize};
use core::str;
use std::{collections::HashSet, io::Read};

#[derive(Deserialize, Serialize, Eq, Hash, PartialEq, Debug, Clone)]
pub struct MediaMetadata {
    pub width: String,
    pub height: String,
}

#[derive(Deserialize, Serialize, Eq, Hash, PartialEq, Debug, Clone)]
pub struct MediaItem {
    pub id: String,
    pub productUrl: String,
    baseUrl: String,
    mimeType: String,
    pub mediaMetadata: MediaMetadata,
    filename: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SearchResult<T> {
    #[serde(alias = "albums", alias = "mediaItems")]
    result: Vec<T>,
    nextPageToken: Option<String>,
}

pub struct PollingConfig {
    pub pollInterval: String,
    pub timeoutIn: String,
}

pub struct PickingConfig {
    pub maxItemCount: String,
}

pub struct PickingSession {
    pub id: String,
    pub pickerUri: String,
    pub pollingConfig: PollingConfig,
    pub expireTime: String,
    pub pickingConfig: PickingConfig,
    pub mediaItemsSet: bool,
}

pub fn get_mediaitems(
    access_token: &str,
    album_id: &str,
) -> Result<HashSet<MediaItem>, Box<dyn std::error::Error>> {
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
            match media_item.mimeType.as_str() {
                "image/jpeg" | "image/png" | "image/bmp" | "image/gif" => {
                    media_item_list.insert(media_item);
                }
                _ => continue,
            }
        }
        match response.nextPageToken.is_some() {
            true => page_token = response.nextPageToken.expect("This should never fail"),
            false => break,
        }
    }
    Ok(media_item_list)
}

pub fn get_photo(media_item: &MediaItem) -> Result<DynamicImage, Box<dyn std::error::Error>> {
    let path = match media_item.mediaMetadata.width.parse::<i64>()?
        > media_item.mediaMetadata.height.parse::<i64>()?
    {
        true => format!("{}=w600-h448-d", media_item.baseUrl),
        false => format!("{}=w300-h448-d", media_item.baseUrl),
    };
    let response = ureq::get(&path).call()?;

    let dimage = match response
        .header("Content-Length")
        .and_then(|s| s.parse::<usize>().ok())
        .map(|d| {
            let mut buf: Vec<u8> = Vec::with_capacity(d);
            response
                .into_reader()
                .take(10_000_000)
                .read_to_end(&mut buf)
                .ok();
            buf
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
    coverPhotoBaseUrl: String,
    mediaItemsCount: String,
}

pub fn get_album_list(access_token: &str) -> Result<Vec<PhotoAlbum>, Box<dyn std::error::Error>> {
    let mut album_list = Vec::new();
    let mut page_token = "".to_string();
    loop {
        let response: SearchResult<PhotoAlbum> =
            ureq::get("https://photoslibrary.googleapis.com/v1/albums")
                .set("Authorization", format!("Bearer {}", access_token).as_str())
                .set("Content-Type", "Content-type: application/json")
                .query_pairs(vec![("pageToken", page_token.as_str())])
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
