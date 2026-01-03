#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
use core::str;
use image::DynamicImage;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashSet, io::Read};

#[derive(Debug, Deserialize, Serialize)]
pub struct PhotoAlbum {
    id: String,
    title: String,
    coverPhotoBaseUrl: String,
    mediaItemsCount: String,
}

#[derive(Deserialize, Serialize, Eq, Hash, PartialEq, Debug, Clone)]
pub struct MediaMetadata {
    pub width: String,
    pub height: String,
}

#[derive(Deserialize, Serialize, Eq, Hash, PartialEq, Debug, Clone)]
pub struct MediaItem {
    pub id: String,
    pub productUrl: String,
    pub baseUrl: String,
    pub mimeType: String,
    pub mediaMetadata: MediaMetadata,
    pub filename: String,
}

// New VV

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum VideoProcessingStatus {
    UNSPECIFIED,
    PROCESSING,
    READY,
    FAILED,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct VideoMetadata {
    pub fps: Option<f64>,
    pub processingStatus: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PhotoMetadata {
    pub focalLength: Option<f64>,
    pub apertureFNumber: Option<f64>,
    pub isoEquivalent: Option<i32>,
    pub exposureTime: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct MediaFileMetadata {
    pub width: i32,
    pub height: i32,
    pub cameraMake: Option<String>,
    pub cameraModel: Option<String>,
    pub photoMetadata: Option<PhotoMetadata>,
    pub videoMetadata: Option<VideoMetadata>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct MediaFile {
    pub baseUrl: String,
    pub mimeType: String,
    pub filename: String,
    pub mediaFileMetadata: MediaFileMetadata,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum Type {
    TYPE_UNSPECIFIED,
    PHOTO,
    VIDEO,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PickedMediaItem {
    pub id: String,
    pub createTime: String,
    #[serde(rename = "type")]
    pub type_: Type,
    pub mediaFile: MediaFile,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SearchResult<T> {
    #[serde(alias = "albums", alias = "mediaItems")]
    result: Vec<T>,
    nextPageToken: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PickedMediaItemList {
    mediaItems: Vec<PickedMediaItem>,
    nextPageToken: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PollingConfig {
    pub pollInterval: String,
    pub timeoutIn: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PickingConfig {
    pub maxItemCount: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PickingSession {
    pub id: String,
    pub pickerUri: Option<String>,
    pub pollingConfig: Option<PollingConfig>,
    pub expireTime: String,
    pub pickingConfig: Option<PickingConfig>,
    pub mediaItemsSet: bool,
}

impl PickingSession {
    pub fn create(access_token: &str) -> Result<PickingSession, Box<dyn std::error::Error>> {
        let response = ureq::post("https://photospicker.googleapis.com/v1/sessions")
            .header("Authorization", format!("Bearer {}", access_token).as_str())
            .header("Content-Type", "application/json")
            .send_json(&json!({}))?;
        Ok(response.into_body().read_json()?)
    }

    pub fn poll(
        access_token: &str,
        session_id: &str,
    ) -> Result<PickingSession, Box<dyn std::error::Error>> {
        let response = ureq::get(
            format!(
                "https://photospicker.googleapis.com/v1/sessions/{}",
                session_id
            )
            .as_str(),
        )
        .header("Authorization", format!("Bearer {}", access_token).as_str())
        .header("Content-Type", "application/json")
        .call()?;
        Ok(response.into_body().read_json()?)
    }

    pub fn list_picked(
        access_token: &str,
        session_id: &str,
    ) -> Result<Vec<PickedMediaItem>, Box<dyn std::error::Error>> {
        let mut picked_media_items: Vec<PickedMediaItem> = Vec::new();
        let mut page_token = "".to_string();
        loop {
            let mut query = vec![("sessionId", session_id)];
            if !page_token.is_empty() {
                query.push(("pageToken", page_token.as_str()));
            }
            let response: PickedMediaItemList =
                ureq::get("https://photospicker.googleapis.com/v1/mediaItems")
                    .header("Authorization", format!("Bearer {}", access_token).as_str())
                    .header("Content-Type", "application/json")
                    .query_pairs(query)
                    .call()?
                    .into_body()
                    .read_json()?;
            for picked_media_item in response.mediaItems {
                match picked_media_item.type_ {
                    Type::PHOTO => {
                        picked_media_items.push(picked_media_item);
                    }
                    _ => continue,
                }
            }
            match response.nextPageToken {
                Some(token) => page_token = token,
                _ => break,
            }
        }
        Ok(picked_media_items)
    }

    pub fn delete(
        access_token: &str,
        session_id: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let response = ureq::delete(
            format!(
                "https://photospicker.googleapis.com/v1/sessions/{}",
                session_id
            )
            .as_str(),
        )
        .header("Authorization", format!("Bearer {}", access_token).as_str())
        .header("Content-Type", "application/json")
        .call()?;
        Ok(response.into_body().read_json()?)
    }
}

// pub fn get_mediaitems(
//     access_token: &str,
//     album_id: &str,
// ) -> Result<HashSet<MediaItem>, Box<dyn std::error::Error>> {
//     let mut media_item_list: HashSet<MediaItem> = HashSet::new();
//     let mut page_token = "".to_string();
//     loop {
//         let body = json!({
//             "albumId": album_id,
//             "pageToken": page_token,
//             "pageSize": 100,
//         });
//         let response: SearchResult<MediaItem> =
//             ureq::post("https://photoslibrary.googleapis.com/v1/mediaItems:search")
//                 .header("Authorization", format!("Bearer {}", access_token).as_str())
//                 .header("Content-Type", "application/json")
//                 .send_json(&body)?
//                 .into_body()
//                 .read_json()?;
//         for media_item in response.result {
//             match media_item.mimeType.as_str() {
//                 "image/jpeg" | "image/png" | "image/bmp" | "image/gif" => {
//                     media_item_list.insert(media_item);
//                 }
//                 _ => continue,
//             }
//         }
//         match response.nextPageToken.is_some() {
//             true => page_token = response.nextPageToken.expect("This should never fail"),
//             false => break,
//         }
//     }
//     Ok(media_item_list)
// }

fn build_download_path(base_url: &str, width: i64, height: i64) -> String {
    if width > height {
        format!("{base_url}=w600-h448-d")
    } else {
        format!("{base_url}=w300-h448-d")
    }
}

fn download_image(
    path: &str,
    access_token: Option<&str>,
) -> Result<DynamicImage, Box<dyn std::error::Error>> {
    let mut request = ureq::get(path);
    if let Some(token) = access_token {
        request = request.header("Authorization", format!("Bearer {}", token).as_str());
    }
    let mut response = request.call()?;

    let dimage = match response
        .headers()
        .get("Content-Length")
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .map(|d| {
            let mut buf: Vec<u8> = Vec::with_capacity(d);
            response
                .body_mut()
                .as_reader()
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
            .into());
        }
    };
    Ok(dimage)
}

pub fn get_photo(
    media_item: &MediaItem,
    access_token: Option<&str>,
) -> Result<DynamicImage, Box<dyn std::error::Error>> {
    let width = media_item.mediaMetadata.width.parse::<i64>()?;
    let height = media_item.mediaMetadata.height.parse::<i64>()?;
    let path = build_download_path(&media_item.baseUrl, width, height);
    download_image(&path, access_token)
}

pub fn get_photo_from_baseurl(
    base_url: &str,
    width: i64,
    height: i64,
    access_token: Option<&str>,
) -> Result<DynamicImage, Box<dyn std::error::Error>> {
    let path = build_download_path(base_url, width, height);
    download_image(&path, access_token)
}

// pub fn get_album_list(access_token: &str) -> Result<Vec<PhotoAlbum>, Box<dyn std::error::Error>> {
//     let mut album_list = Vec::new();
//     let mut page_token = "".to_string();
//     loop {
//         let response: SearchResult<PhotoAlbum> =
//             ureq::get("https://photoslibrary.googleapis.com/v1/albums")
//                 .header("Authorization", format!("Bearer {}", access_token).as_str())
//                 .header("Content-Type", "application/json")
//                 .query_pairs(vec![("pageToken", page_token.as_str())])
//                 .call()?
//                 .into_body()
//                 .read_json()?;
//         for album in response.result {
//             album_list.push(album);
//         }
//         match response.nextPageToken.is_some() {
//             true => page_token = response.nextPageToken.expect("This should never fail"),
//             false => break,
//         }
//     }
//     Ok(album_list)
// }
