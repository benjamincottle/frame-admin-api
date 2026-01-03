use chrono::{Duration, Utc};
use serde::{de, Deserialize, Serialize};
use serde_json;

use crate::{
    database::CONNECTION_POOL,
    google_oauth::{refresh_token, request_token, revoke_token, AuthGuard, ValidUser},
    gphotos_api::{
        get_album_list, get_mediaitems, get_photo, MediaItem, MediaMetadata, PickedMediaItem,
        PickingSession,
    },
    image_proc::{decode_image, encode_image},
    model::{AppState, TokenClaims},
    session_mgr::{SessionID, SESSION_MGR},
    task_mgr::{Action, Status, Task, TaskData, TaskQueue, TASK_BOARD},
    template_mgr::TEMPLATES,
};

use image::imageops::FilterType;
use jsonwebtoken::{encode, EncodingKey, Header as JWTHeader};
use route_recognizer::{Params, Router};
use std::{
    cmp::min,
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tera::Context;
use tiny_http::{Header, Request, Response};
use url::Url;

#[derive(Debug, Serialize, Deserialize)]
struct TelemetryRecord {
    ts: i64,
    item_id: Option<String>,
    item_id_2: Option<String>,
    bat_voltage: i32,
    boot_code: i32,
    remote_addr: Vec<IpAddr>,
}

pub fn route_request(app_data: AppState, request: Request) {
    let url = match Url::parse("http://localhost:5000")
        .expect("This should never fail")
        .join(request.url())
    {
        Ok(url) => url,
        Err(e) => {
            log::error!("(route_request) could not parse url: {}", e);
            serve_error(
                request,
                tiny_http::StatusCode(500),
                "Internal server error: could not parse url",
            );
            return;
        }
    };
    let url = url.path().trim_end_matches('/');
    let mut router = Router::new();
    router.add("/frame_admin", "index".to_string());
    router.add("/frame_admin/oauth/login", "oauth_login".to_string());
    router.add("/frame_admin/oauth/logout", "oauth_logout".to_string());
    router.add(
        "/frame_admin/oauth/authorise",
        "oauth_authorise".to_string(),
    );
    router.add("/frame_admin/oauth/google", "oauth_google".to_string());
    router.add("/frame_admin/oauth/revoke", "oauth_revoke".to_string());
    // router.add("/frame_admin/config", "config".to_string());
    // router.add("/frame_admin/sync", "sync".to_string());
    router.add("/frame_admin/sync_progress", "sync_progress".to_string());
    router.add("/frame_admin/monitor", "monitor".to_string());
    router.add("/frame_admin/album_data", "album_data".to_string());
    router.add("/frame_admin/manage", "manage".to_string());
    router.add("/frame_admin/telemetry_data", "telemetry_data".to_string());
    // router.add("/frame_admin/tasks", "tasks".to_string());
    router.add("/frame_admin/image/:id", "image".to_string());
    let matched = match router.recognize(url) {
        Ok(m) => m,
        Err(_) => {
            serve_static_file(request);
            return;
        }
    };
    let auth_guard: AuthGuard<ValidUser> = ValidUser::from_request(&app_data, &request);
    match matched.handler().as_str() {
        "oauth_login" => {
            if let Some(err) = handle_oauth_login(app_data, request).err() {
                log::error!("(route_request) login route failed: {}", err);
            };
        }
        "oauth_logout" => {
            handle_oauth_logout(request, auth_guard);
        }
        "oauth_authorise" => {
            handle_oauth_authorise(app_data, request);
        }
        "oauth_google" => {
            handle_oauth_google(app_data, request);
        }
        "oauth_revoke" => {
            handle_oauth_revoke(app_data, request, auth_guard);
        }
        "index" => {
            handle_index(app_data, request, auth_guard);
        }
        // "config" => {
        //     if let Some(err) = handle_config(app_data, request, auth_guard).err() {
        //         log::error!("(route_request) sync route failed: {}", err);
        //     };
        // }
        // "sync" => {
        //     if let Some(err) = handle_sync(app_data, request, auth_guard).err() {
        //         log::error!("(route_request) sync route failed: {}", err);
        //     };
        // }
        "sync_progress" => {
            handle_sync_progress(request, auth_guard);
        }
        // "tasks" => {
        //     handle_tasks(request, auth_guard);
        // }
        "monitor" => {
            handle_monitor(request, auth_guard);
        }
        "album_data" => {
            handle_album_data(request, auth_guard);
        }
        "manage" => {
            handle_manage(request, auth_guard);
        }
        "telemetry_data" => {
            if let Some(err) = handle_telemetry_data(request, auth_guard).err() {
                log::error!("(route_request) telemetry_data route failed: {}", err);
            };
        }
        "image" => {
            if let Some(err) = handle_image(request, auth_guard, matched.params()).err() {
                log::error!("(route_request) image route failed: {}", err);
            };
        }
        _ => {
            unreachable!("unreachable");
        }
    }
}

fn handle_oauth_login(
    app_data: AppState,
    request: Request,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(e) = SESSION_MGR.get_session_id(&request).err() {
        log::info!("(handle_login) session error: {:?}", e);
        let next_uri = request
            .headers()
            .iter()
            .find(|header| header.field.equiv("Referer"))
            .map(|h| h.value.as_str())
            .or(Some("/frame_admin"))
            .expect("next_uri is now some");
        let session_id: SessionID = SESSION_MGR.create_session();
        SESSION_MGR.set_session_data(&session_id, "next_uri", next_uri);
        let env = app_data.env.lock().unwrap();
        let jwt_max_age = env.jwt_max_age;
        drop(env);
        let mut response = Response::empty(tiny_http::StatusCode(302));
        response
            .add_header(Header::from_str("Location: authorise").expect("This should never fail"));
        response.add_header(
            Header::from_str(&format!(
                "Set-Cookie: session={}; Path=/frame_admin/oauth; Max-Age={}; HttpOnly; SameSite=Lax;",
                session_id,
                jwt_max_age
            ))
            .expect("This should never fail"),
        );
        dispatch_response(request, response);
        return Ok(());
    }
    log::error!("(handle login) user logged out but session exists");
    serve_error(request, tiny_http::StatusCode(500), "Internal server error");
    Ok(())
}

fn handle_oauth_logout(request: Request, auth_guard: AuthGuard<ValidUser>) {
    let mut response = Response::empty(tiny_http::StatusCode(302));
    if auth_guard.is_ok() {
        response.add_header(
            Header::from_str(&format!(
                "Set-Cookie: token=; Path=/; Max-Age={}; HttpOnly; SameSite=Lax;",
                Duration::seconds(-1)
            ))
            .expect("This should never fail"),
        );
        response.add_header(
            Header::from_str(&format!(
                "Set-Cookie: session=; Path=/frame_admin/oauth; Max-Age={}; HttpOnly; SameSite=Lax;",
                Duration::seconds(-1)
            ))
            .expect("This should never fail"),
        );
    };
    response
        .add_header(Header::from_str("Location: /frame_admin").expect("This should never fail"));
    dispatch_response(request, response);
}

fn handle_oauth_authorise(app_data: AppState, request: Request) {
    let session_id = match SESSION_MGR.get_session_id(&request) {
        Ok(session_id) => session_id,
        Err(e) => {
            log::warn!("(handle_authorise) session error: {:?}", e);
            serve_error(request, tiny_http::StatusCode(400), "Bad request");
            return;
        }
    };
    let state = SESSION_MGR.generate_state();
    SESSION_MGR.set_session_data(&session_id, "state", &state);
    let env = app_data.env.lock().unwrap();
    let google_oauth_client_id = &env.google_oauth_client_id.to_string();
    let google_oauth_redirect_url = &env.google_oauth_redirect_url.to_string();
    drop(env);
    let mut url =
        Url::parse("https://accounts.google.com/o/oauth2/v2/auth").expect("This should never fail");
    url.query_pairs_mut()
        .append_pair("client_id", google_oauth_client_id)
        .append_pair("redirect_uri", google_oauth_redirect_url)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid profile email https://www.googleapis.com/auth/photospicker.mediaitems.readonly")
        .append_pair("access_type", "offline")
        // .append_pair("prompt", "consent") // This causes the user to be asked to re-authorise every time, and ensures a refresh token is returned
        .append_pair("state", &state);
    let mut response = Response::new_empty(tiny_http::StatusCode(302));
    response.add_header(
        tiny_http::Header::from_bytes(&b"Location"[..], &url[..]).expect("This should never fail"),
    );
    dispatch_response(request, response);
}

fn handle_oauth_google(app_data: AppState, request: Request) {
    let session_id = match SESSION_MGR.get_session_id(&request) {
        Ok(session_id) => session_id,
        Err(e) => {
            log::warn!("session error: {:?}", e);
            serve_error(request, tiny_http::StatusCode(400), "Bad request");
            return;
        }
    };
    let session_state = SESSION_MGR
        .get_session_data(&session_id, "state")
        .expect("We should have a state in the session");
    let session_next_uri = SESSION_MGR
        .get_session_data(&session_id, "next_uri")
        .expect("We should have a next_uri in the session");
    let params = extract_params(request.url());
    let state = params.get("state");
    let code = params.get("code");
    let error = params.get("error");
    if error.is_some() || state != Some(&session_state) || code.is_none() {
        log::error!("oauth2 error or state mismatch or code not found");
        serve_error(
            request,
            tiny_http::StatusCode(403),
            "Unauthorised: oauth2 error",
        );
        return;
    }
    let code = code.expect("Code should be present");
    let token_response = request_token(&app_data, code.as_str());
    if token_response.is_err() {
        let message = token_response
            .expect_err("token_response is err")
            .to_string();
        log::error!("oauth2 error: {}", message);
        serve_error(request, tiny_http::StatusCode(502), "Bad Gateway");
        return;
    }
    let user_id = token_response.expect("token_response is not err");
    let current_datetime = Utc::now();
    let env = app_data.env.lock().unwrap();
    let jwt_secret = env.jwt_secret.to_owned();
    let jwt_max_age = env.jwt_max_age;
    drop(env);
    let iat = current_datetime.timestamp() as usize;
    let exp = (current_datetime + Duration::seconds(jwt_max_age)).timestamp() as usize;
    let claims: TokenClaims = TokenClaims {
        sub: user_id,
        exp,
        iat,
    };
    let token = encode(
        &JWTHeader::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .expect("can't encode token");
    let mut response = Response::empty(tiny_http::StatusCode(302));
    response.add_header(
        Header::from_str(&format!(
            "Set-Cookie: token={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax;",
            token, jwt_max_age
        ))
        .expect("This should never fail"),
    );
    response.add_header(
        tiny_http::Header::from_bytes(&b"Location"[..], &session_next_uri[..])
            .expect("This should never fail"),
    );
    dispatch_response(request, response);
}

fn handle_oauth_revoke(app_data: AppState, request: Request, auth_guard: AuthGuard<ValidUser>) {
    let auth_guard = match auth_guard {
        Ok(auth_guard) => auth_guard,
        Err(_) => {
            let mut response = Response::empty(tiny_http::StatusCode(302));
            response.add_header(
                tiny_http::Header::from_bytes(&b"Location"[..], "/frame_admin/oauth/login")
                    .expect("This should never fail"),
            );
            dispatch_response(request, response);
            return;
        }
    };
    let mut response = match revoke_token(&app_data, &auth_guard.user) {
        Ok(_) => {
            let mut response = Response::empty(tiny_http::StatusCode(302));
            response.add_header(
                tiny_http::Header::from_bytes(&b"Location"[..], "/frame_admin")
                    .expect("This should never fail"),
            );
            response
        }
        Err(e) => {
            log::error!("(handle_revoke) error revoking access/refresh token, {}", e);
            serve_error(
                request,
                tiny_http::StatusCode(500),
                "Internal server error: error revoking credentials",
            );
            return;
        }
    };
    response.add_header(
        Header::from_str(&format!(
            "Set-Cookie: token=; Path=/; Max-Age={}; HttpOnly; SameSite=Lax;",
            Duration::seconds(-1)
        ))
        .expect("This should never fail"),
    );
    response.add_header(
        Header::from_str(&format!(
            "Set-Cookie: session=; Path=/frame_admin/oauth; Max-Age={}; HttpOnly; SameSite=Lax;",
            Duration::seconds(-1)
        ))
        .expect("This should never fail"),
    );
    dispatch_response(request, response);
}

fn handle_index(app_data: AppState, request: Request, auth_guard: AuthGuard<ValidUser>) {
    let context = match auth_guard {
        Ok(_auth_guard) => {
            let env = app_data.env.lock().unwrap();
            drop(env);
            let mut response = Response::empty(tiny_http::StatusCode(302));
            response.add_header(
                tiny_http::Header::from_bytes(&b"Location"[..], "/frame_admin/monitor")
                    .expect("This should never fail"),
            );
            dispatch_response(request, response);
            return;
        }
        Err(_) => Context::new(),
    };
    let rendered = TEMPLATES.render("index.html.tera", &context);
    let response = Response::from_data(rendered);
    dispatch_response(request, response);
}

// fn handle_config(
//     app_data: AppState,
//     request: Request,
//     auth_guard: AuthGuard<ValidUser>,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let auth_guard = match auth_guard {
//         Ok(auth_guard) => auth_guard,
//         Err(_) => {
//             let mut response = Response::empty(tiny_http::StatusCode(302));
//             response.add_header(
//                 tiny_http::Header::from_bytes(&b"Location"[..], "/frame_admin/oauth/login")
//                     .expect("This should never fail"),
//             );
//             dispatch_response(request, response);
//             return Ok(());
//         }
//     };
//     if let Some(album_id) = request
//         .headers()
//         .iter()
//         .find(|header| header.field.equiv("Google-Photos-Album-ID"))
//     {
//         let mut env = app_data.env.lock().unwrap();
//         if env
//             .google_photos_album_ids
//             .contains(&album_id.value.to_string())
//         {
//             env.google_photos_album_ids
//                 .retain(|id| id != &album_id.value);
//         } else {
//             env.google_photos_album_ids
//                 .push(album_id.value.clone().to_string());
//         }
//         let google_photos_album_list = env.google_photos_album_ids.clone();
//         drop(env);
//         app_data.save("secrets/");
//         let album_list = ureq::serde_json::to_string(&google_photos_album_list)
//             .expect("couldn't serialise album list");
//         let response = Response::from_string(album_list).with_header(
//             tiny_http::Header::from_str("Content-Type: application/json")
//                 .expect("This should never fail"),
//         );
//         dispatch_response(request, response);
//         return Ok(());
//     };
//     let env = app_data.env.lock().unwrap();
//     let google_photos_album_ids = env.google_photos_album_ids.clone();
//     drop(env);
//     let mut context = Context::new();
//     if google_photos_album_ids.is_empty() {
//         context.insert("config", &true);
//     }
//     let mut credentials = auth_guard.user.credentials.clone();
//     if SystemTime::now()
//         .duration_since(UNIX_EPOCH)
//         .expect("Time went backwards")
//         .as_secs()
//         > credentials.expires_in
//     {
//         log::info!("(handle_sync) token expired, should refresh");
//         credentials = refresh_token(&app_data, &auth_guard.user)?;
//     }
//     let access_token = credentials.access_token;
//     let album_list = match get_album_list(&access_token) {
//         Ok(album_list) => album_list,
//         Err(e) => {
//             log::error!("(handle_config) error getting album list, {}", e);
//             serve_error(
//                 request,
//                 tiny_http::StatusCode(500),
//                 "Internal server error: error getting album list",
//             );
//             return Ok(());
//         }
//     };
//     context.insert("selected_albums", &google_photos_album_ids);
//     context.insert("album_list", &album_list);
//     context.insert("profile", &auth_guard.user.photo);
//     let rendered = TEMPLATES.render("config.html.tera", &context);
//     let response = Response::from_data(rendered);
//     dispatch_response(request, response);
//     Ok(())
// }

// fn handle_sync(
//     app_data: AppState,
//     request: Request,
//     auth_guard: AuthGuard<ValidUser>,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let auth_guard = match auth_guard {
//         Ok(auth_guard) => auth_guard,
//         Err(_) => {
//             let mut response = Response::empty(tiny_http::StatusCode(302));
//             response.add_header(
//                 tiny_http::Header::from_bytes(&b"Location"[..], "/frame_admin/oauth/login")
//                     .expect("This should never fail"),
//             );
//             dispatch_response(request, response);
//             return Ok(());
//         }
//     };
//     let mut credentials = auth_guard.user.credentials.clone();
//     if SystemTime::now()
//         .duration_since(UNIX_EPOCH)
//         .expect("Time went backwards")
//         .as_secs()
//         > credentials.expires_in
//     {
//         log::info!("(handle_sync) token expired, should refresh");
//         credentials = refresh_token(&app_data, &auth_guard.user)?;
//     }
//     let access_token = credentials.access_token;
//     let mut dbclient = CONNECTION_POOL.get_client()?;
//     let mut db_set = HashSet::new();
//     for row in dbclient.query("SELECT item_id FROM album", &[])? {
//         let media_item_id: &str = row.get(0);
//         db_set.insert(media_item_id.to_string());
//     }
//     CONNECTION_POOL.release_client(dbclient);
//     let mut gg_mediaitems: HashSet<MediaItem> = HashSet::new();
//     let env = app_data.env.lock().unwrap();
//     let google_photos_album_ids = env.google_photos_album_ids.clone();
//     drop(env);
//     for album_id in google_photos_album_ids {
//         let album_mediaitems = get_mediaitems(&access_token, &album_id)?;
//         gg_mediaitems.extend(album_mediaitems);
//     }
//     let gg_set: HashSet<_> = gg_mediaitems
//         .iter()
//         .map(|media_item| media_item.id.clone())
//         .collect();
//     let new_set: HashSet<_> = gg_set.difference(&db_set).cloned().collect();
//     let deleted_set: HashSet<_> = db_set.difference(&gg_set).cloned().collect();
//     TASK_BOARD.reset();
//     if new_set.is_empty() && deleted_set.is_empty() {
//         let response = Response::empty(tiny_http::StatusCode(200));
//         dispatch_response(request, response);
//         return Ok(());
//     }
//     let queue = Arc::new(TaskQueue::new());
//     if !new_set.is_empty() {
//         log::info!("(handle_sync) found {} new media items", new_set.len());
//         for media_item in gg_mediaitems.iter() {
//             if new_set.contains(&media_item.id) {
//                 queue.push(Task {
//                     id: TASK_BOARD.add_task(Action::Add),
//                     action: Action::Add,
//                     data: TaskData::MediaItem(media_item.clone()),
//                     status: Status::Pending,
//                 });
//             }
//         }
//     }
//     if !deleted_set.is_empty() {
//         log::info!(
//             "(handle_sync) found {} deleted media items",
//             deleted_set.len()
//         );
//         for media_item_id in deleted_set.iter() {
//             queue.push(Task {
//                 id: TASK_BOARD.add_task(Action::Remove),
//                 action: Action::Remove,
//                 data: TaskData::String(media_item_id.to_string()),
//                 status: Status::Pending,
//             });
//         }
//     }
//     let threads = min(new_set.len() + deleted_set.len(), 4);
//     for _ in 0..threads {
//         let queue = queue.clone();
//         thread::spawn(move || loop {
//             if queue.is_empty() {
//                 log::info!("(handle_sync) queue is empty, nothing to do");
//                 break;
//             }
//             let task = queue.pop();
//             TASK_BOARD.set_board_data(task.id, Status::InProgress);
//             let mut dbclient = match CONNECTION_POOL.get_client() {
//                 Ok(dbclient) => dbclient,
//                 Err(err) => {
//                     log::error!("(handle_sync): {err}");
//                     TASK_BOARD.set_board_data(task.id, Status::Failed);
//                     continue;
//                 }
//             };
//             match task.data {
//                 TaskData::MediaItem(media_item) => {
//                     log::info!("(handle_sync) retrieving photo");
//                     match get_photo(&media_item)
//                         .map(|data| {
//                             log::info!("(handle_sync) encoding image");
//                             encode_image(&data)
//                         })
//                         .and_then(|data| {
//                             log::info!("(handle_sync) adding media item to db");
//                             let portrait = media_item.mediaMetadata.width.parse::<i64>()?
//                                 < media_item.mediaMetadata.height.parse::<i64>()?;
//                             Ok(dbclient.execute(
//                                 "INSERT INTO album (item_id, product_url, ts, portrait, data) VALUES ($1, $2, $3, $4, $5)",
//                                 &[
//                                     &media_item.id,
//                                     &media_item.productUrl,
//                                     &0_i64,
//                                     &portrait,
//                                     &data,
//                                 ],
//                             ))
//                         }) {
//                         Ok(_) => {}
//                         Err(err) => {
//                             log::error!("(handle_sync): {err}");
//                             TASK_BOARD.set_board_data(task.id, Status::Failed);
//                         }
//                     };
//                 }
//                 TaskData::String(item_id) => {
//                     log::info!("(handle_sync) removing record from db");
//                     match dbclient.execute("DELETE FROM album WHERE item_id = $1", &[&item_id]) {
//                         Ok(_) => {}
//                         Err(err) => {
//                             log::error!("(handle_sync): {err}");
//                             TASK_BOARD.set_board_data(task.id, Status::Failed);
//                         }
//                     };
//                 }
//             }
//             CONNECTION_POOL.release_client(dbclient);
//             TASK_BOARD.set_board_data(task.id, Status::Completed);
//         });
//     }
//     log::info!("(handle_sync) {} sync thread(s) dispatched", threads);
//     let response = Response::empty(tiny_http::StatusCode(202));
//     dispatch_response(request, response);
//     Ok(())
// }

// fn handle_tasks(request: Request, auth_guard: AuthGuard<ValidUser>) {
//     match auth_guard {
//         Ok(_) => {}
//         Err(_) => {
//             serve_error(request, tiny_http::StatusCode(401), "Unauthorised");
//             return;
//         }
//     };
//     let body =
//         ureq::serde_json::to_string(&TASK_BOARD.get_board()).expect("can't serialize task board");
//     let rendered = body.as_bytes();
//     let response = Response::empty(tiny_http::StatusCode(200))
//         .with_data(rendered, Some(rendered.len()))
//         .with_header(
//             tiny_http::Header::from_str("Content-Type: application/json")
//                 .expect("This should never fail"),
//         );
//     dispatch_response(request, response);
// }

// fn handle_sync_progress(request: Request, auth_guard: AuthGuard<ValidUser>) {
//     match auth_guard {
//         Ok(_) => {}
//         Err(_) => {
//             serve_error(request, tiny_http::StatusCode(401), "Unauthorised");
//             return;
//         }
//     };
//     let body =
//         ureq::serde_json::to_string(&TASK_BOARD.board_status().expect("can't get board status"))
//             .expect("can't serialize task board");
//     let rendered = body.as_bytes();
//     let response = Response::empty(tiny_http::StatusCode(200))
//         .with_data(rendered, Some(rendered.len()))
//         .with_header(
//             tiny_http::Header::from_str("Content-Type: application/json")
//                 .expect("This should never fail"),
//         );
//     dispatch_response(request, response);
// }

fn picked_to_media_item(picked: &PickedMediaItem) -> MediaItem {
    MediaItem {
        id: picked.id.clone(),
        productUrl: picked.mediaFile.baseUrl.clone(),
        baseUrl: picked.mediaFile.baseUrl.clone(),
        mimeType: picked.mediaFile.mimeType.clone(),
        mediaMetadata: MediaMetadata {
            width: picked.mediaFile.mediaFileMetadata.width.to_string(),
            height: picked.mediaFile.mediaFileMetadata.height.to_string(),
        },
        filename: picked.mediaFile.filename.clone(),
    }
}

fn handle_manage(request: Request, auth_guard: AuthGuard<ValidUser>) {
    let auth_guard = match auth_guard {
        Ok(auth_guard) => auth_guard,
        Err(_) => {
            let mut response = Response::empty(tiny_http::StatusCode(302));
            response.add_header(
                tiny_http::Header::from_bytes(&b"Location"[..], "/frame_admin/oauth/login")
                    .expect("This should never fail"),
            );
            dispatch_response(request, response);
            return;
        }
    };

    if let Some(header) = request.headers().iter().find(|h| h.field.equiv("picker-session")) {
        let value = header.value.as_str();
        let mut parts = value.splitn(2, ':');
        let action = parts.next().unwrap_or("");
        let session_id = parts.next();

        fn respond_json<T: serde::Serialize>(request: Request, result: Result<T, impl std::fmt::Debug>) {
            let json = serde_json::json!(result.expect("API call failed"));
            let body = serde_json::to_string(&json).expect("can't serialize response");
            let response = Response::empty(tiny_http::StatusCode(200))
                .with_data(body.as_bytes(), Some(body.len()))
                .with_header(
                    tiny_http::Header::from_str("Content-Type: application/json")
                        .expect("This should never fail"),
                );
            dispatch_response(request, response);
        }

        match action {
            "create" => {
                respond_json(request, PickingSession::create(&auth_guard.user.credentials.access_token));
            }
            "delete" => {
                if let Some(session_id) = session_id {
                    let session_id = session_id.to_string();
                    respond_json(request, PickingSession::delete(&auth_guard.user.credentials.access_token, &session_id));
                }
            }
            "poll" => {
                if let Some(session_id) = session_id {
                    let session_id = session_id.to_string();
                    let result = PickingSession::poll(&auth_guard.user.credentials.access_token, &session_id);
                    if let Ok(ref poll_response) = result {
                        if poll_response.mediaItemsSet {
                            log::info!("Media items have been set for picking session {}", session_id);
                            let list = PickingSession::list_picked(&auth_guard.user.credentials.access_token, &session_id);
                            if let Ok(ref media_items) = list {
                                log::info!("Media items picked: {:?}", media_items);
                                let picked_map: HashMap<String, PickedMediaItem> = media_items
                                    .iter()
                                    .map(|item| (item.id.clone(), item.clone()))
                                    .collect();
                                let picked_ids: HashSet<String> =
                                    media_items.iter().map(|item| item.id.clone()).collect();
                                if picked_ids.is_empty() {
                                    log::info!(
                                        "No media items returned for picking session {}, nothing to sync",
                                        session_id
                                    );
                                } else {
                                    let access_token = auth_guard.user.credentials.access_token.clone();
                                    let mut dbclient = match CONNECTION_POOL.get_client() {
                                        Ok(c) => c,
                                        Err(e) => {
                                            log::error!(
                                                "(handle_manage) DB pool error: {:?}",
                                                e
                                            );
                                            respond_json(request, result);
                                            return;
                                        }
                                    };
                                    let mut existing_ids = HashSet::new();
                                    match dbclient.query("SELECT item_id FROM album", &[]) {
                                        Ok(rows) => {
                                            for row in rows {
                                                let media_item_id: String = row.get(0);
                                                existing_ids.insert(media_item_id);
                                            }
                                        }
                                        Err(e) => {
                                            log::error!(
                                                "(handle_manage) DB query error: {:?}",
                                                e
                                            );
                                            CONNECTION_POOL.release_client(dbclient);
                                            respond_json(request, result);
                                            return;
                                        }
                                    }
                                    CONNECTION_POOL.release_client(dbclient);
                                    let new_ids: HashSet<_> =
                                        picked_ids.difference(&existing_ids).cloned().collect();
                                    if new_ids.is_empty() {
                                        log::info!(
                                            "All {} picked items already exist, skipping sync",
                                            picked_ids.len()
                                        );
                                    } else {
                                        TASK_BOARD.reset();
                                        let queue = Arc::new(TaskQueue::new());
                                        let mut task_count = 0;
                                        for media_item_id in new_ids.iter() {
                                            if let Some(picked_item) = picked_map.get(media_item_id) {
                                                let media_item = picked_to_media_item(picked_item);
                                                queue.push(Task {
                                                    id: TASK_BOARD.add_task(Action::Add),
                                                    action: Action::Add,
                                                    data: TaskData::MediaItemWithToken(media_item, access_token.clone()),
                                                    status: Status::Pending,
                                                });
                                                task_count += 1;
                                            } else {
                                                log::warn!(
                                                    "(handle_manage) picked item {} not found in map after filtering",
                                                    media_item_id
                                                );
                                            }
                                        }
                                        if task_count == 0 {
                                            log::info!(
                                                "No tasks enqueued after filtering picked items for session {}",
                                                session_id
                                            );
                                        } else {
                                            let threads = min(task_count, 4);
                                            for _ in 0..threads {
                                                let queue = queue.clone();
                                                thread::spawn(move || loop {
                                                    if queue.is_empty() {
                                                        log::info!("(handle_manage) queue is empty, nothing to do");
                                                        break;
                                                    }
                                                    let task = queue.pop();
                                                    TASK_BOARD.set_board_data(task.id, Status::InProgress);
                                                    let mut dbclient = match CONNECTION_POOL.get_client() {
                                                        Ok(dbclient) => dbclient,
                                                        Err(err) => {
                                                            log::error!("(handle_manage): {err}");
                                                            TASK_BOARD.set_board_data(task.id, Status::Failed);
                                                            continue;
                                                        }
                                                    };
                                                    let mut success = true;
                                                    match task.data {
                                                        TaskData::MediaItem(media_item) => {
                                                            log::info!("(handle_manage) retrieving photo");
                                                            match get_photo(&media_item, None)
                                                                .map(|data| {
                                                                    log::info!("(handle_manage) encoding image");
                                                                    encode_image(&data)
                                                                })
                                                                .and_then(|data| {
                                                                    log::info!("(handle_manage) adding media item to db");
                                                                    let portrait = media_item.mediaMetadata.width.parse::<i64>()?
                                                                        < media_item.mediaMetadata.height.parse::<i64>()?;
                                                                    dbclient.execute(
                                                                        "INSERT INTO album (item_id, ts, portrait, data) VALUES ($1, $2, $3, $4)",
                                                                        &[
                                                                            &media_item.id,
                                                                            &0_i64,
                                                                            &portrait,
                                                                            &data,
                                                                        ],
                                                                    )?;
                                                                    Ok(())
                                                                }) {
                                                                Ok(_) => {}
                                                                Err(err) => {
                                                                    log::error!(
                                                                        "(handle_manage) db insert error for {}: {:?}",
                                                                        media_item.id,
                                                                        err
                                                                    );
                                                                    TASK_BOARD.set_board_data(task.id, Status::Failed);
                                                                    success = false;
                                                                }
                                                            };
                                                        }
                                                        TaskData::MediaItemWithToken(media_item, token) => {
                                                            log::info!("(handle_manage) retrieving photo");
                                                            match get_photo(&media_item, Some(token.as_str()))
                                                                .map(|data| {
                                                                    log::info!("(handle_manage) encoding image");
                                                                    encode_image(&data)
                                                                })
                                                                .and_then(|data| {
                                                                    log::info!("(handle_manage) adding media item to db");
                                                                    let portrait = media_item.mediaMetadata.width.parse::<i64>()?
                                                                        < media_item.mediaMetadata.height.parse::<i64>()?;
                                                                    dbclient.execute(
                                                                        "INSERT INTO album (item_id, ts, portrait, data) VALUES ($1, $2, $3, $4)",
                                                                        &[
                                                                            &media_item.id,
                                                                            &0_i64,
                                                                            &portrait,
                                                                            &data,
                                                                        ],
                                                                    )?;
                                                                    Ok(())
                                                                }) {
                                                                Ok(_) => {}
                                                                Err(err) => {
                                                                    log::error!(
                                                                        "(handle_manage) db insert error for {}: {:?}",
                                                                        media_item.id,
                                                                        err
                                                                    );
                                                                    TASK_BOARD.set_board_data(task.id, Status::Failed);
                                                                    success = false;
                                                                }
                                                            };
                                                        }
                                                        TaskData::String(_) => {
                                                            log::error!("(handle_manage) unexpected remove task in manage flow");
                                                            TASK_BOARD.set_board_data(task.id, Status::Failed);
                                                            success = false;
                                                        }
                                                    }
                                                    CONNECTION_POOL.release_client(dbclient);
                                                    if success {
                                                        TASK_BOARD.set_board_data(task.id, Status::Completed);
                                                    }
                                                });
                                            }
                                            log::info!(
                                                "(handle_manage) dispatched {} sync thread(s) for {} new items",
                                                threads,
                                                task_count
                                            );
                                        }
                                    }
                                }
                            } else {
                                log::error!("Error listing picked media items: {:?}", list.err());
                            }

                            log::info!("Media items set, deleting picking session {}", session_id);
                            let _ = PickingSession::delete(&auth_guard.user.credentials.access_token, &session_id);
                        }
                    }
                    respond_json(request, result);
                }
            }
            _ => {
                serve_error(request, tiny_http::StatusCode(400), "Invalid picker-session action");
            }
        }
        return;
    }

    let mut context = Context::new();
    context.insert("profile", &auth_guard.user.photo);
    let rendered = TEMPLATES.render("manage.html.tera", &context);
    let response = Response::from_data(rendered);
    dispatch_response(request, response);
}

fn handle_sync_progress(request: Request, auth_guard: AuthGuard<ValidUser>) {
    match auth_guard {
        Ok(_) => {}
        Err(_) => {
            serve_error(request, tiny_http::StatusCode(401), "Unauthorised");
            return;
        }
    };
    let body = match TASK_BOARD.board_status() {
        Ok(status) => match serde_json::to_string(&status) {
            Ok(b) => b,
            Err(e) => {
                log::error!("(handle_sync_progress) serialize error: {:?}", e);
                serve_error(request, tiny_http::StatusCode(500), "Internal server error");
                return;
            }
        },
        Err(e) => {
            log::error!("(handle_sync_progress) can't get board status: {}", e);
            serve_error(request, tiny_http::StatusCode(500), "Internal server error");
            return;
        }
    };
    let rendered = body.as_bytes();
    let response = Response::empty(tiny_http::StatusCode(200))
        .with_data(rendered, Some(rendered.len()))
        .with_header(
            tiny_http::Header::from_str("Content-Type: application/json")
                .expect("This should never fail"),
        );
    dispatch_response(request, response);
}

fn handle_album_data(request: Request, auth_guard: AuthGuard<ValidUser>) {
    match auth_guard {
        Ok(_) => {}
        Err(_) => {
            let mut response = Response::empty(tiny_http::StatusCode(302));
            response.add_header(
                tiny_http::Header::from_bytes(&b"Location"[..], "/frame_admin/oauth/login")
                    .expect("This should never fail"),
            );
            dispatch_response(request, response);
            return;
        }
    };

    let params = extract_params(request.url());
    let page: i64 = params.get("page").and_then(|v| v.parse().ok()).filter(|p| *p > 0).unwrap_or(1);
    let page_size: i64 = params.get("pageSize").and_then(|v| v.parse::<i64>().ok()).filter(|s| *s > 0).map(|s| s.min(24)).unwrap_or(12);
    let offset = (page - 1) * page_size;

    let mut dbclient = match CONNECTION_POOL.get_client() {
        Ok(c) => c,
        Err(e) => {
            log::error!("(handle_album_data) DB pool error: {:?}", e);
            serve_error(request, tiny_http::StatusCode(500), "Internal server error");
            return;
        }
    };

    let rows = match dbclient.query(
        "SELECT item_id, ts, portrait FROM album ORDER BY ts DESC LIMIT $1 OFFSET $2",
        &[&page_size, &offset],
    ) {
        Ok(r) => r,
        Err(e) => {
            log::error!("(handle_album_data) query error: {:?}", e);
            serve_error(request, tiny_http::StatusCode(500), "Internal server error");
            return;
        }
    };

    let total: i64 = match dbclient.query_one("SELECT count(*) FROM album", &[]) {
        Ok(r) => r.get(0),
        Err(e) => {
            log::error!("(handle_album_data) count error: {:?}", e);
            serve_error(request, tiny_http::StatusCode(500), "Internal server error");
            return;
        }
    };
    CONNECTION_POOL.release_client(dbclient);

    let mut items = Vec::new();
    for row in rows {
        let id: String = row.get(0);
        let ts_secs: i64 = row.get(1);
        let portrait: bool = row.get(2);
        let ts_iso = chrono::DateTime::<chrono::Utc>::from_timestamp(ts_secs, 0)
            .map(|dt| dt.to_rfc3339());
        items.push(serde_json::json!({
            "id": id,
            "thumbUrl": format!("/frame_admin/image/{}?size=thumb", id),
            "productUrl": Option::<String>::None,
            "ts": ts_iso,
            "portrait": portrait,
        }));
    }

    let body = match serde_json::to_string(&serde_json::json!({
        "items": items,
        "page": page,
        "pageSize": page_size,
        "total": total,
    })) {
        Ok(b) => b,
        Err(e) => {
            log::error!("(handle_album_data) serialize error: {:?}", e);
            serve_error(request, tiny_http::StatusCode(500), "Internal server error");
            return;
        }
    };

    let response = Response::empty(tiny_http::StatusCode(200))
        .with_data(body.as_bytes(), Some(body.len()))
        .with_header(
            tiny_http::Header::from_str("Content-Type: application/json")
                .expect("This should never fail"),
        );
    dispatch_response(request, response);
}

fn handle_monitor(request: Request, auth_guard: AuthGuard<ValidUser>) {
    let auth_guard = match auth_guard {
        Ok(auth_guard) => auth_guard,
        Err(_) => {
            let mut response = Response::empty(tiny_http::StatusCode(302));
            response.add_header(
                tiny_http::Header::from_bytes(&b"Location"[..], "/frame_admin/oauth/login")
                    .expect("This should never fail"),
            );
            dispatch_response(request, response);
            return;
        }
    };
    let mut context = Context::new();
    context.insert("profile", &auth_guard.user.photo);
    let rendered = TEMPLATES.render("monitor.html.tera", &context);
    let response = Response::from_data(rendered);
    dispatch_response(request, response);
}

fn handle_telemetry_data(
    request: Request,
    auth_guard: AuthGuard<ValidUser>,
) -> Result<(), Box<dyn std::error::Error>> {
    match auth_guard {
        Ok(_) => {}
        Err(_) => {
            let mut response = Response::empty(tiny_http::StatusCode(302));
            response.add_header(
                tiny_http::Header::from_bytes(&b"Location"[..], "/frame_admin/oauth/login")
                    .expect("This should never fail"),
            );
            dispatch_response(request, response);
            return Ok(());
        }
    };
    let params = extract_params(request.url());
    let offset = params
        .get("start")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let mut limit = params
        .get("length")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(20);
    let draw = params
        .get("draw")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let mut dbclient = CONNECTION_POOL.get_client()?;
    let mut transaction = dbclient.transaction()?;
    let count_row = transaction.query_one("SELECT COUNT(*) FROM telemetry", &[])?;
    let records_total: i64 = count_row.get(0);
    if limit == -1 {
        limit = records_total;
    }
    let records = transaction.query(
        "SELECT ts, item_id, item_id_2, bat_voltage, boot_code, remote_addr 
        FROM telemetry 
        ORDER BY ts DESC
        LIMIT $1 OFFSET $2",
        &[&limit, &offset],
    )?;
    transaction.commit()?;
    CONNECTION_POOL.release_client(dbclient);
    let mut event_log: Vec<TelemetryRecord> = Vec::new();
    for row in records {
        let record = TelemetryRecord {
            ts: row.get(0),
            item_id: row.get(1),
            item_id_2: row.get(2),
            bat_voltage: row.get(3),
            boot_code: row.get(4),
            remote_addr: row.get(5),
        };
        event_log.push(record);
    }
    let event_log = serde_json::json!({
        "data": serde_json::to_value(&event_log)?,
        "recordsFiltered": records_total,
        "recordsTotal": records_total,
        "draw": Some(draw),
    });
    let body = serde_json::to_string(&event_log)?;
    let rendered = body.as_bytes();
    let response = Response::empty(tiny_http::StatusCode(200))
        .with_data(rendered, Some(rendered.len()))
        .with_header(
            tiny_http::Header::from_str("Content-Type: application/json")
                .expect("This should never fail"),
        );
    dispatch_response(request, response);
    Ok(())
}

fn handle_image(
    request: Request,
    auth_guard: AuthGuard<ValidUser>,
    params: &Params,
) -> Result<(), Box<dyn std::error::Error>> {
    match auth_guard {
        Ok(_) => {}
        Err(_) => {
            let mut response = Response::empty(tiny_http::StatusCode(302));
            response.add_header(
                tiny_http::Header::from_bytes(&b"Location"[..], "/frame_admin/oauth/login")
                    .expect("This should never fail"),
            );
            dispatch_response(request, response);
            return Ok(());
        }
    };
    let image_id = match params.find("id") {
        Some(image_id) => image_id,
        None => {
            serve_error(request, tiny_http::StatusCode(404), "Not found");
            return Ok(());
        }
    };
    let query_params = extract_params(request.url());
    let is_thumb = matches!(query_params.get("size"), Some(v) if v == "thumb");
    let mut dbclient = CONNECTION_POOL.get_client()?;
    let data: Vec<u8> = match dbclient
        .query("SELECT data FROM album WHERE item_id = $1", &[&image_id])?
        .get(0)
        .and_then(|row| row.get(0))
    {
        Some(data) => data,
        None => {
            serve_error(request, tiny_http::StatusCode(500), "Internal server error");
            return Ok(());
        }
    };
    CONNECTION_POOL.release_client(dbclient);
    let (nwidth, nheight) = if is_thumb {
        match data.len() {
            134400 => (120, 90),  // landscape thumbnail
            67200 => (90, 120),   // portrait thumbnail
            _ => unreachable!(),
        }
    } else {
        match data.len() {
            134400 => (350, 261),
            67200 => (175, 261),
            _ => unreachable!(),
        }
    };
    let dynamic_image = decode_image(data)?;
    let resized_dynamic_image = dynamic_image.resize_to_fill(nwidth, nheight, FilterType::Lanczos3);
    let mut buf = std::io::Cursor::new(Vec::new());
    resized_dynamic_image.write_to(&mut buf, image::ImageFormat::Jpeg)?;
    let mut response = Response::from_data(buf.into_inner());
    response.add_header(
        tiny_http::Header::from_str("Content-Type: image/jpeg").expect("This should never fail"),
    );
    dispatch_response(request, response);
    Ok(())
}

fn extract_params(url: &str) -> HashMap<String, String> {
    url.split('?')
        .nth(1)
        .unwrap_or("")
        .split('&')
        .map(|param| {
            let mut parts = param.split('=');
            (parts.next().unwrap_or(""), parts.next().unwrap_or(""))
        })
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn serve_static_file(request: Request) {
    let mut file_name = match request.url().split('?').next() {
        Some(f) => f,
        None => {
            serve_error(
                request,
                tiny_http::StatusCode(500),
                "Internal server error: could not parse url",
            );
            return;
        }
    };
    file_name = file_name.trim_start_matches("/frame_admin/");
    if file_name == "/" {
        serve_error(request, tiny_http::StatusCode(404), "File not found");
        return;
    }
    let file_path = format!("public/{}", file_name);
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => {
            serve_error(request, tiny_http::StatusCode(404), "File not found");
            return;
        }
    };
    let content_type = match file_name.split('.').last() {
        Some("html") => "text/html; charset=UTF-8",
        Some("css") => "text/css",
        Some("js") => "text/javascript",
        Some("json") => "application/json",
        Some("ico") => "image/x-icon",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        _ => "application/octet-stream",
    };
    let response = Response::from_file(file).with_header(
        tiny_http::Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes())
            .expect("This should never fail"),
    );
    dispatch_response(request, response);
}

pub fn serve_error(request: Request, status_code: tiny_http::StatusCode, message: &str) {
    let response = Response::new(
        status_code,
        vec![],
        message.as_bytes(),
        Some(message.as_bytes().len()),
        None,
    );
    dispatch_response(request, response);
}

pub fn log_request(request: &tiny_http::Request, status: u16, size: usize) {
    let remote_addr = request
        .remote_addr()
        .unwrap_or(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
        .ip();
    let date_time = chrono::Local::now().format("%d/%b/%Y:%H:%M:%S %z");
    let method = request.method();
    let uri = request.url();
    let protocol = request.http_version();
    let status = status;
    let size = size;
    let referer = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Referer"))
        .map(|header| header.value.to_string())
        .unwrap_or("-".to_string());
    let user_agent = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("User-Agent"))
        .map(|header| header.value.to_string())
        .unwrap_or("-".to_string());
    println!(
        "{} [{}] \"{} {} {}\" {} {} \"{}\" \"{}\"",
        remote_addr, date_time, method, uri, protocol, status, size, referer, user_agent
    );
}

fn dispatch_response<R>(request: Request, mut response: Response<R>)
where
    R: Read,
{
    if !response
        .headers()
        .iter()
        .any(|header| header.field.equiv("Content-Type"))
    {
        response = response.with_header(
            tiny_http::Header::from_str("Content-Type: text/html; charset=UTF-8")
                .expect("This should never fail"),
        );
    }
    log_request(
        &request,
        response.status_code().0,
        response.data_length().expect("This should not fail"),
    );
    if let Err(e) = request.respond(response) {
        log::error!("(dispatch_reponse) could not send response: {}", e);
    }
}
