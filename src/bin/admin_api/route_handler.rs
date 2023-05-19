use chrono::{Duration, Utc};
use frame::database::CONNECTION_POOL;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    google_oauth::{refresh_token, request_token, revoke_token, AuthGuard, ValidUser},
    gphotos_api::{get_album_list, get_mediaitems, get_photo, MediaItem},
    image_proc::{decode_image, encode_image},
    model::{AppState, TokenClaims},
    session_mgr::{SessionID, SESSION_MGR},
    task_mgr::{Action, Status, Task, TaskData, TaskQueue, TASK_BOARD},
    template_mgr::TEMPLATES,
};

use image::imageops::FilterType;
use jsonwebtoken::{encode, EncodingKey, Header as JWTHeader};
use log;
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
    product_url: Option<String>,
    item_id_2: Option<String>,
    product_url_2: Option<String>,
    chip_id: i32,
    uuid_number: Uuid,
    bat_voltage: i32,
    boot_code: i32,
    error_code: i32,
    return_code: Option<i32>,
    write_bytes: Option<i32>,
    remote_addr: Vec<IpAddr>,
}

pub fn route_request(app_data: AppState, request: Request) {
    let url = match Url::parse("http://localhost:5000")
        .expect("This should never fail")
        .join(&request.url())
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
    let url = url.path().trim_end_matches("/");
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
    router.add("/frame_admin/config", "config".to_string());
    router.add("/frame_admin/sync", "sync".to_string());
    router.add("/frame_admin/sync_progress", "sync_progress".to_string());
    router.add("/frame_admin/telemetry", "telemetry".to_string());
    router.add("/frame_admin/telemetry_data", "telemetry_data".to_string());
    router.add("/frame_admin/tasks", "tasks".to_string());
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
        "config" => {
            if let Some(err) = handle_config(app_data, request, auth_guard).err() {
                log::error!("(route_request) sync route failed: {}", err);
            };
        }
        "sync" => {
            if let Some(err) = handle_sync(app_data, request, auth_guard).err() {
                log::error!("(route_request) sync route failed: {}", err);
            };
        }
        "sync_progress" => {
            handle_sync_progress(request, auth_guard);
        }
        "tasks" => {
            handle_tasks(request, auth_guard);
        }
        "telemetry" => {
            handle_telemetry(request, auth_guard);
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
            assert!(false, "unreachable");
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
            .and_then(|h| Some(h.value.as_str()))
            .or_else(|| Some("/frame_admin")) // TODO: this should be the default route
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
    assert!(false, "I'm not sure that I should be able to get down here");
    let mut response = Response::empty(tiny_http::StatusCode(302));
    response.add_header(
        Header::from_str("Location: /frame_admin/telemetry").expect("This should never fail"),
    );
    dispatch_response(request, response);
    Ok(())
}

fn handle_oauth_logout(request: Request, auth_guard: AuthGuard<ValidUser>) {
    let mut response = Response::empty(tiny_http::StatusCode(302));
    match auth_guard {
        Ok(_) => {
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
        }
        Err(_) => {}
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
        .append_pair("client_id", &google_oauth_client_id)
        .append_pair("redirect_uri", &google_oauth_redirect_url)
        .append_pair("response_type", "code")
        .append_pair(
            "scope",
            "openid profile email https://www.googleapis.com/auth/photoslibrary.readonly",
        )
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
            .err()
            .expect("token_response is err")
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
    let jwt_secret = jwt_secret;
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
        Ok(auth_guard) => {
            let env = app_data.env.lock().unwrap();
            let google_photos_album_ids = env.google_photos_album_ids.clone();
            drop(env);
            let mut context = Context::new();
            context.insert("profile", &auth_guard.user.photo);
            if google_photos_album_ids.is_empty() {
                let mut response = Response::empty(tiny_http::StatusCode(302));
                response.add_header(
                    tiny_http::Header::from_bytes(&b"Location"[..], "/frame_admin/config")
                        .expect("This should never fail"),
                );
                dispatch_response(request, response);
                return;
            }
            context
        }
        Err(_) => Context::new(),
    };
    let rendered = TEMPLATES.render("index.html.tera", &context);
    let response = Response::from_data(rendered);
    dispatch_response(request, response);
}

fn handle_config(
    app_data: AppState,
    request: Request,
    auth_guard: AuthGuard<ValidUser>,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_guard = match auth_guard {
        Ok(auth_guard) => auth_guard,
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
    match request
        .headers()
        .iter()
        .find(|header| header.field.as_str() == "Google-Photos-Album-ID")
    {
        Some(album_id) => {
            let mut env = app_data.env.lock().unwrap();
            if env
                .google_photos_album_ids
                .contains(&album_id.value.to_string())
            {
                env.google_photos_album_ids
                    .retain(|id| id != &album_id.value);
            } else {
                env.google_photos_album_ids
                    .push(album_id.value.clone().to_string());
            }
            let google_photos_album_list = env.google_photos_album_ids.clone();
            drop(env);
            app_data.save("secrets/");
            let album_list = ureq::serde_json::to_string(&google_photos_album_list)
                .expect("couldn't serialise album list");
            let response = Response::from_string(album_list).with_header(
                tiny_http::Header::from_str("Content-Type: application/json")
                    .expect("This should never fail"),
            );
            dispatch_response(request, response);
            return Ok(());
        }
        _ => {}
    };
    let env = app_data.env.lock().unwrap();
    let google_photos_album_ids = env.google_photos_album_ids.clone();
    drop(env);
    let mut context = Context::new();
    if google_photos_album_ids.is_empty() {
        context.insert("config", &true);
    }
    let mut credentials = auth_guard.user.credentials.clone();
    if SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        > credentials.expires_in
    {
        log::info!("(handle_sync) token expired, should refresh");
        credentials = refresh_token(&app_data, &auth_guard.user)?;
    }
    let access_token = credentials.access_token;
    let album_list = match get_album_list(&access_token) {
        Ok(album_list) => album_list,
        Err(e) => {
            log::error!("(handle_config) error getting album list, {}", e);
            serve_error(
                request,
                tiny_http::StatusCode(500),
                "Internal server error: error getting album list",
            );
            return Ok(());
        }
    };
    context.insert("selected_albums", &google_photos_album_ids);
    context.insert("album_list", &album_list);
    context.insert("profile", &auth_guard.user.photo);
    let rendered = TEMPLATES.render("config.html.tera", &context);
    let response = Response::from_data(rendered);
    dispatch_response(request, response);
    Ok(())
}

fn handle_sync(
    app_data: AppState,
    request: Request,
    auth_guard: AuthGuard<ValidUser>,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_guard = match auth_guard {
        Ok(auth_guard) => auth_guard,
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
    let mut credentials = auth_guard.user.credentials.clone();
    if SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
        > credentials.expires_in
    {
        log::info!("(handle_sync) token expired, should refresh");
        credentials = refresh_token(&app_data, &auth_guard.user)?;
    }
    let access_token = credentials.access_token;
    let mut dbclient = CONNECTION_POOL.get_client()?;
    let mut db_set = HashSet::new();
    for row in dbclient.query("SELECT item_id FROM album", &[])? {
        let media_item_id: &str = row.get(0);
        db_set.insert(media_item_id.to_string());
    }
    CONNECTION_POOL.release_client(dbclient);
    let mut gg_mediaitems: HashSet<MediaItem> = HashSet::new();
    let env = app_data.env.lock().unwrap();
    let google_photos_album_ids = env.google_photos_album_ids.clone();
    drop(env);
    for album_id in google_photos_album_ids {
        let album_mediaitems = get_mediaitems(&access_token, &album_id)?;
        gg_mediaitems.extend(album_mediaitems);
    }
    let gg_set: HashSet<_> = gg_mediaitems
        .iter()
        .map(|media_item| media_item.id.clone())
        .collect();
    let new_set: HashSet<_> = gg_set
        .difference(&db_set)
        .cloned()
        .map(|s| s.to_string())
        .collect();
    let deleted_set: HashSet<_> = db_set
        .difference(&gg_set)
        .cloned()
        .map(|s| s.to_string())
        .collect();
    TASK_BOARD.reset();
    if new_set.len() == 0 && deleted_set.len() == 0 {
        let response = Response::empty(tiny_http::StatusCode(200));
        dispatch_response(request, response);
        return Ok(());
    }
    let queue = Arc::new(TaskQueue::new());
    if new_set.len() > 0 {
        log::info!("(handle_sync) found {} new media items", new_set.len());
        for media_item in gg_mediaitems.iter() {
            if new_set.contains(&media_item.id) {
                queue.push(Task {
                    id: TASK_BOARD.add_task(Action::Add),
                    action: Action::Add,
                    data: TaskData::MediaItem(media_item.clone()),
                    status: Status::Pending,
                });
            }
        }
    }
    if deleted_set.len() > 0 {
        log::info!(
            "(handle_sync) found {} deleted media items",
            deleted_set.len()
        );
        for media_item_id in deleted_set.iter() {
            queue.push(Task {
                id: TASK_BOARD.add_task(Action::Remove),
                action: Action::Remove,
                data: TaskData::String(media_item_id.to_string()),
                status: Status::Pending,
            });
        }
    }
    let threads = min(new_set.len() + deleted_set.len(), 4);
    for _ in 0..threads {
        let queue = queue.clone();
        thread::spawn(move || loop {
            if queue.is_empty() {
                log::info!("(handle_sync) queue is empty, nothing to do");
                break;
            }
            let task = queue.pop();
            TASK_BOARD.set_board_data(task.id, Status::InProgress);
            let mut dbclient = match CONNECTION_POOL.get_client() {
                Ok(dbclient) => dbclient,
                Err(err) => {
                    log::error!("(handle_sync): {err}");
                    TASK_BOARD.set_board_data(task.id, Status::Failed);
                    continue;
                }
            };
            match task.data {
                TaskData::MediaItem(media_item) => {
                    log::info!("(handle_sync) retrieving photo");
                    match get_photo(&media_item)
                        .and_then(|data| {
                            log::info!("(handle_sync) encoding image");
                            Ok(encode_image(&data))
                        })
                        .and_then(|data| {
                            log::info!("(handle_sync) adding media item to db");
                            let portrait = media_item.mediaMetadata.width.parse::<i64>()?
                                < media_item.mediaMetadata.height.parse::<i64>()?;
                            Ok(dbclient.execute(
                                "INSERT INTO album (item_id, product_url, ts, portrait, data) VALUES ($1, $2, $3, $4, $5)",
                                &[
                                    &media_item.id,
                                    &media_item.productUrl,
                                    &(0 as i64),
                                    &portrait,
                                    &data,
                                ],
                            ))
                        }) {
                        Ok(_) => {}
                        Err(err) => {
                            log::error!("(handle_sync): {err}");
                            TASK_BOARD.set_board_data(task.id, Status::Failed);
                        }
                    };
                }
                TaskData::String(item_id) => {
                    log::info!("(handle_sync) removing record from db");
                    match dbclient.execute("DELETE FROM album WHERE item_id = $1", &[&item_id]) {
                        Ok(_) => {}
                        Err(err) => {
                            log::error!("(handle_sync): {err}");
                            TASK_BOARD.set_board_data(task.id, Status::Failed);
                        }
                    };
                }
            }
            CONNECTION_POOL.release_client(dbclient);
            TASK_BOARD.set_board_data(task.id, Status::Completed);
        });
    }
    log::info!("(handle_sync) {} sync thread(s) dispatched", threads);
    let response = Response::empty(tiny_http::StatusCode(202));
    dispatch_response(request, response);
    Ok(())
}

fn handle_tasks(request: Request, auth_guard: AuthGuard<ValidUser>) {
    match auth_guard {
        Ok(_) => {}
        Err(_) => {
            serve_error(request, tiny_http::StatusCode(401), "Unauthorised");
            return;
        }
    };
    let body =
        ureq::serde_json::to_string(&TASK_BOARD.get_board()).expect("can't serialize task board");
    let rendered = body.as_bytes();
    let response = Response::empty(tiny_http::StatusCode(200))
        .with_data(rendered, Some(rendered.len()))
        .with_header(
            tiny_http::Header::from_str("Content-Type: application/json")
                .expect("This should never fail"),
        );
    dispatch_response(request, response);
}

// TODOL unwraps
fn handle_sync_progress(request: Request, auth_guard: AuthGuard<ValidUser>) {
    match auth_guard {
        Ok(_) => {}
        Err(_) => {
            serve_error(request, tiny_http::StatusCode(401), "Unauthorised");
            return;
        }
    };
    let body = ureq::serde_json::to_string(&TASK_BOARD.board_status().unwrap())
        .expect("can't serialize task board");
    let rendered = body.as_bytes();
    let response = Response::empty(tiny_http::StatusCode(200))
        .with_data(rendered, Some(rendered.len()))
        .with_header(
            tiny_http::Header::from_str("Content-Type: application/json")
                .expect("This should never fail"),
        );
    dispatch_response(request, response);
}

fn handle_telemetry(request: Request, auth_guard: AuthGuard<ValidUser>) {
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
    let rendered = TEMPLATES.render("telemetry.html.tera", &context);
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
        "SELECT ts, item_id, product_url, item_id_2, product_url_2, chip_id, uuid_number, bat_voltage, boot_code, error_code, return_code, write_bytes, remote_addr 
        FROM telemetry 
        ORDER BY ts DESC
        LIMIT $1 OFFSET $2", &[&limit, &offset])?;
    transaction.commit()?;
    CONNECTION_POOL.release_client(dbclient);
    let mut event_log: Vec<TelemetryRecord> = Vec::new();
    for row in records {
        let record = TelemetryRecord {
            ts: row.get(0),
            item_id: row.get(1),
            product_url: row.get(2),
            item_id_2: row.get(3),
            product_url_2: row.get(4),
            chip_id: row.get(5),
            uuid_number: row.get(6),
            bat_voltage: row.get(7),
            boot_code: row.get(8),
            error_code: row.get(9),
            return_code: row.get(10),
            write_bytes: row.get(11),
            remote_addr: row.get(12),
        };
        event_log.push(record);
    }
    let event_log = ureq::json!({
        "data": ureq::serde_json::to_value(&event_log)?,
        "recordsFiltered": records_total,
        "recordsTotal": records_total,
        "draw": Some(draw),
    });
    let body = ureq::serde_json::to_string(&event_log)?;
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
    let (nwidth, nheight) = match data.len() {
        134400 => (350, 261),
        67200 => (175, 261),
        _ => unreachable!(),
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
    let file = match File::open(&file_path) {
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
    if response
        .headers()
        .iter()
        .find(|header| header.field.equiv("Content-Type"))
        .is_none()
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
