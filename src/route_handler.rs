use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json;

use crate::{
    database::CONNECTION_POOL,
    google_oauth::{AuthGuard, ValidUser, request_token, revoke_token},
    gphotos_api::{MediaItem, MediaMetadata, PickedMediaItem, PickingSession, get_photo},
    image_proc::{decode_image, encode_image},
    model::{AppState, TokenClaims},
    session_mgr::SESSION_MGR,
    task_mgr::{Action, Status, TASK_BOARD, Task, TaskData, TaskQueue},
    template_mgr::TEMPLATES,
};

use image::imageops::FilterType;
use jsonwebtoken::{EncodingKey, Header as JWTHeader, encode};
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
    router.add("/frame_admin/sync_progress", "sync_progress".to_string());
    router.add("/frame_admin/monitor", "monitor".to_string());
    router.add("/frame_admin/album_data", "album_data".to_string());
    router.add("/frame_admin/manage", "manage".to_string());
    router.add("/frame_admin/telemetry_data", "telemetry_data".to_string());
    router.add("/frame_admin/image/:id", "image".to_string());
    let matched = match router.recognize(url) {
        Ok(m) => m,
        Err(_) => {
            serve_static_file(request, url);
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
            handle_oauth_logout(app_data, request);
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
        "sync_progress" => {
            handle_sync_progress(request, auth_guard);
        }
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
    let next_uri = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Referer"))
        .map(|h| safe_next_uri(h.value.as_str()))
        .unwrap_or_else(|| "/frame_admin/monitor".to_string());
    let (session_id, session_err) = match SESSION_MGR.get_session_id(&request) {
        Ok(session_id) => (session_id, None),
        Err(e) => {
            log::info!("(handle_login) session error: {:?}", e);
            (SESSION_MGR.create_session(), Some(e))
        }
    };
    SESSION_MGR.set_session_data(&session_id, "next_uri", &next_uri);
    let env = app_data.env.lock().unwrap_or_else(|e| e.into_inner());
    let jwt_max_age = env.jwt_max_age;
    let cookie_secure = env.cookie_secure;
    drop(env);
    let mut response = Response::empty(tiny_http::StatusCode(302));
    response.add_header(Header::from_str("Location: authorise").expect("This should never fail"));
    response.add_header(set_cookie_header(
        "session",
        &session_id,
        "/frame_admin/oauth",
        jwt_max_age,
        cookie_secure,
        "Lax",
    ));
    if let Some(e) = session_err {
        log::debug!(
            "(handle_login) proceeding with new session after error: {:?}",
            e
        );
    }
    dispatch_response(request, response);
    Ok(())
}

fn handle_oauth_logout(app_data: AppState, request: Request) {
    // Always clear the auth cookies, even when the current token is missing or
    // expired, so a user with a stale session can still log out cleanly.
    let cookie_secure = app_data.env.lock().unwrap_or_else(|e| e.into_inner()).cookie_secure;
    let mut response = Response::empty(tiny_http::StatusCode(302));
    response.add_header(set_cookie_header("token", "", "/", -1, cookie_secure, "Strict"));
    response.add_header(set_cookie_header(
        "session",
        "",
        "/frame_admin/oauth",
        -1,
        cookie_secure,
        "Lax",
    ));
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
    let env = app_data.env.lock().unwrap_or_else(|e| e.into_inner());
    let google_oauth_client_id = &env.google_oauth_client_id.to_string();
    let google_oauth_redirect_url = &env.google_oauth_redirect_url.to_string();
    drop(env);
    let mut url =
        Url::parse("https://accounts.google.com/o/oauth2/v2/auth").expect("This should never fail");
    url.query_pairs_mut()
        .append_pair("client_id", google_oauth_client_id)
        .append_pair("redirect_uri", google_oauth_redirect_url)
        .append_pair("response_type", "code")
        .append_pair(
            "scope",
            "openid profile email https://www.googleapis.com/auth/photospicker.mediaitems.readonly",
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
    // The state is set during /oauth/authorise; if it's absent the callback was
    // reached out of order. Redirect to login rather than panicking the worker.
    let session_state = match SESSION_MGR.get_session_data(&session_id, "state") {
        Some(state) => state,
        None => {
            log::warn!("(handle_oauth_google) no state in session; restarting login");
            redirect_to(request, "/frame_admin/oauth/login");
            return;
        }
    };
    let session_next_uri = safe_next_uri(
        &SESSION_MGR
            .get_session_data(&session_id, "next_uri")
            .unwrap_or_default(),
    );
    let params = extract_params(request.url());
    let state = params.get("state");
    let code = params.get("code");
    let error = params.get("error");
    if error.is_some() || state != Some(&session_state) || code.is_none() {
        log::error!("oauth2 error or state mismatch or code not found");
        redirect_to(request, "/frame_admin?error=oauth");
        return;
    }
    let code = code.expect("Code should be present");
    let token_response = request_token(&app_data, code.as_str());
    let user_id = match token_response {
        Ok(user_id) => user_id,
        Err(e) => {
            let message = e.to_string();
            log::error!("oauth2 error: {}", message);
            // Distinguish "you may not sign in" from a backend failure so the
            // login page can show a meaningful message.
            if message.contains("not authorised") {
                redirect_to(request, "/frame_admin?error=unauthorised");
            } else {
                redirect_to(request, "/frame_admin?error=oauth");
            }
            return;
        }
    };
    let current_datetime = Utc::now();
    let env = app_data.env.lock().unwrap_or_else(|e| e.into_inner());
    let jwt_secret = env.jwt_secret.to_owned();
    let jwt_max_age = env.jwt_max_age;
    let cookie_secure = env.cookie_secure;
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
    response.add_header(set_cookie_header(
        "token",
        &token,
        "/",
        jwt_max_age,
        cookie_secure,
        "Strict",
    ));
    response.add_header(
        tiny_http::Header::from_bytes(&b"Location"[..], session_next_uri.as_bytes())
            .expect("This should never fail"),
    );
    dispatch_response(request, response);
}

fn handle_oauth_revoke(app_data: AppState, request: Request, auth_guard: AuthGuard<ValidUser>) {
    let auth_guard = match auth_guard {
        Ok(auth_guard) => auth_guard,
        Err(_) => {
            redirect_to(request, "/frame_admin/oauth/login");
            return;
        }
    };
    let cookie_secure = app_data.env.lock().unwrap_or_else(|e| e.into_inner()).cookie_secure;
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
    response.add_header(set_cookie_header("token", "", "/", -1, cookie_secure, "Strict"));
    response.add_header(set_cookie_header(
        "session",
        "",
        "/frame_admin/oauth",
        -1,
        cookie_secure,
        "Lax",
    ));
    dispatch_response(request, response);
}

fn handle_index(app_data: AppState, request: Request, auth_guard: AuthGuard<ValidUser>) {
    let context = match auth_guard {
        Ok(_auth_guard) => {
            let env = app_data.env.lock().unwrap_or_else(|e| e.into_inner());
            drop(env);
            let mut response = Response::empty(tiny_http::StatusCode(302));
            response.add_header(
                tiny_http::Header::from_bytes(&b"Location"[..], "/frame_admin/monitor")
                    .expect("This should never fail"),
            );
            dispatch_response(request, response);
            return;
        }
        Err(_) => {
            let mut context = Context::new();
            // Surface a friendly reason when the user was bounced back from a failed
            // login (e.g. an unauthorised email or an OAuth error).
            if let Some(error) = extract_params(request.url()).get("error") {
                let message = match error.as_str() {
                    "unauthorised" => {
                        "Your account is not authorised to access this application."
                    }
                    "oauth" => "Sign-in failed. Please try again.",
                    _ => "Sign-in failed. Please try again.",
                };
                context.insert("error", message);
            }
            context
        }
    };
    let rendered = TEMPLATES.render("index.html.tera", &context);
    let response = Response::from_data(rendered);
    dispatch_response(request, response);
}

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

fn handle_manage(mut request: Request, auth_guard: AuthGuard<ValidUser>) {
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

    if let Some(header) = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("manage-action"))
    {
        match header.value.as_str() {
            "delete" => {
                // Bound the body so a client can't force unbounded memory use.
                const MAX_DELETE_BODY: u64 = 1 << 20; // 1 MiB
                let mut body = String::new();
                if let Err(e) = request
                    .as_reader()
                    .take(MAX_DELETE_BODY)
                    .read_to_string(&mut body)
                {
                    log::error!(
                        "(handle_manage) failed to read delete request body: {:?}",
                        e
                    );
                    serve_error(request, tiny_http::StatusCode(400), "Invalid request body");
                    return;
                }

                #[derive(Deserialize)]
                struct DeletePayload {
                    photos: Vec<String>,
                }

                let payload: DeletePayload = match serde_json::from_str(&body) {
                    Ok(p) => p,
                    Err(e) => {
                        log::error!("(handle_manage) delete payload parse error: {:?}", e);
                        serve_error(request, tiny_http::StatusCode(400), "Invalid JSON payload");
                        return;
                    }
                };

                let mut ids: HashSet<String> = payload
                    .photos
                    .into_iter()
                    .filter(|s| !s.trim().is_empty())
                    .collect();

                if ids.is_empty() {
                    serve_error(request, tiny_http::StatusCode(400), "No photo ids provided");
                    return;
                }

                TASK_BOARD.reset();
                let queue = Arc::new(TaskQueue::new());
                let mut task_count = 0;
                for id in ids.drain() {
                    queue.push(Task {
                        id: TASK_BOARD.add_task(Action::Remove),
                        data: TaskData::String(id),
                    });
                    task_count += 1;
                }

                let threads = min(task_count, 4);
                for _ in 0..threads {
                    let queue = queue.clone();
                    thread::spawn(move || {
                        loop {
                            if queue.is_empty() {
                                log::info!("(handle_manage) delete queue is empty, nothing to do");
                                break;
                            }
                            let task = queue.pop();
                            TASK_BOARD.set_board_data(task.id, Status::InProgress);
                            let mut dbclient = match CONNECTION_POOL.get_client() {
                                Ok(dbclient) => dbclient,
                                Err(err) => {
                                    log::error!("(handle_manage) delete: {err}");
                                    TASK_BOARD.set_board_data(task.id, Status::Failed);
                                    continue;
                                }
                            };
                            let mut success = true;
                            match task.data {
                                TaskData::String(item_id) => {
                                    if let Err(err) = dbclient.execute(
                                        "DELETE FROM album WHERE item_id = $1",
                                        &[&item_id],
                                    ) {
                                        log::error!(
                                            "(handle_manage) db delete error for {}: {:?}",
                                            item_id,
                                            err
                                        );
                                        TASK_BOARD.set_board_data(task.id, Status::Failed);
                                        success = false;
                                    }
                                }
                                _ => {
                                    log::error!(
                                        "(handle_manage) unexpected task data in delete flow"
                                    );
                                    TASK_BOARD.set_board_data(task.id, Status::Failed);
                                    success = false;
                                }
                            }
                            CONNECTION_POOL.release_client(dbclient);
                            if success {
                                TASK_BOARD.set_board_data(task.id, Status::Completed);
                            }
                        }
                    });
                }
                log::info!(
                    "(handle_manage) dispatched {} delete thread(s) for {} items",
                    threads,
                    task_count
                );
                let body = match serde_json::to_string(&serde_json::json!({ "queued": task_count }))
                {
                    Ok(b) => b,
                    Err(e) => {
                        log::error!("(handle_manage) serialize error: {:?}", e);
                        serve_error(request, tiny_http::StatusCode(500), "Internal server error");
                        return;
                    }
                };
                let response = Response::empty(tiny_http::StatusCode(202))
                    .with_data(body.as_bytes(), Some(body.len()))
                    .with_header(
                        tiny_http::Header::from_str("Content-Type: application/json")
                            .expect("This should never fail"),
                    );
                dispatch_response(request, response);
                return;
            }
            _ => {
                serve_error(request, tiny_http::StatusCode(400), "Invalid manage action");
                return;
            }
        }
    }

    if let Some(header) = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("picker-session"))
    {
        let value = header.value.as_str();
        let mut parts = value.splitn(2, ':');
        let action = parts.next().unwrap_or("");
        let session_id = parts.next();

        fn respond_json<T: serde::Serialize>(
            request: Request,
            result: Result<T, impl std::fmt::Debug>,
        ) {
            // An upstream Google API failure must return an error response, not
            // panic the worker thread.
            let value = match result {
                Ok(v) => v,
                Err(e) => {
                    log::error!("(handle_manage) upstream API call failed: {:?}", e);
                    serve_error(
                        request,
                        tiny_http::StatusCode(502),
                        "Upstream request failed",
                    );
                    return;
                }
            };
            let body = match serde_json::to_string(&value) {
                Ok(b) => b,
                Err(e) => {
                    log::error!("(handle_manage) serialize error: {:?}", e);
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

        match action {
            "create" => {
                respond_json(
                    request,
                    PickingSession::create(&auth_guard.user.credentials.access_token),
                );
            }
            "delete" => {
                if let Some(session_id) = session_id {
                    let session_id = session_id.to_string();
                    respond_json(
                        request,
                        PickingSession::delete(
                            &auth_guard.user.credentials.access_token,
                            &session_id,
                        ),
                    );
                }
            }
            "poll" => {
                if let Some(session_id) = session_id {
                    let session_id = session_id.to_string();
                    let result = PickingSession::poll(
                        &auth_guard.user.credentials.access_token,
                        &session_id,
                    );
                    if let Ok(ref poll_response) = result {
                        if poll_response.mediaItemsSet {
                            log::info!(
                                "Media items have been set for picking session {}",
                                session_id
                            );
                            let list = PickingSession::list_picked(
                                &auth_guard.user.credentials.access_token,
                                &session_id,
                            );
                            if let Ok(ref media_items) = list {
                                // Avoid logging item base URLs/filenames; a count
                                // is enough for operational visibility.
                                log::info!("Media items picked: {} item(s)", media_items.len());
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
                                    let access_token =
                                        auth_guard.user.credentials.access_token.clone();
                                    let mut dbclient = match CONNECTION_POOL.get_client() {
                                        Ok(c) => c,
                                        Err(e) => {
                                            log::error!("(handle_manage) DB pool error: {:?}", e);
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
                                            log::error!("(handle_manage) DB query error: {:?}", e);
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
                                            if let Some(picked_item) = picked_map.get(media_item_id)
                                            {
                                                let media_item = picked_to_media_item(picked_item);
                                                queue.push(Task {
                                                    id: TASK_BOARD.add_task(Action::Add),
                                                    data: TaskData::MediaItemWithToken(
                                                        media_item,
                                                        access_token.clone(),
                                                    ),
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
                                                thread::spawn(move || {
                                                    loop {
                                                        if queue.is_empty() {
                                                            log::info!(
                                                                "(handle_manage) queue is empty, nothing to do"
                                                            );
                                                            break;
                                                        }
                                                        let task = queue.pop();
                                                        TASK_BOARD.set_board_data(
                                                            task.id,
                                                            Status::InProgress,
                                                        );
                                                        let mut dbclient =
                                                            match CONNECTION_POOL.get_client() {
                                                                Ok(dbclient) => dbclient,
                                                                Err(err) => {
                                                                    log::error!(
                                                                        "(handle_manage): {err}"
                                                                    );
                                                                    TASK_BOARD.set_board_data(
                                                                        task.id,
                                                                        Status::Failed,
                                                                    );
                                                                    continue;
                                                                }
                                                            };
                                                        let mut success = true;
                                                        match task.data {
                                                            TaskData::MediaItemWithToken(
                                                                media_item,
                                                                token,
                                                            ) => {
                                                                log::info!(
                                                                    "(handle_manage) retrieving photo"
                                                                );
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
                                                                log::error!(
                                                                    "(handle_manage) unexpected remove task in manage flow"
                                                                );
                                                                TASK_BOARD.set_board_data(
                                                                    task.id,
                                                                    Status::Failed,
                                                                );
                                                                success = false;
                                                            }
                                                        }
                                                        CONNECTION_POOL.release_client(dbclient);
                                                        if success {
                                                            TASK_BOARD.set_board_data(
                                                                task.id,
                                                                Status::Completed,
                                                            );
                                                        }
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
                            let _ = PickingSession::delete(
                                &auth_guard.user.credentials.access_token,
                                &session_id,
                            );
                        }
                    }
                    respond_json(request, result);
                }
            }
            _ => {
                serve_error(
                    request,
                    tiny_http::StatusCode(400),
                    "Invalid picker-session action",
                );
            }
        }
        return;
    }

    let mut context = Context::new();
    context.insert("is_authenticated", &true);
    context.insert("current_page", "manage");
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
    let page: i64 = params
        .get("page")
        .and_then(|v| v.parse().ok())
        .filter(|p| *p > 0)
        .unwrap_or(1);
    let page_size: i64 = params
        .get("pageSize")
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|s| *s > 0)
        .map(|s| s.min(24))
        .unwrap_or(12);
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
        // Use stable ordering to avoid duplicates across pages when timestamps are equal.
        "SELECT item_id, ts, portrait FROM album ORDER BY ts DESC, item_id DESC LIMIT $1 OFFSET $2",
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
        let ts_iso =
            chrono::DateTime::<chrono::Utc>::from_timestamp(ts_secs, 0).map(|dt| dt.to_rfc3339());
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
    let _auth_guard = match auth_guard {
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
    context.insert("is_authenticated", &true);
    context.insert("current_page", "monitor");
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
    // Clamp pagination inputs. A negative OFFSET (e.g. ?start=-1) is rejected by
    // Postgres and previously surfaced as a 500 that also leaked a pooled
    // connection; bound LIMIT so a client can't request an unbounded result set.
    const MAX_PAGE_LEN: i64 = 1000;
    let offset = params
        .get("start")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|v| *v >= 0)
        .unwrap_or(0);
    let requested_limit = params
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
    // -1 is the DataTables "All" sentinel; otherwise require a sane positive page.
    let limit = if requested_limit == -1 {
        records_total
    } else {
        requested_limit.clamp(0, MAX_PAGE_LEN)
    };
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
            serve_error(request, tiny_http::StatusCode(404), "Not found");
            return Ok(());
        }
    };
    CONNECTION_POOL.release_client(dbclient);
    // Dimensions are inferred from the stored packed-pixel length. A row whose
    // data has any other length (corrupt, truncated, or from an older schema)
    // must not crash the worker: return 404 instead of panicking. This was a
    // remotely reachable, whole-server denial of service.
    let (nwidth, nheight) = match (is_thumb, data.len()) {
        (true, 134400) => (120, 90), // landscape thumbnail
        (true, 67200) => (90, 120),  // portrait thumbnail
        (false, 134400) => (350, 261),
        (false, 67200) => (175, 261),
        _ => {
            log::warn!(
                "(handle_image) unexpected data length {} for item {}",
                data.len(),
                image_id
            );
            serve_error(request, tiny_http::StatusCode(404), "Not found");
            return Ok(());
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

/// Send a 302 redirect to an internal path.
fn redirect_to(request: Request, location: &str) {
    let mut response = Response::empty(tiny_http::StatusCode(302));
    response.add_header(
        tiny_http::Header::from_bytes(&b"Location"[..], location.as_bytes())
            .expect("This should never fail"),
    );
    dispatch_response(request, response);
}

/// Validate a post-login redirect target. Only same-origin absolute paths are
/// allowed, preventing an attacker-controlled `Referer` from redirecting users
/// off-site after authentication. Anything else falls back to the monitor page.
fn safe_next_uri(candidate: &str) -> String {
    let trimmed = candidate.trim();
    if trimmed.starts_with('/')
        && !trimmed.starts_with("//")
        && !trimmed.contains(':')
        && !trimmed.contains('\\')
    {
        trimmed.to_string()
    } else {
        "/frame_admin/monitor".to_string()
    }
}

/// Build a `Set-Cookie` header, appending `Secure` when configured. Centralises the
/// cookie attributes so login/logout/callback/revoke stay consistent.
///
/// `same_site` should be `Strict` for the auth `token` cookie so it is never sent
/// on cross-site requests (this is the CSRF defence for the destructive
/// revoke/logout/manage routes), and `Lax` for the short-lived OAuth `session`
/// cookie, which must survive Google's cross-site redirect back to the callback.
fn set_cookie_header(
    name: &str,
    value: &str,
    path: &str,
    max_age: i64,
    secure: bool,
    same_site: &str,
) -> Header {
    let secure_attr = if secure { " Secure;" } else { "" };
    Header::from_str(&format!(
        "Set-Cookie: {name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite={same_site};{secure_attr}"
    ))
    .expect("This should never fail")
}

/// Serve a file from the `public/` directory. `normalised_path` is the parsed,
/// dot-segment-collapsed request path (produced in `route_request`), so encoded
/// or literal `..` traversal has already been neutralised; on top of that we
/// canonicalise the resolved path and require it to stay inside `public/`,
/// which also defeats symlink escapes. Without this, the previous handler
/// concatenated raw request input onto `public/` and happily served
/// `../secrets/config.json`, `../src/*`, and arbitrary host files.
fn serve_static_file(request: Request, normalised_path: &str) {
    let file_name = normalised_path.trim_start_matches("/frame_admin/");
    // Reject anything that isn't a simple relative path segment sequence.
    if file_name.is_empty()
        || file_name.starts_with('/')
        || file_name.contains('\\')
        || file_name.contains('\0')
        || file_name.split('/').any(|seg| seg == ".." || seg == "." || seg.is_empty())
    {
        serve_error(request, tiny_http::StatusCode(404), "File not found");
        return;
    }

    let public_root = match std::fs::canonicalize("public") {
        Ok(p) => p,
        Err(e) => {
            log::error!("(serve_static_file) cannot canonicalise public dir: {}", e);
            serve_error(request, tiny_http::StatusCode(404), "File not found");
            return;
        }
    };
    let candidate = match std::fs::canonicalize(public_root.join(file_name)) {
        Ok(p) => p,
        Err(_) => {
            serve_error(request, tiny_http::StatusCode(404), "File not found");
            return;
        }
    };
    // Final guard: the resolved, symlink-followed target must live under public/.
    if !candidate.starts_with(&public_root) || !candidate.is_file() {
        serve_error(request, tiny_http::StatusCode(404), "File not found");
        return;
    }

    let file = match File::open(&candidate) {
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

/// Baseline security response headers. The CSP is scoped to the CDN origins the
/// templates actually use; `'unsafe-inline'` is required because the templates
/// embed inline `<script>`/`<style>` blocks.
fn security_headers() -> Vec<Header> {
    const CSP: &str = "default-src 'self'; \
script-src 'self' 'unsafe-inline' https://cdn.datatables.net https://cdnjs.cloudflare.com https://code.jquery.com; \
style-src 'self' 'unsafe-inline' https://cdn.datatables.net https://fonts.googleapis.com; \
img-src 'self' data:; \
font-src 'self' https://fonts.gstatic.com; \
connect-src 'self'; \
object-src 'none'; \
base-uri 'self'; \
form-action 'self'; \
frame-ancestors 'none'";
    [
        ("Content-Security-Policy", CSP),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
    ]
    .iter()
    .filter_map(|(k, v)| Header::from_bytes(k.as_bytes(), v.as_bytes()).ok())
    .collect()
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
    // Baseline security headers applied to every response. The CSP allows the
    // handful of CDN origins the dashboard templates load from, plus the inline
    // scripts/styles those templates rely on; it blocks framing and restricts
    // everything else to same-origin.
    for header in security_headers() {
        response.add_header(header);
    }
    log_request(
        &request,
        response.status_code().0,
        response.data_length().unwrap_or(0),
    );
    if let Err(e) = request.respond(response) {
        log::error!("(dispatch_reponse) could not send response: {}", e);
    }
}
