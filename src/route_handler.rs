use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    config::random_token,
    database::CONNECTION_POOL,
    google_oauth::{AuthGuard, ValidUser, request_token, revoke_token},
    gphotos_api::{MediaItem, MediaMetadata, PickedMediaItem, PickingSession, get_photo},
    image_proc::{decode_image, encode_image},
    model::{AppState, TokenClaims},
    session_mgr::{
        OAUTH_SESSION_TTL_SECS, SESSION_COOKIE, SESSION_MGR, revoke_token_id, secure_cookies,
        token_cookie_name,
    },
    task_mgr::{Action, Status, TASK_BOARD, Task, TaskData, TaskQueue},
    template_mgr::TEMPLATES,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use image::imageops::FilterType;
use jsonwebtoken::{EncodingKey, Header as JWTHeader, encode};
use route_recognizer::{Params, Router};
use sha2::{Digest, Sha256};
use std::{
    cmp::min,
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, OnceLock},
    thread,
};
use tera::Context;
use tiny_http::{Header, Request, Response};
use url::Url;

const LOGIN_PATH: &str = "/frame_admin/oauth/login";
const SESSION_COOKIE_PATH: &str = "/frame_admin/oauth";

#[derive(Debug, Serialize, Deserialize)]
struct TelemetryRecord {
    ts: i64,
    item_id: Option<String>,
    item_id_2: Option<String>,
    bat_voltage: i32,
    boot_code: i32,
    /// Device error bitfield reported by the frame (bit 0 = low battery). The
    /// monitor page colours chart points and overlays a low-battery icon from
    /// it.
    error_code: i32,
    remote_addr: Vec<IpAddr>,
}

/// Whether the `telemetry` table (owned by the frame backend) still has its
/// `error_code` column. Probed once; deployments without it get `0` so the
/// monitor page degrades to "no markers" instead of a broken table.
static TELEMETRY_HAS_ERROR_CODE: OnceLock<bool> = OnceLock::new();

fn telemetry_has_error_code(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<bool, postgres::Error> {
    if let Some(present) = TELEMETRY_HAS_ERROR_CODE.get() {
        return Ok(*present);
    }
    let row = transaction.query_one(
        "SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'telemetry'
              AND column_name = 'error_code'
        )",
        &[],
    )?;
    let present: bool = row.get(0);
    if !present {
        log::warn!(
            "telemetry table has no error_code column; low-battery and error markers on the monitor page will not be shown"
        );
    }
    let _ = TELEMETRY_HAS_ERROR_CODE.set(present);
    Ok(present)
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
    // Every state-changing route is POST-only, and no POST is ever legitimately
    // made from another origin, so refuse cross-site POSTs before routing.
    if is_post(&request) && is_cross_site(&request) {
        log::warn!(
            "(route_request) rejected cross-site POST to {}",
            sanitise_log(url)
        );
        serve_error(request, tiny_http::StatusCode(403), "Forbidden");
        return;
    }
    let mut router = Router::new();
    router.add("/frame_admin", "index".to_string());
    router.add("/frame_admin/oauth/login", "oauth_login".to_string());
    router.add("/frame_admin/oauth/logout", "oauth_logout".to_string());
    // Kept as an alias of /oauth/login for old bookmarks.
    router.add("/frame_admin/oauth/authorise", "oauth_login".to_string());
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
            handle_oauth_login(app_data, request);
        }
        "oauth_logout" => {
            handle_oauth_logout(request, auth_guard);
        }
        "oauth_google" => {
            handle_oauth_google(app_data, request);
        }
        "oauth_revoke" => {
            handle_oauth_revoke(app_data, request, auth_guard);
        }
        "index" => {
            handle_index(request, auth_guard);
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
            handle_telemetry_data(request, auth_guard);
        }
        "image" => {
            handle_image(request, auth_guard, matched.params());
        }
        _ => {
            unreachable!("unreachable");
        }
    }
}

/// Start the Google sign-in handshake.
///
/// A *fresh* server-side session is always minted here — an existing `session`
/// cookie presented by the client is never adopted, so an attacker who managed
/// to plant a cookie could not pre-seed the handshake (session fixation). The
/// session holds three one-time secrets that the callback must match:
/// `state` (CSRF), a PKCE verifier (code interception) and an OIDC `nonce`
/// (id_token replay).
fn handle_oauth_login(app_data: AppState, request: Request) {
    let session_id = SESSION_MGR.create_session();
    let state = SESSION_MGR.generate_state();
    let code_verifier = random_token(64);
    let nonce = random_token(32);
    SESSION_MGR.set_session_data(&session_id, "state", &state);
    SESSION_MGR.set_session_data(&session_id, "pkce_verifier", &code_verifier);
    SESSION_MGR.set_session_data(&session_id, "oidc_nonce", &nonce);
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));

    let env = app_data.env.lock().unwrap_or_else(|e| e.into_inner());
    let google_oauth_client_id = env.google_oauth_client_id.clone();
    let google_oauth_redirect_url = env.google_oauth_redirect_url.clone();
    drop(env);
    let mut url =
        Url::parse("https://accounts.google.com/o/oauth2/v2/auth").expect("This should never fail");
    url.query_pairs_mut()
        .append_pair("client_id", &google_oauth_client_id)
        .append_pair("redirect_uri", &google_oauth_redirect_url)
        .append_pair("response_type", "code")
        .append_pair(
            "scope",
            "openid profile email https://www.googleapis.com/auth/photospicker.mediaitems.readonly",
        )
        .append_pair("access_type", "offline")
        // .append_pair("prompt", "consent") // Forces re-consent every time; guarantees a refresh token is returned
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256");
    let mut response = redirect(url.as_str());
    response.add_header(set_cookie_header(
        SESSION_COOKIE,
        &session_id,
        SESSION_COOKIE_PATH,
        OAUTH_SESSION_TTL_SECS as i64,
        secure_cookies(),
        "Lax",
    ));
    dispatch_response(request, response);
}

/// End the session. POST-only so a cross-site link can't log the user out, and
/// the token's `jti` is deny-listed so the cookie value itself stops working
/// rather than merely being forgotten by the browser.
fn handle_oauth_logout(request: Request, auth_guard: AuthGuard<ValidUser>) {
    if !is_post(&request) {
        serve_error(request, tiny_http::StatusCode(405), "Method not allowed");
        return;
    }
    if let Ok(valid) = &auth_guard {
        revoke_token_id(&valid.claims.jti, valid.claims.exp as u64);
    }
    let mut response = redirect("/frame_admin");
    clear_auth_cookies(&mut response);
    dispatch_response(request, response);
}

/// OAuth callback. The handshake secrets are consumed and the session discarded
/// on entry, so this URL — with its single-use code — cannot be replayed even
/// if it leaks from a browser history or proxy log.
fn handle_oauth_google(app_data: AppState, request: Request) {
    let session_id = match SESSION_MGR.get_session_id(&request) {
        Ok(session_id) => session_id,
        Err(e) => {
            log::warn!("(handle_oauth_google) session error: {:?}", e);
            serve_error(request, tiny_http::StatusCode(400), "Bad request");
            return;
        }
    };
    let state = SESSION_MGR.take_session_data(&session_id, "state");
    let code_verifier = SESSION_MGR.take_session_data(&session_id, "pkce_verifier");
    let nonce = SESSION_MGR.take_session_data(&session_id, "oidc_nonce");
    SESSION_MGR.remove_session(&session_id);
    let (Some(session_state), Some(code_verifier), Some(nonce)) = (state, code_verifier, nonce)
    else {
        log::warn!("(handle_oauth_google) handshake secrets missing; restarting login");
        finish_login(request, redirect(LOGIN_PATH));
        return;
    };
    let params = extract_params(request.url());
    let state = params.get("state");
    let code = params.get("code");
    let error = params.get("error");
    if error.is_some() || state != Some(&session_state) || code.is_none() {
        log::error!("oauth2 error or state mismatch or code not found");
        finish_login(request, redirect("/frame_admin?error=oauth"));
        return;
    }
    let code = code.expect("Code should be present");
    let user_id = match request_token(&app_data, code.as_str(), &code_verifier, &nonce) {
        Ok(user_id) => user_id,
        Err(e) => {
            let message = e.to_string();
            log::error!("oauth2 error: {}", message);
            // Distinguish "you may not sign in" from a backend failure so the
            // login page can show a meaningful message.
            if message.contains("not authorised") {
                finish_login(request, redirect("/frame_admin?error=unauthorised"));
            } else {
                finish_login(request, redirect("/frame_admin?error=oauth"));
            }
            return;
        }
    };
    let current_datetime = Utc::now();
    let env = app_data.env.lock().unwrap_or_else(|e| e.into_inner());
    let jwt_secret = env.jwt_secret.to_owned();
    let jwt_max_age = env.jwt_max_age;
    drop(env);
    let iat = current_datetime.timestamp() as usize;
    let exp = (current_datetime + Duration::seconds(jwt_max_age)).timestamp() as usize;
    let claims = TokenClaims {
        sub: user_id,
        exp,
        iat,
        jti: random_token(32),
    };
    let token = match encode(
        &JWTHeader::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    ) {
        Ok(token) => token,
        Err(e) => {
            log::error!("(handle_oauth_google) could not encode session token: {e}");
            serve_error(request, tiny_http::StatusCode(500), "Internal server error");
            return;
        }
    };
    let mut response = redirect("/frame_admin/monitor");
    // `Lax` rather than `Strict`: the callback is a cross-site navigation from
    // Google, and browsers may extend that cross-site-ness to the redirect that
    // follows it, which with `Strict` turns into a login loop. Lax still blocks
    // the cookie on every cross-site POST/fetch/subresource, and all mutating
    // routes are POST-only behind the Fetch-Metadata check in route_request.
    response.add_header(set_cookie_header(
        token_cookie_name(),
        &token,
        "/",
        jwt_max_age,
        secure_cookies(),
        "Lax",
    ));
    finish_login(request, response);
}

/// Every exit from the callback clears the handshake cookie.
fn finish_login(request: Request, mut response: Response<std::io::Empty>) {
    response.add_header(set_cookie_header(
        SESSION_COOKIE,
        "",
        SESSION_COOKIE_PATH,
        -1,
        secure_cookies(),
        "Lax",
    ));
    dispatch_response(request, response);
}

/// Disconnect the app from the user's Google account and end the session.
/// POST-only: this is destructive and must never be triggerable by a link.
fn handle_oauth_revoke(app_data: AppState, request: Request, auth_guard: AuthGuard<ValidUser>) {
    if !is_post(&request) {
        serve_error(request, tiny_http::StatusCode(405), "Method not allowed");
        return;
    }
    let valid = match auth_guard {
        Ok(valid) => valid,
        Err(_) => {
            redirect_to(request, LOGIN_PATH);
            return;
        }
    };
    if let Err(e) = revoke_token(&app_data, &valid.user) {
        log::error!("(handle_revoke) error revoking access/refresh token, {}", e);
        serve_error(
            request,
            tiny_http::StatusCode(500),
            "Internal server error: error revoking credentials",
        );
        return;
    }
    revoke_token_id(&valid.claims.jti, valid.claims.exp as u64);
    let mut response = redirect("/frame_admin");
    clear_auth_cookies(&mut response);
    dispatch_response(request, response);
}

fn handle_index(request: Request, auth_guard: AuthGuard<ValidUser>) {
    let context = match auth_guard {
        Ok(_auth_guard) => {
            redirect_to(request, "/frame_admin/monitor");
            return;
        }
        Err(_) => {
            let mut context = Context::new();
            // Surface a friendly reason when the user was bounced back from a failed
            // login (e.g. an unauthorised email or an OAuth error).
            if let Some(error) = extract_params(request.url()).get("error") {
                let message = match error.as_str() {
                    "unauthorised" => "Your account is not authorised to access this application.",
                    "oauth" => "Sign-in failed. Please try again.",
                    _ => "Sign-in failed. Please try again.",
                };
                context.insert("error", message);
            }
            context
        }
    };
    render_page(request, "index.html.tera", context);
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

/// Google picker session ids are used as a URL path segment when talking to
/// the Photos Picker API, so only allow URL-unreserved characters.
fn is_valid_picker_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
}

fn handle_manage(mut request: Request, auth_guard: AuthGuard<ValidUser>) {
    let manage_action = header_value(&request, "manage-action").map(str::to_owned);
    let picker_session = header_value(&request, "picker-session").map(str::to_owned);
    let is_api_call = manage_action.is_some() || picker_session.is_some();

    let auth_guard = match auth_guard {
        Ok(auth_guard) => auth_guard,
        Err(_) => {
            if is_api_call {
                serve_error(request, tiny_http::StatusCode(401), "Unauthorised");
            } else {
                redirect_to(request, LOGIN_PATH);
            }
            return;
        }
    };
    // The page itself is a GET; every action on it changes state and is POST-only.
    if is_api_call != is_post(&request) {
        serve_error(request, tiny_http::StatusCode(405), "Method not allowed");
        return;
    }

    if let Some(action) = manage_action {
        match action.as_str() {
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
                                            sanitise_log(&item_id),
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

    if let Some(value) = picker_session {
        let mut parts = value.splitn(2, ':');
        let action = parts.next().unwrap_or("");
        let session_id = parts.next();
        if let Some(id) = session_id
            && !is_valid_picker_session_id(id)
        {
            serve_error(
                request,
                tiny_http::StatusCode(400),
                "Invalid picker session id",
            );
            return;
        }

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
                } else {
                    serve_error(
                        request,
                        tiny_http::StatusCode(400),
                        "Missing picker session id",
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
                    if let Ok(ref poll_response) = result
                        && poll_response.mediaItemsSet
                    {
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
                                let access_token = auth_guard.user.credentials.access_token.clone();
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
                                        if let Some(picked_item) = picked_map.get(media_item_id) {
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
                                                    let mut dbclient = match CONNECTION_POOL
                                                        .get_client()
                                                    {
                                                        Ok(dbclient) => dbclient,
                                                        Err(err) => {
                                                            log::error!("(handle_manage): {err}");
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
                    respond_json(request, result);
                } else {
                    serve_error(
                        request,
                        tiny_http::StatusCode(400),
                        "Missing picker session id",
                    );
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
    render_page(request, "manage.html.tera", context);
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
    // JSON endpoint: answer 401 rather than redirecting, so the page script can
    // detect an expired session and send the user to login itself.
    if auth_guard.is_err() {
        serve_error(request, tiny_http::StatusCode(401), "Unauthorised");
        return;
    }

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
        // Percent-encode the id in the URL we hand back; ids come from the
        // database and must never be able to change the path they land on.
        let encoded_id: String = url::form_urlencoded::byte_serialize(id.as_bytes()).collect();
        items.push(serde_json::json!({
            "id": id,
            "thumbUrl": format!("/frame_admin/image/{}?size=thumb", encoded_id),
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
    if auth_guard.is_err() {
        redirect_to(request, LOGIN_PATH);
        return;
    }
    let mut context = Context::new();
    context.insert("is_authenticated", &true);
    context.insert("current_page", "monitor");
    render_page(request, "monitor.html.tera", context);
}

fn handle_telemetry_data(request: Request, auth_guard: AuthGuard<ValidUser>) {
    if auth_guard.is_err() {
        serve_error(request, tiny_http::StatusCode(401), "Unauthorised");
        return;
    }
    let params = extract_params(request.url());
    // Any DB failure becomes a proper 500 with the usual headers rather than
    // tiny_http's bare fallback response.
    let body = match telemetry_json(&params) {
        Ok(body) => body,
        Err(e) => {
            log::error!("(handle_telemetry_data) {e}");
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

fn telemetry_json(params: &HashMap<String, String>) -> Result<String, Box<dyn std::error::Error>> {
    // Clamp pagination inputs. A negative OFFSET (e.g. ?start=-1) is rejected by
    // Postgres and previously surfaced as a 500 that also leaked a pooled
    // connection; bound LIMIT so a client can't request an unbounded result set.
    const MAX_PAGE_LEN: i64 = 1000;
    // Ceiling for the DataTables "All" option, so one request can't pull the
    // whole table into the container's memory limit.
    const MAX_ALL_ROWS: i64 = 10_000;
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
        records_total.min(MAX_ALL_ROWS)
    } else {
        requested_limit.clamp(0, MAX_PAGE_LEN)
    };
    // The only interpolated fragment is one of two fixed literals chosen by the
    // schema probe; user input still travels exclusively through $1/$2.
    let error_code_expr = if telemetry_has_error_code(&mut transaction)? {
        "error_code::int"
    } else {
        "0::int"
    };
    let query = format!(
        "SELECT ts, item_id, item_id_2, bat_voltage, boot_code, remote_addr, {error_code_expr} AS error_code
        FROM telemetry
        ORDER BY ts DESC
        LIMIT $1 OFFSET $2"
    );
    let records = transaction.query(&query, &[&limit, &offset])?;
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
            error_code: row.get(6),
        };
        event_log.push(record);
    }
    let event_log = serde_json::json!({
        "data": serde_json::to_value(&event_log)?,
        "recordsFiltered": records_total,
        "recordsTotal": records_total,
        "draw": Some(draw),
    });
    Ok(serde_json::to_string(&event_log)?)
}

fn handle_image(request: Request, auth_guard: AuthGuard<ValidUser>, params: &Params) {
    if auth_guard.is_err() {
        serve_error(request, tiny_http::StatusCode(401), "Unauthorised");
        return;
    }
    // Path parameters arrive percent-encoded; decode so the lookup matches the
    // stored id (the query itself is parameterised, so no injection risk).
    let image_id = match params.find("id") {
        Some(image_id) => percent_decode(image_id),
        None => {
            serve_error(request, tiny_http::StatusCode(404), "Not found");
            return;
        }
    };
    let query_params = extract_params(request.url());
    let is_thumb = matches!(query_params.get("size"), Some(v) if v == "thumb");
    let jpeg = match render_image(&image_id, is_thumb) {
        Ok(Some(jpeg)) => jpeg,
        Ok(None) => {
            serve_error(request, tiny_http::StatusCode(404), "Not found");
            return;
        }
        Err(e) => {
            log::error!("(handle_image) {} : {e}", sanitise_log(&image_id));
            serve_error(request, tiny_http::StatusCode(500), "Internal server error");
            return;
        }
    };
    let mut response = Response::from_data(jpeg);
    response.add_header(
        tiny_http::Header::from_str("Content-Type: image/jpeg").expect("This should never fail"),
    );
    // Album images are the user's own photos; let the browser keep them briefly
    // (private cache only) so paging through the album doesn't re-render every
    // thumbnail.
    response.add_header(
        tiny_http::Header::from_str("Cache-Control: private, max-age=600")
            .expect("This should never fail"),
    );
    dispatch_response(request, response);
}

/// Load, decode and re-encode an album image. `Ok(None)` means no such image
/// (or an unusable blob, which is deliberately indistinguishable to a client).
fn render_image(
    image_id: &str,
    is_thumb: bool,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut dbclient = CONNECTION_POOL.get_client()?;
    let data: Vec<u8> = match dbclient
        .query("SELECT data FROM album WHERE item_id = $1", &[&image_id])?
        .first()
        .and_then(|row| row.get(0))
    {
        Some(data) => data,
        None => return Ok(None),
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
                "(render_image) unexpected data length {} for item {}",
                data.len(),
                sanitise_log(image_id)
            );
            return Ok(None);
        }
    };
    let dynamic_image = decode_image(data)?;
    let resized_dynamic_image = dynamic_image.resize_to_fill(nwidth, nheight, FilterType::Lanczos3);
    let mut buf = std::io::Cursor::new(Vec::new());
    resized_dynamic_image.write_to(&mut buf, image::ImageFormat::Jpeg)?;
    Ok(Some(buf.into_inner()))
}

/// Parse the query string with proper percent-decoding (and `+` as space).
fn extract_params(url: &str) -> HashMap<String, String> {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn percent_decode(value: &str) -> String {
    Url::parse(&format!("http://localhost/{value}"))
        .ok()
        .and_then(|u| {
            u.path_segments()
                .and_then(|mut segments| segments.next().map(str::to_owned))
        })
        .map(|segment| {
            url::form_urlencoded::parse(segment.replace('+', "%2B").as_bytes())
                .map(|(k, v)| format!("{k}{v}"))
                .collect::<String>()
        })
        .unwrap_or_else(|| value.to_string())
}

fn is_post(request: &Request) -> bool {
    request.method().as_str() == "POST"
}

fn header_value<'a>(request: &'a Request, name: &'static str) -> Option<&'a str> {
    request
        .headers()
        .iter()
        .find(|header| header.field.equiv(name))
        .map(|header| header.value.as_str())
}

/// CSRF guard for state-changing requests. Modern browsers attach
/// `Sec-Fetch-Site` to every request; anything other than `same-origin` (or a
/// user-initiated `none`) is refused. Clients without Fetch Metadata fall back
/// to comparing `Origin` against `Host`. A request with neither header is not a
/// browser-initiated cross-site request (browsers always send `Origin` on POST).
fn is_cross_site(request: &Request) -> bool {
    if let Some(site) = header_value(request, "Sec-Fetch-Site") {
        return !matches!(
            site.trim().to_ascii_lowercase().as_str(),
            "same-origin" | "none"
        );
    }
    match (
        header_value(request, "Origin"),
        header_value(request, "Host"),
    ) {
        (Some(origin), Some(host)) => {
            let origin_host = Url::parse(origin.trim()).ok().and_then(|u| {
                u.host_str().map(|h| match u.port() {
                    Some(port) => format!("{h}:{port}"),
                    None => h.to_string(),
                })
            });
            origin_host.as_deref() != Some(host.trim())
        }
        _ => false,
    }
}

fn redirect(location: &str) -> Response<std::io::Empty> {
    let mut response = Response::empty(tiny_http::StatusCode(302));
    response.add_header(
        tiny_http::Header::from_bytes(&b"Location"[..], location.as_bytes())
            .expect("This should never fail"),
    );
    response
}

/// Send a 302 redirect to an internal path.
fn redirect_to(request: Request, location: &str) {
    dispatch_response(request, redirect(location));
}

fn clear_auth_cookies<R>(response: &mut Response<R>)
where
    R: Read,
{
    let secure = secure_cookies();
    response.add_header(set_cookie_header(
        token_cookie_name(),
        "",
        "/",
        -1,
        secure,
        "Lax",
    ));
    response.add_header(set_cookie_header(
        SESSION_COOKIE,
        "",
        SESSION_COOKIE_PATH,
        -1,
        secure,
        "Lax",
    ));
}

/// Build a `Set-Cookie` header, appending `Secure` when configured. Centralises the
/// cookie attributes so login/logout/callback/revoke stay consistent.
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

/// Render an HTML page with a per-response CSP nonce so inline scripts run
/// without `'unsafe-inline'`: an injected `<script>` that lacks the nonce is
/// blocked by the browser.
fn render_page(request: Request, template: &str, mut context: Context) {
    let nonce = random_token(24);
    context.insert("csp_nonce", &nonce);
    let rendered = TEMPLATES.render(template, &context);
    let response = Response::from_data(rendered);
    dispatch_response_with_nonce(request, response, Some(&nonce));
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
        || file_name
            .split('/')
            .any(|seg| seg == ".." || seg == "." || seg.is_empty())
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
    let content_type = match file_name.split('.').next_back() {
        Some("html") => "text/html; charset=UTF-8",
        Some("css") => "text/css",
        Some("js") => "text/javascript",
        Some("json") => "application/json",
        Some("ico") => "image/x-icon",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        _ => "application/octet-stream",
    };
    let response = Response::from_file(file)
        .with_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes())
                .expect("This should never fail"),
        )
        .with_header(
            tiny_http::Header::from_str("Cache-Control: public, max-age=86400")
                .expect("This should never fail"),
        );
    dispatch_response(request, response);
}

/// OPTIONS on any path: 204 and the methods served. This is also what
/// `--healthcheck` probes, and its own requests stay out of the access log.
pub fn serve_options(request: Request) {
    let response = Response::empty(204).with_header(
        tiny_http::Header::from_str("Allow: GET, POST, OPTIONS").expect("This should never fail"),
    );
    if crate::healthcheck::is_self_probe(&request) {
        if let Err(e) = request.respond(response) {
            log::error!("(serve_options) could not send response: {}", e);
        }
        return;
    }
    dispatch_response(request, response);
}

pub fn serve_error(request: Request, status_code: tiny_http::StatusCode, message: &str) {
    let response = Response::new(
        status_code,
        vec![],
        message.as_bytes(),
        Some(message.len()),
        None,
    );
    dispatch_response(request, response);
}

/// Strip control characters (CR/LF, ANSI escapes, ...) and bound the length so
/// attacker-supplied request fields can't forge or mangle log lines.
fn sanitise_log(value: &str) -> String {
    value
        .chars()
        .take(512)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// The OAuth callback carries the single-use authorization code and the
/// anti-CSRF state in its query string; keep those out of the access log.
fn loggable_uri(uri: &str) -> String {
    let path = uri.split_once('?').map(|(p, _)| p).unwrap_or(uri);
    if path.trim_end_matches('/') == "/frame_admin/oauth/google" {
        format!("{}?<redacted>", sanitise_log(path))
    } else {
        sanitise_log(uri)
    }
}

pub fn log_request(request: &tiny_http::Request, status: u16, size: usize) {
    let remote_addr = request
        .remote_addr()
        .unwrap_or(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
        .ip();
    let date_time = chrono::Local::now().format("%d/%b/%Y:%H:%M:%S %z");
    let method = request.method();
    let uri = loggable_uri(request.url());
    let protocol = request.http_version();
    let referer = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("Referer"))
        .map(|header| sanitise_log(header.value.as_str()))
        .unwrap_or("-".to_string());
    let user_agent = request
        .headers()
        .iter()
        .find(|header| header.field.equiv("User-Agent"))
        .map(|header| sanitise_log(header.value.as_str()))
        .unwrap_or("-".to_string());
    println!(
        "{} [{}] \"{} {} {}\" {} {} \"{}\" \"{}\"",
        remote_addr, date_time, method, uri, protocol, status, size, referer, user_agent
    );
}

/// Baseline security response headers.
///
/// `script-src` is nonce-based: only inline scripts carrying this response's
/// nonce (and the pinned CDN hosts, which are additionally integrity-checked in
/// the templates) may run. Responses that render no page get no nonce and thus
/// allow no inline script at all. `style-src` still needs `'unsafe-inline'`
/// because DataTables/Highcharts set inline styles at runtime.
fn security_headers(nonce: Option<&str>) -> Vec<Header> {
    let script_src = match nonce {
        Some(nonce) => format!(
            "'self' 'nonce-{nonce}' https://cdn.datatables.net https://cdnjs.cloudflare.com https://code.jquery.com"
        ),
        None => "'self'".to_string(),
    };
    let csp = format!(
        "default-src 'self'; \
script-src {script_src}; \
style-src 'self' 'unsafe-inline' https://cdn.datatables.net https://fonts.googleapis.com; \
img-src 'self' data:; \
font-src 'self' https://fonts.gstatic.com; \
connect-src 'self'; \
object-src 'none'; \
base-uri 'self'; \
form-action 'self'; \
frame-ancestors 'none'"
    );
    let mut headers: Vec<(&str, String)> = vec![
        ("Content-Security-Policy", csp),
        ("X-Content-Type-Options", "nosniff".into()),
        ("X-Frame-Options", "DENY".into()),
        ("Referrer-Policy", "no-referrer".into()),
        ("Cross-Origin-Opener-Policy", "same-origin".into()),
        ("Cross-Origin-Resource-Policy", "same-origin".into()),
        (
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()".into(),
        ),
    ];
    if secure_cookies() {
        // Only meaningful (and only safe to emit) when the site is served over TLS.
        headers.push((
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains".into(),
        ));
    }
    headers
        .iter()
        .filter_map(|(k, v)| Header::from_bytes(*k, v.as_str()).ok())
        .collect()
}

fn dispatch_response<R>(request: Request, response: Response<R>)
where
    R: Read,
{
    dispatch_response_with_nonce(request, response, None);
}

fn dispatch_response_with_nonce<R>(request: Request, mut response: Response<R>, nonce: Option<&str>)
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
    // Everything this service produces is authenticated, per-user data unless a
    // handler says otherwise (static assets, album images): never let a shared
    // or browser cache keep it.
    if !response
        .headers()
        .iter()
        .any(|header| header.field.equiv("Cache-Control"))
    {
        response = response.with_header(
            tiny_http::Header::from_str("Cache-Control: no-store").expect("This should never fail"),
        );
    }
    for header in security_headers(nonce) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_params_decodes() {
        let p = extract_params("/x?code=4%2F0Abc&state=s+t&empty=&novalue");
        assert_eq!(p.get("code").map(String::as_str), Some("4/0Abc"));
        assert_eq!(p.get("state").map(String::as_str), Some("s t"));
        assert_eq!(p.get("empty").map(String::as_str), Some(""));
        assert_eq!(p.get("novalue").map(String::as_str), Some(""));
        assert!(extract_params("/x").is_empty());
    }

    #[test]
    fn percent_decode_round_trips_album_ids() {
        let id = "AF1Qip/O+x_y=z";
        let encoded: String = url::form_urlencoded::byte_serialize(id.as_bytes()).collect();
        assert_eq!(percent_decode(&encoded), id);
        assert_eq!(percent_decode("plain-id_123"), "plain-id_123");
    }

    #[test]
    fn sanitise_log_strips_control_chars() {
        assert_eq!(sanitise_log("a\r\nb\x1b[31mc"), "a??b?[31mc");
        assert_eq!(sanitise_log("x".repeat(600).as_str()).len(), 512);
    }

    #[test]
    fn callback_query_is_redacted_in_access_log() {
        assert_eq!(
            loggable_uri("/frame_admin/oauth/google?state=abc&code=4%2Fsecret"),
            "/frame_admin/oauth/google?<redacted>"
        );
        assert_eq!(
            loggable_uri("/frame_admin/album_data?page=2"),
            "/frame_admin/album_data?page=2"
        );
    }

    #[test]
    fn picker_session_id_charset() {
        assert!(is_valid_picker_session_id("abc-DEF_123.x~"));
        assert!(!is_valid_picker_session_id(""));
        assert!(!is_valid_picker_session_id("../sessions"));
        assert!(!is_valid_picker_session_id("a b"));
    }
}
