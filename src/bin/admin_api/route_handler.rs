use chrono::{Duration, Utc};
use frame::database::{AlbumRecord, TelemetryRecord, CONNECTION_POOL};
use uuid::Uuid;

use crate::{
    google_oauth::{get_google_user, request_token, ValidUser, Credentials, AuthError, AuthGuard},
    gphotos_api::{get_mediaitems, get_photo},
    image_proc::{decode_image, encode_image},
    model::{AppState, TokenClaims, User},
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
    env,
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

struct AppContext {
    app_data: AppState, 
    request: Request, 
    auth_guard: AuthGuard<ValidUser>
}

pub fn route_request(app_data: AppState, request: Request) {
    let url = match Url::parse("http://localhost:5000")
        .expect("This should never fail")
        .join(&request.url())
    {
        Ok(url) => url,
        Err(e) => {
            log::error!("[Error] (route_request) could not parse url: {}", e);
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
    router.add("/frame_admin/login", "login".to_string());
    router.add("/frame_admin/logout", "logout".to_string());
    router.add("/frame_admin/sync", "sync".to_string());
    router.add("/frame_admin/authorise", "authorise".to_string());
    router.add("/frame_admin/oauth2callback", "oauth2callback".to_string());
    router.add("/frame_admin/revoke", "revoke".to_string());
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
        "index" => {
            handle_index(app_data, request, auth_guard);
        }
        "login" => {
            if let Some(err) = handle_login(app_data, request).err() {
                log::error!("[Error] (route_request) login route failed: {}", err);
            };
        }
        "logout" => {
            handle_logout(app_data, request, auth_guard);
        }
        "sync" => {
            if let Some(err) = handle_sync(request).err() {
                log::error!("[Error] (route_request) sync route failed: {}", err);
            };
        }
        "authorise" => {
            handle_authorise(request);
        }
        "oauth2callback" => {
            handle_oauth2callback(app_data, request);
        }
        "telemetry" => {
            handle_telemetry(request, auth_guard);
        }
        "telemetry_data" => {
            if let Some(err) = handle_telemetry_data(request, auth_guard).err() {
                log::error!(
                    "[Error] (route_request) telemetry_data route failed: {}",
                    err
                );
            };
        }
        "revoke" => {
            handle_revoke(request);
        }
        "tasks" => {
            handle_task_board(request);
        }
        "image" => {
            if let Some(err) = handle_image(request, matched.params()).err() {
                log::error!("[Error] (route_request) image route failed: {}", err);
            };
        }
        _ => {
            assert!(false, "unreachable");
        }
    }
}

fn handle_login(app_data: AppState, request: Request) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(e) = SESSION_MGR.get_session_id(&request).err() {
        log::info!("[Info] (handle_login) session error: {:?}", e);
        println!("next_uri= {}", request.url());
        // let next_uri = request.url();
        let next_uri = "/frame_admin";
        let session_id: SessionID = SESSION_MGR.create_session();
        SESSION_MGR.set_session_data(&session_id, "next_uri", next_uri);
        let mut response = Response::empty(tiny_http::StatusCode(302));
        response
            .add_header(Header::from_str("Location: authorise").expect("This should never fail"));
        response.add_header(
            Header::from_str(&format!(
                "Set-Cookie: session={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax;",
                session_id,
                app_data.env.jwt_max_age * 60
            ))
            .expect("This should never fail"),
        );
        dispatch_response(request, response);
        return Ok(());
    }
    assert!(false, "I'm not sure that I should be able to get down here");
    let mut response = Response::empty(tiny_http::StatusCode(302));
    response
        .add_header(Header::from_str("Location: /frame_admin").expect("This should never fail"));
    dispatch_response(request, response);
    Ok(())
}

fn handle_logout(app_data: AppState, request: Request, auth_guard: AuthGuard<ValidUser>) {
    let mut response = Response::empty(tiny_http::StatusCode(302));
    match auth_guard {
        Ok(user) => {
            response.add_header(
                Header::from_str(&format!(
                    "Set-Cookie: token=; Path=/; Max-Age={}; HttpOnly; SameSite=Lax;",
                    Duration::seconds(-1)
                ))
                .expect("This should never fail"),
            );
            response.add_header(
                Header::from_str(&format!(
                    "Set-Cookie: session=; Path=/; Max-Age={}; HttpOnly; SameSite=Lax;",
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

fn handle_oauth2callback(app_data: AppState, request: Request) {
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
    // let scope = params.get("scope");
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
    let token_response = request_token(code.as_str(), &app_data);
    if token_response.is_err() {
        let message = token_response.err().unwrap().to_string();
        log::error!("oauth2 error: {}", message);
        serve_error(request, tiny_http::StatusCode(502), "Bad Gateway");
        return;
    }
    let token_response = token_response.expect("previously checked for error");
    let google_user = get_google_user(&token_response.access_token);
    if google_user.is_err() {
        let message = google_user.err().unwrap().to_string();
        log::error!("oauth2 error: {}", message);
        serve_error(request, tiny_http::StatusCode(502), "Bad Gateway");
        return;
    }
    let google_user = google_user.unwrap();

    let mut user_db = app_data.db.lock().unwrap();
    let email = google_user.email.to_lowercase();
    let user = user_db.iter_mut().find(|user| user.email == email);
    let user_id: String;
    if user.is_some() {
        let user = user.unwrap();
        user_id = user.id.to_owned().unwrap();
        user.email = email.to_owned();
        user.photo = google_user.picture;
        user.updatedAt = Some(Utc::now());
    } else {
        let datetime = Utc::now();
        let id = Uuid::new_v4();
        user_id = id.to_owned().to_string();
        let user_data = User {
            id: Some(id.to_string()),
            name: google_user.name,
            verified: google_user.verified_email,
            email,
            provider: "Google".to_string(),
            role: "user".to_string(),
            password: "".to_string(),
            photo: google_user.picture,
            createdAt: Some(datetime),
            updatedAt: Some(datetime),
        };

        user_db.push(user_data.to_owned());
    }

    let jwt_secret = app_data.env.jwt_secret.to_owned();
    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + Duration::minutes(app_data.env.jwt_max_age)).timestamp() as usize;
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
    .unwrap();

    let mut response = Response::empty(tiny_http::StatusCode(302));
    response.add_header(
        Header::from_str(&format!(
            "Set-Cookie: token={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax;",
            token,
            app_data.env.jwt_max_age * 60
        ))
        .expect("This should never fail"),
    );
    response.add_header(
        tiny_http::Header::from_bytes(&b"Location"[..], &session_next_uri[..])
            .expect("This should never fail"),
    );
    dispatch_response(request, response);
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
        log::error!("[Error] (dispatch_reponse) could not send response: {}", e);
    }
}

fn handle_image(request: Request, params: &Params) -> Result<(), Box<dyn std::error::Error>> {
    let image_id = match params.find("id") {
        Some(image_id) => image_id,
        None => {
            serve_error(request, tiny_http::StatusCode(404), "Not found");
            return Ok(());
        }
    };
    let mut dbclient = CONNECTION_POOL.get_client()?;
    let data: Vec<u8> = match dbclient
        .0
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
    let dynamic_image = decode_image(data)?;
    let resized_dynamic_image = dynamic_image.resize_exact(350, 261, FilterType::Lanczos3);
    let mut buf = std::io::Cursor::new(Vec::new());
    resized_dynamic_image.write_to(&mut buf, image::ImageFormat::Jpeg)?;
    let mut response = Response::from_data(buf.into_inner());
    response.add_header(
        tiny_http::Header::from_str("Content-Type: image/jpeg").expect("This should never fail"),
    );
    dispatch_response(request, response);
    Ok(())
}

fn handle_index(app_data: AppState, request: Request, auth_guard: AuthGuard<ValidUser>) {
    let context = match auth_guard {
        Ok(user) => {
            let mut context = Context::new();
            context.insert("user","logged_in");
            context
        },
        Err(_) => Context::new(),
    };
    let rendered = TEMPLATES.render("index.html.tera", &context);
    let response = Response::from_data(rendered);
    dispatch_response(request, response);
}

// TODO: UNWRAP (1)
fn handle_task_board(request: Request) {
    let body = ureq::serde_json::to_string(&TASK_BOARD.get_board()).unwrap();
    let rendered = body.as_bytes();
    let response = Response::empty(tiny_http::StatusCode(200))
        .with_data(rendered, Some(rendered.len()))
        .with_header(
            tiny_http::Header::from_str("Content-Type: application/json")
                .expect("This should never fail"),
        );
    dispatch_response(request, response);
}

fn handle_sync(request: Request) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(e) = SESSION_MGR.get_session_id(&request).err() {
        log::info!("[Info] (handle_sync) session error: {:?}", e);
        let next_uri = request.url();
        let session_id: SessionID = SESSION_MGR.create_session();
        SESSION_MGR.set_session_data(&session_id, "next_uri", next_uri);
        let mut response = Response::empty(tiny_http::StatusCode(302));
        response
            .add_header(Header::from_str("Location: authorise").expect("This should never fail"));
        response.add_header(
            Header::from_str(&format!("Set-Cookie: session={}", session_id))
                .expect("This should never fail"),
        );
        dispatch_response(request, response);
        return Ok(());
    }
    let credentials = Credentials::load();
    if credentials.expired() {
        log::info!("[Info] (handle_sync) access token is expired");
        credentials.refresh_access_token()?;
    }
    let access_token = match credentials.access_token.clone() {
        Some(access_token) => access_token,
        None => {
            log::error!("[Error] (handle_sync) access token is missing");
            serve_error(
                request,
                tiny_http::StatusCode(500),
                "Internal server error: missing access_token",
            );
            return Ok(());
        }
    };
    let mut dbclient = CONNECTION_POOL.get_client()?;
    let db_set = dbclient.get_mediaitems_set()?;
    CONNECTION_POOL.release_client(dbclient);
    let gg_mediaitems = get_mediaitems(&access_token)?;
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
        let rendered = TEMPLATES.render("sync.html.tera", &Context::new());
        let response = Response::from_data(rendered);
        dispatch_response(request, response);
        return Ok(());
    }
    let queue = Arc::new(TaskQueue::new());
    if new_set.len() > 0 {
        log::info!(
            "[Info] (handle_sync) found {} new media items",
            new_set.len()
        );
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
            "[Info] (handle_sync) found {} deleted media items",
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
                log::info!("[Info] (handle_sync) queue is empty, nothing to do");
                break;
            }
            let task = queue.pop();
            TASK_BOARD.set_board_data(task.id, Status::InProgress);
            let mut dbclient = match CONNECTION_POOL.get_client() {
                Ok(dbclient) => dbclient,
                Err(err) => {
                    log::error!("[Error] (handle_sync): {err}");
                    TASK_BOARD.set_board_data(task.id, Status::Failed);
                    continue;
                }
            };
            match task.data {
                TaskData::MediaItem(task_data) => {
                    log::info!("[Info] (handle_sync) retrieving photo");
                    match get_photo(&task_data)
                        .and_then(|data| {
                            log::info!("[Info] (handle_sync) encoding image");
                            Ok(encode_image(&data))
                        })
                        .and_then(|data| {
                            log::info!("[Info] (handle_sync) adding media item to db");
                            Ok(dbclient.add_record(AlbumRecord {
                                item_id: task_data.id,
                                product_url: task_data.productUrl,
                                ts: 0,
                                data,
                            }))
                        }) {
                        Ok(_) => {}
                        Err(err) => {
                            log::error!("[Error] (handle_sync): {err}");
                            TASK_BOARD.set_board_data(task.id, Status::Failed);
                        }
                    };
                }
                TaskData::String(task_data) => {
                    log::info!("[Info] (handle_sync) removing record from db");
                    match dbclient.remove_record(task_data) {
                        Ok(_) => {}
                        Err(err) => {
                            log::error!("[Error] (handle_sync): {err}");
                            TASK_BOARD.set_board_data(task.id, Status::Failed);
                        }
                    };
                }
            }
            CONNECTION_POOL.release_client(dbclient);
            TASK_BOARD.set_board_data(task.id, Status::Completed);
        });
    }
    log::info!("[Info] (handle_sync) {} sync thread(s) dispatched", threads);
    let rendered = TEMPLATES.render("sync.html.tera", &Context::new());
    let response = Response::from_data(rendered);
    dispatch_response(request, response);
    Ok(())
}

fn handle_authorise(request: Request) {
    let session_id = match SESSION_MGR.get_session_id(&request) {
        Ok(session_id) => session_id,
        Err(e) => {
            log::warn!("[Warn] (handle_authorise) session error: {:?}", e);
            serve_error(request, tiny_http::StatusCode(400), "Bad request");
            return;
        }
    };
    let state = SESSION_MGR.generate_state();
    SESSION_MGR.set_session_data(&session_id, "state", &state);
    let mut url =
        Url::parse("https://accounts.google.com/o/oauth2/v2/auth").expect("This should never fail");
    url.query_pairs_mut()
        .append_pair(
            "client_id",
            &env::var("GOOGLE_OAUTH_CLIENT_ID").expect("This should never fail"),
        )
        .append_pair(
            "redirect_uri",
            &env::var("GOOGLE_OAUTH_REDIRECT_URI").expect("This should never fail"),
        )
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

fn handle_oauth2callback_old(request: Request) {
    let session_id = match SESSION_MGR.get_session_id(&request) {
        Ok(session_id) => session_id,
        Err(e) => {
            log::warn!("[Warn] (handle_oauth2callback) session error: {:?}", e);
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
    // let scope = params.get("scope");
    let error = params.get("error");
    if error.is_some() || state != Some(&session_state) || code.is_none() {
        log::error!(
            "[Error] (handle_oauth2callback) oauth2 error or state mismatch or code not found"
        );
        serve_error(
            request,
            tiny_http::StatusCode(500),
            "Internal server error: oauth2 error",
        );
        return;
    }
    let credentials = Credentials::load();
    let code = code.expect("Code should be present");
    if credentials.retrieve_tokens(code).is_err() {
        log::error!("[Error] (handle_oauth2callback) error exchanging code for credentials");
        serve_error(
            request,
            tiny_http::StatusCode(500),
            "Internal server error: oauth2 error",
        );
        return;
    }
    let mut response = Response::empty(tiny_http::StatusCode(302));
    response.add_header(
        tiny_http::Header::from_bytes(&b"Location"[..], &session_next_uri[..])
            .expect("This should never fail"),
    );
    dispatch_response(request, response);
}

fn handle_telemetry(request: Request, auth_guard: AuthGuard<ValidUser>) {
    match auth_guard {
        Ok(_) => {
            let mut context = Context::new();
            context.insert("user","logged_in");
            let rendered = TEMPLATES.render("telemetry.html.tera", &context);
            let response = Response::from_data(rendered);
            dispatch_response(request, response);
        },
        Err(_) => {
            let mut response = Response::empty(tiny_http::StatusCode(302));
            response.add_header(
                tiny_http::Header::from_bytes(&b"Location"[..], "/frame_admin")
                    .expect("This should never fail"),
            );
            dispatch_response(request, response);
        }
    };
}

fn handle_telemetry_data(request: Request, auth_guard: AuthGuard<ValidUser>) -> Result<(), Box<dyn std::error::Error>> {
    match auth_guard {
        Ok(_) => {},
        Err(_) => {
            serve_error(request, tiny_http::StatusCode(401), "Unauthorised");
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
    let mut transaction = dbclient.0.transaction()?;
    let count_row = transaction.query_one("SELECT COUNT(*) FROM telemetry", &[])?;
    let records_total: i64 = count_row.get(0);
    if limit == -1 {
        limit = records_total;
    }
    let records = transaction.query(
        "SELECT ts, item_id, product_url, chip_id, uuid_number, bat_voltage, boot_code, error_code, return_code, write_bytes, remote_addr 
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
            chip_id: row.get(3),
            uuid_number: row.get(4),
            bat_voltage: row.get(5),
            boot_code: row.get(6),
            error_code: row.get(7),
            return_code: row.get(8),
            write_bytes: row.get(9),
            remote_addr: row.get(10),
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

fn handle_revoke(request: Request) {
    let session_id = match SESSION_MGR.get_session_id(&request) {
        Ok(session_id) => session_id,
        Err(e) => {
            log::info!("[Info] (handle_revoke) session error: {:?}", e);
            let next_uri = request.url();
            let session_id: SessionID = SESSION_MGR.create_session();
            SESSION_MGR.set_session_data(&session_id, "next_uri", next_uri);
            let mut response = Response::empty(tiny_http::StatusCode(302));
            response.add_header(
                Header::from_str("Location: authorise").expect("This should never fail"),
            );
            response.add_header(
                Header::from_str(&format!("Set-Cookie: session={}", session_id))
                    .expect("This should never fail"),
            );
            dispatch_response(request, response);
            return;
        }
    };
    let credentials = Credentials::load();
    let response = match credentials.revoke().is_ok() {
        true => {
            SESSION_MGR.remove_session(session_id.as_str());
            log::info!("[Info] (handle_revoke) revoked access/refresh token");
            let mut context = Context::new();
            context.insert("message", "Credentials revoked");
            let rendered = TEMPLATES.render("revoke.html.tera", &context);
            Response::from_data(rendered)
        }
        false => {
            log::error!("[Error] (handle_revoke) error revoking access/refresh token");
            serve_error(
                request,
                tiny_http::StatusCode(500),
                "Internal server error: error revoking credentials",
            );
            return;
        }
    };
    dispatch_response(request, response);
}
