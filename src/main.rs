mod config;
mod database;
mod google_oauth;
mod gphotos_api;
mod image_proc;
mod model;
mod route_handler;
mod session_mgr;
mod task_mgr;
mod template_mgr;

use crate::{
    database::CONNECTION_POOL,
    model::AppState,
    route_handler::{route_request, serve_error},
    session_mgr::SESSION_MGR,
    task_mgr::TASK_BOARD,
    template_mgr::TEMPLATES,
};

use std::{process::exit, sync::Arc, thread};
use tiny_http::Server;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    #[cfg(debug_assertions)]
    std::panic::set_hook(Box::new(|info| {
        eprintln!("{info}");
        eprintln!("{}", std::backtrace::Backtrace::force_capture());
    }));
    // Dev convenience: seed the environment from secrets/.env if present. Real
    // environment variables (e.g. those provided by the container in production)
    // always take precedence, and the file is simply absent in production.
    config::load_env_file("secrets/.env");
    let app_data = AppState::init("secrets/");
    let env = app_data.env.lock().unwrap_or_else(|e| e.into_inner());
    let postgres_connection_string = env.postgres_connection_string.clone();
    session_mgr::set_secure_cookies(env.cookie_secure);
    drop(env);
    let pool_size = 4;
    if let Err(e) = CONNECTION_POOL.initialise(&postgres_connection_string, pool_size) {
        log::error!("failed to set max pool size: {:?}", e);
        exit(1);
    };
    TEMPLATES.full_reload();
    TASK_BOARD.initialise();
    SESSION_MGR.initialise();
    app_data.save("secrets/");
    // Bind address is configurable so the service can be pinned to localhost
    // when it sits behind a reverse proxy. Defaults to the previous behaviour.
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:5000".to_string());
    let server = Server::http(bind_addr.as_str())
        .unwrap_or_else(|e| panic!("failed to bind {bind_addr}: {e}"));
    log::info!(
        "🚀 server started successfully, listening on {}",
        server.server_addr()
    );
    let server = Arc::new(server);
    for _ in 0..4 {
        let server = server.clone();
        let app_data = app_data.clone();
        thread::spawn(move || {
            loop {
                let request = match server.recv() {
                    Ok(r) => r,
                    Err(e) => {
                        log::error!("could not receive request: {}", e);
                        continue;
                    }
                };
                let method = request.method().as_str();
                if method != "GET" && method != "POST" {
                    serve_error(request, tiny_http::StatusCode(405), "Method not allowed");
                    continue;
                }
                // Isolate each request: a panic in a handler must not kill this
                // worker thread (which would eventually take the whole server
                // down). On panic the request is dropped, and tiny_http's Drop
                // sends a 500 to the client automatically.
                let app_data = app_data.clone();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    route_request(app_data, request);
                }));
                if let Err(e) = result {
                    let msg = e
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| e.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".to_string());
                    log::error!("(worker) recovered from panic while handling request: {msg}");
                }
            }
        });
    }
    loop {
        thread::park();
    }
}
