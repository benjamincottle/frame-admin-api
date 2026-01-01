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

use std::{
    env,
    io::{BufRead, stdin},
    process::exit,
    sync::Arc,
    thread,
};
use tiny_http::Server;

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();
    #[cfg(debug_assertions)]
    std::panic::set_hook(Box::new(|info| {
        eprintln!("{info}");
        eprintln!("{}", std::backtrace::Backtrace::force_capture());
    }));
    dotenv::from_filename("secrets/.env").ok();
    let app_data = AppState::init("secrets/");
    let env = app_data.env.lock().unwrap();
    let postgres_connection_string = env.postgres_connection_string.clone();
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
    let server = Server::http("0.0.0.0:5000").expect("This should not fail");
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
                if request.method().as_str() != "GET" {
                    serve_error(request, tiny_http::StatusCode(405), "Method not allowed");
                    continue;
                }
                route_request(app_data.clone(), request);
            }
        });
    }
    loop {
        // This won't work when the system is running in a docker container
        // but it's useful for debugging when running natively.
        // let mut input = String::new();
        // stdin().lock().read_line(&mut input).unwrap();
        // if input.trim() == "d" {
        //     TASK_BOARD.dump();
        // } else if input.trim() == "s" {
        //     SESSION_MGR.dump();
        // } else if input.trim() == "r" {
        //     TEMPLATES.full_reload();
        // } else if input.trim() == "u" {
        //     println!("[Debug] Users in AppState");
        //     println!("[Debug]   Users:");
        //     let user_db = app_data.db.lock().unwrap();
        //     for user in user_db.iter() {
        //         println!("[Debug]      {:?}", user);
        //     }
        // }
        thread::park();
    }
}
