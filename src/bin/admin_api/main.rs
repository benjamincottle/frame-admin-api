mod config;
mod google_oauth;
mod gphotos_api;
mod image_proc;
mod model;
mod route_handler;
mod session_mgr;
mod task_mgr;
mod template_mgr;

use frame::database::CONNECTION_POOL;

use crate::{
    model::AppState,
    route_handler::{route_request, serve_error},
    session_mgr::SESSION_MGR,
    task_mgr::TASK_BOARD,
    template_mgr::TEMPLATES,
};

use log;
use std::{
    env,
    io::{stdin, BufRead},
    process::exit,
    sync::Arc,
    thread,
};
use tiny_http::Server;

fn main() {
    // for debugging purposes
    if env::var_os("RUST_LOG").is_none() {
        env::set_var("RUST_LOG", "info");
    }
    if env::var_os("RUST_BACKTRACE").is_none() {
        env::set_var("RUST_BACKTRACE", "1");
    }
    dotenv::from_filename("secrets/.env").ok();
    env_logger::init();
    let app_data = AppState::init("secrets/");
    let pool_size = 4;
    match CONNECTION_POOL.initialise(&app_data.env.postgres_connection_string, pool_size) {
        Err(e) => {
            log::error!("failed to initialise connection pool: {:?}", e);
            exit(1);
        }
        _ => {}
    };
    TEMPLATES.full_reload();
    TASK_BOARD.initialise();
    SESSION_MGR.initialise();
    app_data.env.save("secrets/");
    let server = Server::http("0.0.0.0:5000").expect("This should not fail");
    log::info!(
        "🚀 server started successfully, listening on {}",
        server.server_addr()
    );
    let server = Arc::new(server);
    for _ in 0..4 {
        let server = server.clone();
        let app_data = app_data.clone();
        thread::spawn(move || loop {
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
        });
    }
    loop {
        let mut input = String::new();
        stdin().lock().read_line(&mut input).unwrap();
        if input.trim() == "d" {
            TASK_BOARD.dump();
        } else if input.trim() == "s" {
            SESSION_MGR.dump();
        } else if input.trim() == "r" {
            TEMPLATES.full_reload();
        } else if input.trim() == "u" {
            println!("[Debug] Users in AppState");
            println!("[Debug]   Users:");
            let user_db = app_data.db.lock().unwrap();
            for user in user_db.iter() {
                println!("[Debug]      {:?}", user);
            }
        }
        // thread::park();
    }
}

// COPY telemetry(ts, chip_id, uuid_number, bat_voltage, boot_code, error_code, return_code, write_bytes, remote_addr)
// FROM '/var/lib/postgresql/data/db.csv'
// DELIMITER '?'
// CSV HEADER;

// fn main2() {
//     dotenv::from_path("secrets/.env").ok();
//     env_logger::init();
//     if env::var("POSTGRES_CONNECTION_STRING").is_err()
//     {
//         log::error!("environment not configured");
//         return;
//     }
//     let database_url = &env::var("POSTGRES_CONNECTION_STRING").expect("previously validated");
//     let pool_size = 4;
//     CONNECTION_POOL.initialise(database_url, pool_size);
//     let mut dbclient = CONNECTION_POOL.get_client().unwrap();

//     let tel_rows = dbclient.0.query("SELECT * FROM telemetry", &[]).unwrap();
//     for tel_row in tel_rows.iter() {
//         let album_row = dbclient.0.query_one("SELECT item_id, product_url FROM album ORDER BY random() LIMIT 1", &[]).unwrap();
//         let item_id: String = album_row.get(0);
//         let product_url: String = album_row.get(1);
//         let uuid_number: uuid::Uuid = tel_row.get(4);
//         dbclient.0.execute("UPDATE telemetry SET item_id = $1, product_url = $2 WHERE uuid_number = $3",
//                        &[&item_id, &product_url, &uuid_number]).unwrap();

//     }
//     CONNECTION_POOL.release_client(dbclient);
// }
