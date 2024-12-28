// api/src/server.rs

use actix_web::{App, HttpServer, web, http::header};
use actix_cors::Cors;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;
use crate::routes::*;
use crate::batcher::*;
use crate::ws_actix::{websocket_handler, WsBroadcast};
use redis::Client as RedisClient;
use miner::cpu_miner::CpuMiner;
use serde_json::Value;

pub async fn start_server(pool: PgPool, cpu_miner: Arc<CpuMiner>, redis_client: RedisClient) {
    let redis_client_arc = Arc::new(redis_client);

    println!("Starting HTTP server with Redis and PostgreSQL...");

    // Create broadcast channel for JSON messages
    let (tx, _rx) = broadcast::channel::<Value>(100);

    // Wrap it in WsBroadcast for the /ws handler
    let ws_broadcast = WsBroadcast {
        sender: Arc::new(tx.clone()), // store an Arc<Sender<Value>>
    };

    // Notice we pass Some(Arc::new(tx.clone())) to the batching workers:
    tokio::spawn(start_transaction_batching_worker(
        pool.clone(),
        redis_client_arc.clone(),
        Some(Arc::new(tx.clone())),
    ));

    tokio::spawn(start_mining_submission_batching_worker(
        pool.clone(),
        redis_client_arc.clone(),
        Some(Arc::new(tx.clone())),
    ));

    tokio::spawn(start_state_root_updater(pool.clone()));

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(cpu_miner.clone()))
            .app_data(web::Data::new(redis_client_arc.clone()))
            .app_data(web::Data::new(ws_broadcast.clone()))
            // Routes
            .service(create_account)
            .service(create_sub_account)
            .service(get_accounts)
            .service(get_account_by_identifier)
            .service(get_mining_params)
            .service(submit_mining_result)
            .service(get_circulating_supply)
            .service(create_transaction)
            .service(get_transactions)
            .service(create_account_new)
            .service(create_transaction_new)
            .service(get_user_transactions)
            .service(websocket_handler)
            .wrap(Cors::permissive())  // change for production
            .wrap(
                Cors::default()
                    .allowed_origin("http://demo.peerlync.com")
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_headers(vec![header::CONTENT_TYPE, header::ACCEPT])
                    .supports_credentials(),
            )
    })
    .bind("0.0.0.0:8080")
    .expect("Failed to bind server")
    .run()
    .await
    .expect("Failed to run server");
}
