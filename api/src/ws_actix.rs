// api/src/ws_actix.rs

use actix_ws::Message;
use actix_web::{get, web, HttpRequest, HttpResponse, Error};
use futures_util::StreamExt;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Holds the broadcast sender so we can spawn a receiving task for each WS.
#[derive(Clone)]
pub struct WsBroadcast {
    pub sender: Arc<broadcast::Sender<Value>>,
}

#[get("/ws")]
pub async fn websocket_handler(
    req: HttpRequest,
    stream: web::Payload,
    data: web::Data<WsBroadcast>,
) -> Result<HttpResponse, Error> {
    let (response, session, mut msg_stream) = actix_ws::handle(&req, stream)?;

    // Clone session for each separate task:
    let mut session_to_incoming = session.clone();
    let mut session_to_broadcast = session.clone();

    // Create a new **subscriber** for each WS connection
    let mut rx = data.sender.subscribe();

    // 1) Spawn a task that *pushes* from `rx` => to this `session`
    actix_web::rt::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(val) => {
                    // val is e.g. json!({"type": "supply_update", ...})
                    if let Ok(txt) = serde_json::to_string(&val) {
                        let _ = session_to_broadcast.text(txt).await;
                    }
                }
                Err(_) => {
                    // broadcast channel closed or lagging
                    break;
                }
            }
        }
        // optionally close the session if you want
        let _ = session_to_broadcast.close(None).await;
    });

    // 2) Spawn a task to process incoming messages *from* the client
    actix_web::rt::spawn(async move {
        while let Some(Ok(msg)) = msg_stream.next().await {
            match msg {
                Message::Ping(bytes) => {
                    let _ = session_to_incoming.pong(&bytes).await;
                }
                Message::Text(txt) => {
                    println!("Received WS text: {txt}");
                    // Optionally echo back
                    let _ = session_to_incoming.text(format!("You said: {txt}")).await;
                }
                Message::Close(reason) => {
                    let _ = session_to_incoming.close(reason).await;
                    return;
                }
                _ => (),
            }
        }
        // If the client’s socket ended, close session
        let _ = session_to_incoming.close(None).await;
    });

    Ok(response)
}
