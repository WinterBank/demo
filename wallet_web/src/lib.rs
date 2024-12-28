// wallet_web/src/lib.rs

use yew::prelude::*;
use web_sys::HtmlInputElement;
use wasm_bindgen_futures::spawn_local;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use gloo_timers::callback::Interval;
use gloo_net::websocket::futures::WebSocket;
use hex;
use futures_util::StreamExt;

// For debug logging in browser console
use gloo_console::log;

use wallet_core::routes::{
    WalletClient,
    EncryptedKeyMaterial,
    SignedTransaction,
};

const ACTIX_HTTP_URL: &str = "http://http://107.196.36.121:8080";
const ACTIX_WS_URL: &str = "ws://http://107.196.36.121:8080/ws";

/// A small helper struct to hold the main account info from the server.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct AccountInfo {
    public_key: String,
    name: Option<String>,
    account_key: String,  // 16-byte hex string
    balance: i64,
    // The server also returns these for main accounts:
    encrypted_private_key: Option<String>,
    private_key_nonce: Option<String>,
    kdf_salt: Option<String>,
    kdf_iterations: Option<i32>,
}

#[function_component(App)]
pub fn app() -> Html {
    let current_user_info = use_state(|| None::<AccountInfo>);
    let circulating_supply = use_state(|| 0i64);

    // --------------------------
    // WEB SOCKET SETUP
    // --------------------------
    {
        let current_user_info = current_user_info.clone();
        let circulating_supply = circulating_supply.clone();

        use_effect_with((), move |_| {
            // Attempt to open the WebSocket
            match WebSocket::open(ACTIX_WS_URL) {
                Ok(ws) => {
                    let (_tx, mut rx) = ws.split();

                    spawn_local(async move {
                        while let Some(msg) = rx.next().await {
                            if let Ok(gloo_net::websocket::Message::Text(txt)) = msg {
                                if let Ok(val) = serde_json::from_str::<Value>(&txt) {
                                    log!(format!("WS message received: {:?}", val));

                                    if val["type"] == "supply_update" {
                                        if let Some(new_supp) = val["new_circulating_supply"].as_i64() {
                                            log!(format!("Updating supply to {new_supp}"));
                                            circulating_supply.set(new_supp);
                                        }
                                    }
                                    else if val["type"] == "balance_update" {
                                        let acct_hex = val["account_key"].as_str().unwrap_or("");
                                        let new_bal = val["new_balance"].as_i64().unwrap_or(0);

                                        log!(format!(
                                            "Got balance_update => account_key={}, new_balance={}",
                                            acct_hex, new_bal
                                        ));

                                        // If the current user is signed in:
                                        let user_opt = (*current_user_info).clone();
                                        if let Some(u) = user_opt {
                                            // For debug, log what we have:
                                            log!(format!(
                                                "Signed-in user's account_key={}, currently stored balance={}",
                                                u.account_key, u.balance
                                            ));

                                            // Compare to user's account_key
                                            // (Case-insensitive check if needed)
                                            if u.account_key.eq_ignore_ascii_case(acct_hex) {
                                                log!(format!(
                                                    "Balance update MATCHES user. Updating from {} to {}",
                                                    u.balance, new_bal
                                                ));
                                                let mut updated_user = u.clone();
                                                updated_user.balance = new_bal;
                                                current_user_info.set(Some(updated_user));
                                            } else {
                                                log!(format!(
                                                    "Balance update DOES NOT MATCH. user.account_key={}, broadcast_key={}",
                                                    u.account_key, acct_hex
                                                ));
                                            }
                                        } else {
                                            log!("No user is currently signed in, ignoring balance_update");
                                        }
                                    }
                                }
                            }
                        }
                        log!("WebSocket closed or no more messages!");
                    });
                }
                Err(e) => {
                    log!(format!("Error opening WS: {:?}", e));
                }
            }

            || ()
        });
    }

    // ------------------------------------------------------------------------
    // A) Create Account
    // ------------------------------------------------------------------------
    let create_name = use_state(|| "".to_string());
    let create_pass1 = use_state(|| "".to_string());
    let create_pass2 = use_state(|| "".to_string());
    let create_message = use_state(|| "".to_string());
    let newly_created_info = use_state(|| None::<AccountInfo>);

    let user_ekm = use_state(|| None::<EncryptedKeyMaterial>);
    let user_password = use_state(|| "".to_string());

    let onclick_create_account = {
        let create_name = create_name.clone();
        let create_pass1 = create_pass1.clone();
        let create_pass2 = create_pass2.clone();
        let create_message = create_message.clone();
        let newly_created_info = newly_created_info.clone();
        let user_ekm = user_ekm.clone();
        let user_password = user_password.clone();
        let current_user_info = current_user_info.clone();

        Callback::from(move |_| {
            let name = (*create_name).clone();
            let pass1 = (*create_pass1).clone();
            let pass2 = (*create_pass2).clone();
            let msg_state = create_message.clone();
            let info_state = newly_created_info.clone();
            let ekm_state = user_ekm.clone();
            let user_pass_state = user_password.clone();
            let user_info_state = current_user_info.clone();

            if pass1.is_empty() || pass2.is_empty() {
                msg_state.set("Please enter your password twice.".to_string());
                return;
            }
            if pass1 != pass2 {
                msg_state.set("Passwords do not match!".to_string());
                return;
            }

            spawn_local(async move {
                let wallet_client = WalletClient::new(ACTIX_HTTP_URL);
                let (ekm, _main_key) = WalletClient::generate_and_encrypt_keys(&name, &pass1);

                match wallet_client.create_account_on_server(&name, &ekm).await {
                    Ok(_) => {
                        msg_state.set("Account created successfully! Fetching details...".to_string());
                        let url = format!("{}/accounts/{}", ACTIX_HTTP_URL, name);
                        if let Ok(r) = reqwest::get(&url).await {
                            if let Ok(json_val) = r.json::<Value>().await {
                                if let Ok(info) = serde_json::from_value::<AccountInfo>(json_val) {
                                    info_state.set(Some(info.clone()));
                                    user_info_state.set(Some(info));
                                }
                            }
                        }
                        ekm_state.set(Some(ekm));
                        user_pass_state.set(pass1);
                    }
                    Err(e) => {
                        msg_state.set(format!("Error creating account: {e}"));
                    }
                }
            });
        })
    };

    // ------------------------------------------------------------------------
    // B) Sign In (Returning User)
    // ------------------------------------------------------------------------
    let signin_name = use_state(|| "".to_string());
    let signin_password = use_state(|| "".to_string());
    let signin_message = use_state(|| "".to_string());

    let signin_name_val = (*signin_name).clone();
    let signin_password_val = (*signin_password).clone();

    let onclick_signin = {
        let signin_name = signin_name.clone();
        let signin_password_for_closure = signin_password.clone();
        let signin_message = signin_message.clone();
        let user_ekm = user_ekm.clone();
        let user_password_for_state = user_password.clone();
        let current_user_info = current_user_info.clone();

        Callback::from(move |_| {
            let name = (*signin_name).clone();
            let pass = (*signin_password_for_closure).clone();
            let msg_st = signin_message.clone();
            let ekm_st = user_ekm.clone();
            let user_pass_st = user_password_for_state.clone();
            let user_info_st = current_user_info.clone();

            spawn_local(async move {
                if name.is_empty() || pass.is_empty() {
                    msg_st.set("Please enter your account name and password.".to_string());
                    return;
                }
                let url = format!("{}/accounts/{}", ACTIX_HTTP_URL, name);
                match reqwest::get(&url).await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            match resp.json::<Value>().await {
                                Ok(json_val) => {
                                    let ephemeral = parse_account_info(json_val.clone());
                                    match ephemeral {
                                        Some((ekm_obj, display_str)) => {
                                            let test = WalletClient::decrypt_signing_key(&pass, &ekm_obj);
                                            match test {
                                                Ok(_) => {
                                                    ekm_st.set(Some(ekm_obj));
                                                    user_pass_st.set(pass);
                                                    msg_st.set(format!(
                                                        "Signed in!\nAccount details:\n{}",
                                                        display_str
                                                    ));

                                                    if let Ok(info) = serde_json::from_value::<AccountInfo>(json_val) {
                                                        user_info_st.set(Some(info));
                                                        let supply_url = format!("{}/supply", ACTIX_HTTP_URL);
                                                    }
                                                }
                                                Err(e) => {
                                                    msg_st.set(format!("Decryption failed: {e}"));
                                                }
                                            }
                                        }
                                        None => {
                                            msg_st.set("Could not parse the server’s account info as EKM.".to_string());
                                        }
                                    }
                                }
                                Err(e) => {
                                    msg_st.set(format!("Error parsing JSON: {e}"));
                                }
                            }
                        } else {
                            msg_st.set("Server returned an error for that account name.".to_string());
                        }
                    }
                    Err(e) => {
                        msg_st.set(format!("Network error: {e}"));
                    }
                }
            });
        })
    };

    // ------------------------------------------------------------------------
    // B.1) Sign Out
    // ------------------------------------------------------------------------
    let signout_message = use_state(|| "".to_string());
    let onclick_signout = {
        let user_ekm = user_ekm.clone();
        let user_password = user_password.clone();
        let signout_message = signout_message.clone();
        let current_user_info = current_user_info.clone();

        Callback::from(move |_| {
            user_ekm.set(None);
            user_password.set("".to_string());
            current_user_info.set(None);
            signout_message.set("Signed out. The private key is wiped from memory.".to_string());
        })
    };

    // ------------------------------------------------------------------------
    // C) Sign & Submit Transaction
    // ------------------------------------------------------------------------
    let tx_sender = use_state(|| "".to_string());
    let tx_receiver = use_state(|| "".to_string());
    let tx_amount = use_state(|| "0".to_string());
    let tx_message = use_state(|| "".to_string());

    let onclick_sign_and_submit = {
        let tx_sender = tx_sender.clone();
        let tx_receiver = tx_receiver.clone();
        let tx_amount = tx_amount.clone();
        let tx_message = tx_message.clone();
        let user_ekm = user_ekm.clone();
        let user_password_for_decrypt = user_password.clone();

        Callback::from(move |_| {
            let sender_str = (*tx_sender).clone();
            let receiver_str = (*tx_receiver).clone();
            let amount_str = (*tx_amount).clone();
            let msg_st = tx_message.clone();
            let ekm_opt = (*user_ekm).clone();
            let pass = (*user_password_for_decrypt).clone();

            let amount_i64: i64 = amount_str.parse().unwrap_or(0);
            if amount_i64 <= 0 {
                msg_st.set("Amount must be > 0.".to_string());
                return;
            }
            if ekm_opt.is_none() {
                msg_st.set("Error: You haven't signed in or created an account yet.".to_string());
                return;
            }
            let ekm = ekm_opt.unwrap();

            match WalletClient::decrypt_signing_key(&pass, &ekm) {
                Ok(signing_key) => {
                    let msg_st2 = msg_st.clone();
                    spawn_local(async move {
                        let sender_key_16 = match resolve_account_key_16(&sender_str).await {
                            Some(k) => k,
                            None => {
                                msg_st2.set(format!("Could not resolve sender '{sender_str}' to 16-byte key."));
                                return;
                            }
                        };
                        let receiver_key_16 = match resolve_account_key_16(&receiver_str).await {
                            Some(k) => k,
                            None => {
                                msg_st2.set(format!("Could not resolve receiver '{receiver_str}' to 16-byte key."));
                                return;
                            }
                        };

                        let wallet_client = WalletClient::new(ACTIX_HTTP_URL);
                        let tx = wallet_client.sign_transaction(
                            sender_key_16,
                            receiver_key_16,
                            amount_i64,
                            &signing_key,
                        );

                        match wallet_client.submit_transaction(&tx).await {
                            Ok(_) => msg_st2.set("Transaction submitted!".to_string()),
                            Err(e) => msg_st2.set(format!("Submit TX error: {e}")),
                        }
                    });
                }
                Err(e) => {
                    msg_st.set(format!("Decryption failed: {e}"));
                }
            }
        })
    };

    // ------------------------------------------------------------------------
    // D) Get Circulating Supply
    // ------------------------------------------------------------------------
    let supply_message = use_state(|| "".to_string());
    let onclick_get_supply = {
        let supply_message = supply_message.clone();
        Callback::from(move |_| {
            let msg_state = supply_message.clone();
            spawn_local(async move {
                let wallet_client = WalletClient::new(ACTIX_HTTP_URL);
                match wallet_client.get_circulating_supply().await {
                    Ok(val) => msg_state.set(format!("Circulating supply = {val}")),
                    Err(e) => msg_state.set(format!("Error fetching supply: {e}")),
                }
            });
        })
    };

    // ------------------------------------------------------------------------
    // E) Get All Transactions
    // ------------------------------------------------------------------------
    let transactions_output = use_state(|| "".to_string());
    let onclick_get_txs = {
        let transactions_output = transactions_output.clone();
        Callback::from(move |_| {
            let out_state = transactions_output.clone();
            spawn_local(async move {
                let wallet_client = WalletClient::new(ACTIX_HTTP_URL);
                match wallet_client.get_transactions().await {
                    Ok(json_val) => {
                        let hexified = transform_transactions_to_hex(json_val);
                        let pretty = serde_json::to_string_pretty(&hexified).unwrap();
                        out_state.set(pretty);
                    }
                    Err(e) => out_state.set(format!("Error fetching transactions: {e}")),
                }
            });
        })
    };

    // ------------------------------------------------------------------------
    // E.1) Get Transactions (Mine)
    // ------------------------------------------------------------------------
    let my_txs_output = use_state(|| "".to_string());
    let onclick_get_my_txs = {
        let my_txs_output = my_txs_output.clone();
        let current_user_info = current_user_info.clone();
        Callback::from(move |_| {
            let out_state = my_txs_output.clone();
            let user_info_opt = (*current_user_info).clone();

            spawn_local(async move {
                if let Some(u) = user_info_opt {
                    let identifier = if let Some(n) = u.name {
                        n
                    } else {
                        u.account_key
                    };

                    let wallet_client = WalletClient::new(ACTIX_HTTP_URL);
                    match wallet_client.get_user_transactions(&identifier).await {
                        Ok(json_val) => {
                            let hexified = transform_transactions_to_hex(json_val);
                            let pretty = serde_json::to_string_pretty(&hexified).unwrap();
                            out_state.set(pretty);
                        }
                        Err(e) => out_state.set(format!("Error fetching user transactions: {e}")),
                    }
                } else {
                    out_state.set("Error: You must be signed in to fetch your transactions.".to_string());
                }
            });
        })
    };

    html! {
      <div style="margin: 1em;">
        <h1>{ "WinterBank Web Wallet" }</h1>

        {
          if let Some(user) = &*current_user_info {
            let display_name = user.name.clone().unwrap_or("[unknown]".to_string());
            html! {
              <div style="border:1px solid #ccc; margin-bottom:1em; padding:1em;">
                <p><b>{"Signed in as: "}</b>{ display_name }</p>
                <p><b>{"Account Key: "}</b>{ user.account_key.clone() }</p>
                <p><b>{"Balance: "}</b>{ user.balance }</p>
                <p><b>{"Circulating Supply: "}</b>{ *circulating_supply }</p>
              </div>
            }
          } else {
            html! {}
          }
        }

        // A) Create Account
        <h2>{ "A) Create Account (New User)" }</h2>
        <div>
          <label>{ "Name: " }</label>
          <input
            type="text"
            value={(*create_name).clone()}
            oninput={{
              let st = create_name.clone();
              move |e: InputEvent| st.set(e.target_unchecked_into::<HtmlInputElement>().value())
            }}
          />
        </div>
        <div>
          <label>{ "Password: " }</label>
          <input
            type="password"
            value={(*create_pass1).clone()}
            oninput={{
              let st = create_pass1.clone();
              move |e: InputEvent| st.set(e.target_unchecked_into::<HtmlInputElement>().value())
            }}
          />
        </div>
        <div>
          <label>{ "Re-type Password: " }</label>
          <input
            type="password"
            value={(*create_pass2).clone()}
            oninput={{
              let st = create_pass2.clone();
              move |e: InputEvent| st.set(e.target_unchecked_into::<HtmlInputElement>().value())
            }}
          />
        </div>
        <button onclick={onclick_create_account}>{ "Create Account" }</button>
        <p>{ (*create_message).clone() }</p>
        {
          if let Some(info) = &*newly_created_info {
            html! {
              <div style="border:1px solid #ccc; padding: 0.5em;">
                <p>{ "Public Key: " } { &info.public_key }</p>
                <p>{ "Account Key: " } { &info.account_key }</p>
                <p>{ "Balance: " } { info.balance }</p>
              </div>
            }
          } else {
            html! {}
          }
        }

        <hr/>

        // B) Sign In
        <h2>{ "B) Sign In (Returning User)" }</h2>
        <div>
          <label>{ "Account Name: " }</label>
          <input
            type="text"
            value={signin_name_val}
            oninput={{
              let st = signin_name.clone();
              move |e: InputEvent| st.set(e.target_unchecked_into::<HtmlInputElement>().value())
            }}
          />
        </div>
        <div>
          <label>{ "Password: " }</label>
          <input
            type="password"
            value={signin_password_val}
            oninput={{
              let st = signin_password.clone();
              move |e: InputEvent| st.set(e.target_unchecked_into::<HtmlInputElement>().value())
            }}
          />
        </div>
        <button onclick={onclick_signin}>{ "Sign In" }</button>
        <p>{ (*signin_message).clone() }</p>

        <hr/>
        // B.1) Sign Out
        <button onclick={onclick_signout}>{ "Sign Out" }</button>
        <p>{ (*signout_message).clone() }</p>

        <hr/>

        // C) Sign & Submit Transaction
        <h2>{ "C) Sign & Submit Transaction" }</h2>
        <p>{ "Sender or Receiver can be an account name (e.g. 'alice') or 16-byte hex." }</p>
        <div>
          <label>{ "Sender: " }</label>
          <input
            type="text"
            value={(*tx_sender).clone()}
            oninput={{
              let st = tx_sender.clone();
              move |e: InputEvent| st.set(e.target_unchecked_into::<HtmlInputElement>().value())
            }}
          />
        </div>
        <div>
          <label>{ "Receiver: " }</label>
          <input
            type="text"
            value={(*tx_receiver).clone()}
            oninput={{
              let st = tx_receiver.clone();
              move |e: InputEvent| st.set(e.target_unchecked_into::<HtmlInputElement>().value())
            }}
          />
        </div>
        <div>
          <label>{ "Amount: " }</label>
          <input
            type="number"
            value={(*tx_amount).clone()}
            oninput={{
              let st = tx_amount.clone();
              move |e: InputEvent| st.set(e.target_unchecked_into::<HtmlInputElement>().value())
            }}
          />
        </div>
        <button onclick={onclick_sign_and_submit}>{ "Sign & Submit" }</button>
        <p>{ (*tx_message).clone() }</p>

        <hr/>
        // D) Get Circulating Supply
        <h2>{ "D) Get Circulating Supply" }</h2>
        <button onclick={onclick_get_supply}>{ "Get Supply" }</button>
        <p>{ (*supply_message).clone() }</p>

        <hr/>
        // E) Get All Transactions
        <h2>{ "E) Get All Transactions" }</h2>
        <button onclick={onclick_get_txs}>{ "Get Transactions" }</button>
        <pre style="border:1px solid #ccc; padding: 0.5em;">
          { (*transactions_output).clone() }
        </pre>

        <hr/>
        // E.1) Get Transactions (Mine)
        <h2>{ "Get Transactions (Mine)" }</h2>
        <button onclick={onclick_get_my_txs}>{ "Get My Transactions" }</button>
        <pre style="border:1px solid #ccc; padding: 0.5em;">
          { (*my_txs_output).clone() }
        </pre>
      </div>
    }
}

/// Helper to parse the server’s JSON into an `EncryptedKeyMaterial` and a text display.
fn parse_account_info(json_val: serde_json::Value) -> Option<(EncryptedKeyMaterial, String)> {
    let epk_hex = json_val["encrypted_private_key"].as_str()?;
    let nonce_hex = json_val["private_key_nonce"].as_str()?;
    let salt_hex = json_val["kdf_salt"].as_str()?;
    let iterations = json_val["kdf_iterations"].as_i64()?;

    let pk_hex = json_val["public_key"].as_str()?;
    let pk_bytes = hex::decode(pk_hex).ok()?;
    if pk_bytes.len() != 32 {
        return None;
    }

    let epk = hex::decode(epk_hex).ok()?;
    let nonce = hex::decode(nonce_hex).ok()?;
    let salt = hex::decode(salt_hex).ok()?;

    let ekm = EncryptedKeyMaterial {
        public_key: pk_bytes.try_into().ok()?,
        encrypted_private_key: epk,
        private_key_nonce: nonce,
        kdf_salt: salt,
        kdf_iterations: iterations as u32,
    };

    let display_str = format!(
        "public_key={pk_hex}\nencrypted_key={epk_hex}\nnonce={nonce_hex}\nsalt={salt_hex}\niterations={iterations}"
    );
    Some((ekm, display_str))
}

/// Helper to fetch the 16-byte account_key from the server for a given identifier
/// (e.g. "alice", "bob", or a 16-byte hex).
async fn resolve_account_key_16(identifier: &str) -> Option<[u8; 16]> {
    let url = format!("{}/accounts/{}", ACTIX_HTTP_URL, identifier);
    if let Ok(resp) = reqwest::get(&url).await {
        if resp.status().is_success() {
            if let Ok(val) = resp.json::<Value>().await {
                if let Some(ak_hex) = val["account_key"].as_str() {
                    if let Ok(decoded) = hex::decode(ak_hex) {
                        if decoded.len() == 16 {
                            let mut arr = [0u8; 16];
                            arr.copy_from_slice(&decoded);
                            return Some(arr);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Transform the fetched transactions (JSON) so that fields like
/// `sender_key`, `receiver_key`, `signature`, `id` become hex strings
/// rather than byte arrays.
fn transform_transactions_to_hex(original: Value) -> Value {
    if let Some(arr) = original.as_array() {
        let new_array: Vec<Value> = arr
            .iter()
            .map(|tx_item| {
                if let Some(obj) = tx_item.as_object() {
                    let mut new_obj = obj.clone();
                    for field in &["id", "sender_key", "receiver_key", "signature"] {
                        if let Some(val) = new_obj.get(*field) {
                            match val {
                                Value::String(s) => {
                                    // Possibly already a hex string
                                }
                                Value::Array(byte_arr) => {
                                    let as_u8: Vec<u8> = byte_arr
                                        .iter()
                                        .filter_map(|x| x.as_u64())
                                        .filter_map(|x| u8::try_from(x).ok())
                                        .collect();
                                    let hexed = hex::encode(&as_u8);
                                    new_obj.insert(field.to_string(), Value::String(hexed));
                                }
                                _ => {}
                            }
                        }
                    }
                    Value::Object(new_obj)
                } else {
                    tx_item.clone()
                }
            })
            .collect();
        Value::Array(new_array)
    } else {
        original
    }
}

#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start_app() {
    yew::Renderer::<App>::new().render();
}
