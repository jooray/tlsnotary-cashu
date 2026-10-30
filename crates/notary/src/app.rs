//! HTTP API: `/info`, tickets (NUT-24), the notarization and bridge
//! WebSockets.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Query, State, WebSocketUpgrade},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use tlsnc_protocol::{
    EgressInfo, ErrorBody, Info, NotaryKeyInfo, PROTOCOL, TLSN_VERSION, TicketResponse, WellKnown,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

use crate::{
    bridge,
    config::{Config, TierConfig},
    egress::Egress,
    session::{self, EGRESS_SLACK_DOWN, EGRESS_SLACK_UP, SessionCtx},
    tickets::{Store, Ticket, TicketError},
    wallet::{PayError, Wallets},
};

/// WebSocket messages are chunks of a byte stream; bound them anyway.
const MAX_WS_MESSAGE: usize = 1 << 22;

pub struct AppState {
    pub config: Config,
    pub info: Info,
    pub wallets: Wallets,
    pub tickets: Store,
    pub egress: Arc<Egress>,
    pub capacity: Arc<Semaphore>,
    pub signing_key: [u8; 32],
    /// Tickets with a notarization session running, and whether that
    /// session's bridge was opened.
    pub active: Mutex<HashMap<String, bool>>,
}

pub fn notary_key(signing_key: &[u8; 32], valid_from: Option<u64>) -> anyhow::Result<NotaryKeyInfo> {
    use tlsn::attestation::signing::Signer;
    let vk = tlsn::attestation::signing::Secp256k1Signer::new(signing_key)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .verifying_key();
    Ok(NotaryKeyInfo {
        alg: vk.alg.to_string(),
        key: hex::encode(vk.data),
        valid_from,
        valid_until: None,
    })
}

pub fn build_info(config: &Config, mints: Vec<String>, key: NotaryKeyInfo) -> Info {
    Info {
        protocol: PROTOCOL.into(),
        tlsn_version: TLSN_VERSION.into(),
        name: config.name.clone(),
        description: config.description.clone(),
        unit: "sat".into(),
        mints,
        tiers: config.tiers.iter().map(TierConfig::info).collect(),
        notary_key: key,
        previous_keys: config.previous_keys.clone(),
        ticket_ttl_secs: config.ticket_ttl_secs,
        ticket_attempts: config.ticket_attempts,
        egress: EgressInfo {
            port: crate::egress::PORT,
            per_host_per_hour: config.egress.per_host_per_hour,
        },
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    // Pages on any origin may buy tickets: no cookies are involved, and the
    // payment request travels in X-Cashu, which must be readable.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([HeaderName::from_static("x-cashu"), header::CONTENT_TYPE])
        .expose_headers([HeaderName::from_static("x-cashu"), header::RETRY_AFTER]);
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/info", get(info_handler))
        .route("/.well-known/tlsnc-notary.json", get(well_known))
        .route("/v1/tickets", post(buy_ticket))
        .route("/v1/tickets/status", post(ticket_status))
        .route("/v1/notarize", get(notarize))
        .route("/v1/bridge", get(bridge_handler))
        .layer(cors)
        .with_state(state)
}

fn error(status: StatusCode, code: &str, msg: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            code: code.into(),
            error: msg.into(),
        }),
    )
        .into_response()
}

fn ticket_error(e: TicketError) -> Response {
    let status = match e {
        TicketError::Unknown => StatusCode::UNAUTHORIZED,
        TicketError::Expired | TicketError::Spent | TicketError::NoAttempts => StatusCode::GONE,
    };
    let code = match e {
        TicketError::Unknown => "unknown_ticket",
        TicketError::Expired => "ticket_expired",
        TicketError::Spent => "ticket_spent",
        TicketError::NoAttempts => "no_attempts",
    };
    error(status, code, e.to_string())
}

async fn info_handler(State(s): State<Arc<AppState>>) -> Json<Info> {
    Json(s.info.clone())
}

async fn well_known(State(s): State<Arc<AppState>>) -> Json<WellKnown> {
    let mut keys = vec![s.info.notary_key.clone()];
    keys.extend(s.info.previous_keys.iter().cloned());
    Json(WellKnown {
        name: s.info.name.clone(),
        keys,
    })
}

#[derive(Deserialize)]
struct TicketQuery {
    tier: String,
    #[serde(default = "default_egress")]
    egress: String,
}

fn default_egress() -> String {
    "client".into()
}

async fn buy_ticket(State(s): State<Arc<AppState>>, Query(q): Query<TicketQuery>, headers: HeaderMap) -> Response {
    let Some(tier) = s.config.tier(&q.tier) else {
        return error(StatusCode::BAD_REQUEST, "unknown_tier", format!("no tier `{}`", q.tier));
    };
    let egress: tlsnc_protocol::Egress = match q.egress.parse() {
        Ok(e) => e,
        Err(e) => return error(StatusCode::BAD_REQUEST, "bad_egress", e),
    };
    let price = tier.price.for_egress(egress);

    let token = headers.get("x-cashu").and_then(|v| v.to_str().ok()).map(str::trim);
    let Some(token) = token.filter(|t| !t.is_empty()) else {
        let request = s
            .wallets
            .payment_request(price, &format!("tlsnc ticket {} egress={}", tier.id, egress.as_str()));
        let mut resp = error(
            StatusCode::PAYMENT_REQUIRED,
            "payment_required",
            format!("pay {price} sat in the X-Cashu header (NUT-24)"),
        );
        resp.headers_mut()
            .insert("x-cashu", HeaderValue::from_str(&request).expect("creq is ASCII"));
        return resp;
    };

    let received = match s.wallets.receive(token, price).await {
        Ok(r) => r,
        Err(e @ PayError::MintUnavailable(_)) => {
            warn!("payment: {e}");
            let mut resp = error(StatusCode::SERVICE_UNAVAILABLE, "mint_unavailable", e.to_string());
            resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
            return resp;
        }
        Err(PayError::ShortAfterFees { got, price, refund }) => {
            let body = serde_json::json!({
                "code": "insufficient_after_fees",
                "error": format!("redeemed {got} sat after mint fees, the price is {price}"),
                "refund": refund,
            });
            return (StatusCode::BAD_REQUEST, Json(body)).into_response();
        }
        Err(e @ PayError::Other(_)) => {
            warn!("payment: {e}");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "wallet_error", e.to_string());
        }
        Err(e) => return error(StatusCode::BAD_REQUEST, "bad_payment", e.to_string()),
    };

    match s.tickets.issue(
        &tier.id,
        egress,
        s.config.ticket_ttl_secs,
        s.config.ticket_attempts,
        &received.mint,
        received.amount,
    ) {
        Ok((ticket, expires_at)) => {
            info!(tier = %tier.id, egress = egress.as_str(), amount = received.amount, "ticket sold");
            Json(TicketResponse {
                ticket,
                expires_at,
                attempts: s.config.ticket_attempts,
                tier: tier.info(),
                egress,
                received: received.amount,
            })
            .into_response()
        }
        Err(e) => {
            // The money is in the wallet but no ticket exists. Loud, because
            // it needs a manual refund.
            tracing::error!(amount = received.amount, mint = %received.mint, "ticket not stored after payment: {e}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "store_error", "payment received but the ticket could not be stored; contact the operator")
        }
    }
}

#[derive(Deserialize)]
struct NotarizeQuery {
    ticket: Option<String>,
}

/// WebSocket subprotocol every client offers; the ticket rides along as a
/// second one, `tlsnc.tk_…`, so it never appears in a URL or an access log.
const SUBPROTOCOL: &str = "tlsnc";

fn ticket_from(query: Option<String>, headers: &HeaderMap) -> Option<String> {
    let from_header = headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .find_map(|p| p.strip_prefix("tlsnc.").filter(|t| t.starts_with(crate::tickets::PREFIX)))
        .map(str::to_string);
    from_header.or(query)
}

#[derive(Deserialize)]
struct StatusRequest {
    ticket: String,
}

/// Lets a browser find out why a WebSocket upgrade failed (it cannot see
/// the HTTP status): ticket state and whether the notary has room.
async fn ticket_status(State(s): State<Arc<AppState>>, Json(req): Json<StatusRequest>) -> Response {
    let ticket = match s.tickets.get(&req.ticket) {
        Ok(t) => t,
        Err(e) => return ticket_error(e),
    };
    let needed = s.config.tier(&ticket.tier).map(|t| t.memory_mb).unwrap_or(u32::MAX);
    let body = serde_json::json!({
        "tier": ticket.tier,
        "egress": ticket.egress,
        "expires_at": ticket.expires_at,
        "attempts_left": ticket.attempts_left,
        "spent": ticket.spent,
        "expired": ticket.expires_at < crate::tickets::now(),
        "session_running": s.active.lock().unwrap().contains_key(&ticket.hash),
        "capacity_available": s.capacity.available_permits() >= needed as usize,
    });
    Json(body).into_response()
}

/// Cleans up a session however it ends, including when the WebSocket upgrade
/// never completes (the callback is then dropped unrun).
struct SessionGuard {
    state: Arc<AppState>,
    hash: String,
    session_id: i64,
    started: bool,
    _permit: OwnedSemaphorePermit,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.state.active.lock().unwrap().remove(&self.hash);
        if !self.started {
            self.state.tickets.refund_attempt(&self.hash);
            self.state
                .tickets
                .finish(self.session_id, &self.hash, "none", Err("upgrade not completed"));
        }
    }
}

async fn notarize(
    State(s): State<Arc<AppState>>,
    Query(q): Query<NotarizeQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(ticket) = ticket_from(q.ticket, &headers) else {
        return error(StatusCode::UNAUTHORIZED, "no_ticket", "pass the ticket as the `tlsnc.<ticket>` subprotocol");
    };
    let ticket: Ticket = match s.tickets.usable(&ticket) {
        Ok(t) => t,
        Err(e) => return ticket_error(e),
    };
    let Some(tier) = s.config.tier(&ticket.tier).cloned() else {
        return error(StatusCode::GONE, "tier_retired", "this ticket's tier is no longer offered");
    };
    if s.active.lock().unwrap().contains_key(&ticket.hash) {
        return error(StatusCode::CONFLICT, "session_running", "a session for this ticket is already running");
    }
    let Ok(permit) = s.capacity.clone().try_acquire_many_owned(tier.memory_mb) else {
        let mut resp = error(StatusCode::SERVICE_UNAVAILABLE, "busy", "the notary is at capacity; retry shortly (the ticket is not used)");
        resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
        return resp;
    };
    let session_id = match s.tickets.start_attempt(&ticket.hash) {
        Ok(id) => id,
        Err(e) => return ticket_error(e),
    };
    s.active.lock().unwrap().insert(ticket.hash.clone(), false);
    let mut guard = SessionGuard {
        state: s.clone(),
        hash: ticket.hash.clone(),
        session_id,
        started: false,
        _permit: permit,
    };

    ws.max_message_size(MAX_WS_MESSAGE)
        .protocols([SUBPROTOCOL])
        .on_upgrade(move |socket| async move {
            guard.started = true;
            let ctx = SessionCtx {
                tier: tier.info(),
                ticket_egress: ticket.egress,
                egress: s.egress.clone(),
                signing_key: s.signing_key,
            };
            let io = crate::ws::into_stream(socket).compat();
            let timeout = Duration::from_secs(tier.timeout_secs);
            let outcome = match tokio::time::timeout(timeout, session::run(io, &ctx)).await {
                Ok(r) => r,
                Err(_) => Err(format!("session exceeded {} s", tier.timeout_secs)),
            };
            match &outcome {
                Ok(mode) => {
                    info!(tier = %tier.id, mode = mode.as_str(), "attestation issued");
                    s.tickets.finish(session_id, &ticket.hash, mode.as_str(), Ok(()));
                }
                Err(e) => {
                    warn!(tier = %tier.id, "session failed: {e}");
                    s.tickets.finish(session_id, &ticket.hash, "?", Err(e));
                }
            }
            drop(guard);
        })
}

#[derive(Deserialize)]
struct BridgeQuery {
    ticket: Option<String>,
    host: String,
}

async fn bridge_handler(
    State(s): State<Arc<AppState>>,
    Query(q): Query<BridgeQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(ticket) = ticket_from(q.ticket, &headers) else {
        return error(StatusCode::UNAUTHORIZED, "no_ticket", "pass the ticket as the `tlsnc.<ticket>` subprotocol");
    };
    let ticket = match s.tickets.get(&ticket) {
        Ok(t) => t,
        Err(e) => return ticket_error(e),
    };
    if ticket.spent || ticket.expires_at < crate::tickets::now() {
        return ticket_error(if ticket.spent { TicketError::Spent } else { TicketError::Expired });
    }
    if !ticket.egress.covers(tlsnc_protocol::Egress::Notary) {
        return error(StatusCode::FORBIDDEN, "egress_not_paid", "the bridge connects from the notary: it needs an egress=notary ticket");
    }
    let Some(tier) = s.config.tier(&ticket.tier).cloned() else {
        return error(StatusCode::GONE, "tier_retired", "this ticket's tier is no longer offered");
    };
    {
        let mut active = s.active.lock().unwrap();
        match active.get_mut(&ticket.hash) {
            None => {
                return error(StatusCode::CONFLICT, "no_session", "open the notarization session first, then the bridge");
            }
            Some(true) => {
                return error(StatusCode::CONFLICT, "bridge_used", "this session's bridge was already opened");
            }
            Some(used) => *used = true,
        }
    }
    let tcp = match s.egress.connect(&q.host).await {
        Ok(t) => t,
        Err(e) => {
            let status = match e {
                crate::egress::EgressError::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
                crate::egress::EgressError::Connect { .. } => StatusCode::BAD_GATEWAY,
                _ => StatusCode::FORBIDDEN,
            };
            return error(status, "egress_refused", e.to_string());
        }
    };
    info!(host = %q.host, tier = %tier.id, "bridge opened");
    ws.max_message_size(MAX_WS_MESSAGE).protocols([SUBPROTOCOL]).on_upgrade(move |socket| async move {
        bridge::relay(
            socket,
            tcp,
            tier.max_sent + EGRESS_SLACK_UP,
            tier.max_recv + EGRESS_SLACK_DOWN,
            Duration::from_secs(tier.timeout_secs),
        )
        .await;
    })
}
