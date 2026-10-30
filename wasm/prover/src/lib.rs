//! WebAssembly bindings for the tlsnotary-cashu prover, presenter and
//! verifier. Used by `@tlsnc/client`; see packages/client.
//!
//! The page must be cross-origin isolated (COOP `same-origin`, COEP
//! `require-corp`): MPC runs on a rayon pool of web workers sharing memory.

#![cfg(target_arch = "wasm32")]

mod io;

use js_sys::{Function, Object, Reflect, Uint8Array};
use serde::{Deserialize, Serialize};
use tlsnc_client::{HttpRequestSpec, Limits, RevealSpec, Target};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::io::{JsIo, JsIoAdapter};

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &str = r#"
export interface IoChannel {
  read(): Promise<Uint8Array | null>;
  write(data: Uint8Array): Promise<void>;
  close(): Promise<void>;
}
"#;

fn js_err(e: impl std::fmt::Display) -> JsValue {
    JsError::new(&e.to_string()).into()
}

/// Starts the worker pool. Call once, before anything else.
#[wasm_bindgen]
pub async fn initialize(thread_count: usize) -> Result<(), JsValue> {
    console_error_panic_hook::set_once();
    JsFuture::from(web_spawn::start_spawner()).await?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .spawn_handler(|thread| {
            let _ = web_spawn::spawn(move || thread.run());
            Ok(())
        })
        .build_global()
        .map_err(js_err)?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsLimits {
    max_sent: usize,
    max_recv: usize,
}

/// Bytes the request occupies on the wire (counts against `max_sent`).
#[wasm_bindgen(js_name = requestWireLen)]
pub fn request_wire_len(request: JsValue) -> Result<usize, JsValue> {
    let request: HttpRequestSpec = serde_wasm_bindgen::from_value(request).map_err(js_err)?;
    request.wire_len().map_err(js_err)
}

/// Notarizes one request.
///
/// `notary` is an IoChannel to `/v1/notarize?ticket=…`. `server` is an
/// IoChannel to the target (a bridge) for MPC mode, or null for proxy mode.
/// `onStep(name)` is called with `setup`, `request`, `prove`, `attest`.
///
/// Resolves to `{ attestation: Uint8Array, secrets: Uint8Array, response:
/// { status, headers: [name, value][], body: Uint8Array } }`.
#[wasm_bindgen]
pub async fn notarize(
    request: JsValue,
    limits: JsValue,
    notary: JsIo,
    server: Option<JsIo>,
    on_step: Option<Function>,
) -> Result<JsValue, JsValue> {
    let request: HttpRequestSpec = serde_wasm_bindgen::from_value(request).map_err(js_err)?;
    let limits: JsLimits = serde_wasm_bindgen::from_value(limits).map_err(js_err)?;
    let limits = Limits {
        max_sent: limits.max_sent,
        max_recv: limits.max_recv,
    };
    let target = match server {
        Some(s) => Target::Mpc(JsIoAdapter::new(s)),
        None => Target::Proxy,
    };
    let step = |s: tlsnc_client::Step| {
        if let Some(f) = &on_step {
            let _ = f.call1(&JsValue::NULL, &JsValue::from_str(s.as_str()));
        }
    };
    let notarized = tlsnc_client::notarize(JsIoAdapter::new(notary), target, &request, limits, step)
        .await
        .map_err(js_err)?;

    let out = Object::new();
    let set = |k: &str, v: &JsValue| Reflect::set(&out, &JsValue::from_str(k), v);
    set(
        "attestation",
        &Uint8Array::from(notarized.attestation_bytes().map_err(js_err)?.as_slice()).into(),
    )?;
    set(
        "secrets",
        &Uint8Array::from(notarized.secrets_bytes().map_err(js_err)?.as_slice()).into(),
    )?;
    let response = Object::new();
    Reflect::set(&response, &"status".into(), &JsValue::from(notarized.response.status))?;
    Reflect::set(
        &response,
        &"headers".into(),
        &serde_wasm_bindgen::to_value(&notarized.response.headers).map_err(js_err)?,
    )?;
    Reflect::set(
        &response,
        &"body".into(),
        &Uint8Array::from(notarized.response.body.as_slice()).into(),
    )?;
    set("response", &response.into())?;
    Ok(out.into())
}

/// Builds a presentation. `spec` is a RevealSpec (see the Rust docs or
/// packages/client/src/types.ts).
#[wasm_bindgen]
pub fn present(attestation: &[u8], secrets: &[u8], spec: JsValue) -> Result<Uint8Array, JsValue> {
    let spec: RevealSpec = if spec.is_undefined() || spec.is_null() {
        RevealSpec::default()
    } else {
        serde_wasm_bindgen::from_value(spec).map_err(js_err)?
    };
    let bytes = tlsnc_client::present_bytes(attestation, secrets, &spec).map_err(js_err)?;
    Ok(Uint8Array::from(bytes.as_slice()))
}

/// Verifies a presentation against trusted keys
/// (`[{alg, key, valid_from?, valid_until?}]`). Returns the verified data.
#[wasm_bindgen]
pub fn verify(presentation: &[u8], trusted_keys: JsValue) -> Result<JsValue, JsValue> {
    let keys: Vec<tlsnc_protocol::NotaryKeyInfo> =
        serde_wasm_bindgen::from_value(trusted_keys).map_err(js_err)?;
    let verified = tlsnc_verify::verify(presentation, &keys).map_err(js_err)?;
    verified
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(js_err)
}

/// Versions this build speaks, to compare with the notary's `/info`.
#[wasm_bindgen]
pub fn versions() -> JsValue {
    let out = Object::new();
    let _ = Reflect::set(&out, &"protocol".into(), &tlsnc_protocol::PROTOCOL.into());
    let _ = Reflect::set(&out, &"tlsn".into(), &tlsnc_protocol::TLSN_VERSION.into());
    out.into()
}
