//! End-to-end over the real internet: notary session + client prover over an
//! in-memory pipe, MPC-TLS (and proxy mode) to a public server, then a
//! presentation and its verification. Needs network: `cargo test --release
//! -p tlsnc-notary --test e2e -- --ignored`.

use std::sync::Arc;

use tlsnc_client::{BodyReveal, HttpRequestSpec, Limits, RevealSpec, Target};
use tlsnc_notary::{
    config::EgressConfig,
    egress::Egress,
    session::{self, SessionCtx},
};
use tlsnc_protocol::{Egress as EgressClass, Prices, TierInfo};
use tokio_util::compat::TokioAsyncReadCompatExt;

const HOST: &str = "httpbin.org";

fn tier() -> TierInfo {
    TierInfo {
        id: "S".into(),
        max_sent: 4096,
        max_recv: 16 * 1024,
        max_recv_online: 16 * 1024,
        timeout_secs: 180,
        price: Prices { client: 42, notary: 210 },
    }
}

fn ctx(ticket_egress: EgressClass) -> SessionCtx {
    let egress = Egress::new(&EgressConfig {
        resolvers: vec!["1.1.1.1".parse().unwrap()],
        deny: vec![],
        per_host_per_hour: 100,
        connect_timeout_secs: 10,
    })
    .unwrap();
    SessionCtx {
        tier: tier(),
        ticket_egress,
        egress: Arc::new(egress),
        signing_key: [7u8; 32],
    }
}

async fn run(mode: &str, ticket_egress: EgressClass) -> Result<Vec<u8>, String> {
    let ctx = ctx(ticket_egress);
    let key = tlsnc_notary::app::notary_key(&ctx.signing_key, None).unwrap();
    let (notary_io, prover_io) = tokio::io::duplex(1 << 24);
    let notary = tokio::spawn(async move { session::run(notary_io.compat(), &ctx).await });

    let request = HttpRequestSpec::get(format!("https://{HOST}/json")).header("Accept", "application/json");
    let limits = Limits { max_sent: 4096, max_recv: 16 * 1024 };
    let target = if mode == "mpc" {
        let tcp = tokio::net::TcpStream::connect((HOST, 443)).await.unwrap();
        Target::Mpc(tcp.compat())
    } else {
        Target::Proxy
    };
    let result = tlsnc_client::notarize(prover_io.compat(), target, &request, limits, |s| {
        eprintln!("step: {}", s.as_str())
    })
    .await;
    let notary_result = notary.await.unwrap();
    let notarized = match result {
        Ok(n) => n,
        Err(e) => return Err(format!("prover: {e}; notary: {notary_result:?}")),
    };
    notary_result?;
    assert_eq!(notarized.response.status, 200);

    let spec = RevealSpec {
        response: tlsnc_client::ResponseReveal {
            headers: vec!["content-type".into()],
            body: BodyReveal::JsonPaths(vec!["slideshow.author".into()]),
        },
        ..Default::default()
    };
    let presentation = tlsnc_client::present_bytes(
        &notarized.attestation_bytes().unwrap(),
        &notarized.secrets_bytes().unwrap(),
        &spec,
    )
    .map_err(|e| e.to_string())?;

    let verified = tlsnc_verify::verify(&presentation, std::slice::from_ref(&key)).map_err(|e| e.to_string())?;
    eprintln!("{verified:#?}");
    assert_eq!(verified.server_name, HOST);
    assert!(verified.sent.starts_with("GET /json HTTP/1.1"));
    assert!(verified.received.contains("\"author\""));
    assert!(verified.received.contains("HTTP/1.1 200"));

    // A different key must not verify.
    let mut other = key;
    other.key = tlsnc_notary::app::notary_key(&[8u8; 32], None).unwrap().key;
    assert!(tlsnc_verify::verify(&presentation, &[other]).is_err());
    Ok(presentation)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs network"]
async fn mpc_client_egress() {
    run("mpc", EgressClass::Client).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs network"]
async fn proxy_mode_needs_notary_ticket() {
    let err = run("proxy", EgressClass::Client).await.unwrap_err();
    assert!(err.contains("egress=notary"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs network"]
async fn proxy_mode_with_notary_ticket() {
    run("proxy", EgressClass::Notary).await.unwrap();
}
