mod api;
mod wallet;
mod ws;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use tlsnc_client::{BodyReveal, HttpRequestSpec, Limits, RequestReveal, ResponseReveal, RevealSpec, Target};
use tlsnc_protocol::{Egress, NotaryKeyInfo};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::{api::Notary, api::Payer, wallet::ClientWallet};

#[derive(Parser)]
#[command(version, about = "Client for tlsnotary-cashu notaries: pay with Cashu, notarize, present, verify")]
struct Cli {
    /// Notary base URL. There is no public default: run your own (DEPLOY.md).
    #[arg(long, global = true, env = "TLSNC_NOTARY")]
    notary: Option<String>,
    /// Wallet directory (default ~/.tlsnc).
    #[arg(long, global = true, env = "TLSNC_WALLET")]
    wallet: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    /// MPC-TLS, this machine connects to the target (cheapest; our IP only).
    Mpc,
    /// tlsn proxy mode: the notary connects to the target.
    Proxy,
    /// MPC-TLS through the notary's browser bridge (for testing it).
    Bridge,
}

#[derive(Subcommand)]
enum Command {
    /// Show the notary's prices, tiers, mints and key.
    Info,
    /// Notarize one HTTPS request, paying from the wallet.
    Notarize {
        /// The HTTPS URL to fetch.
        url: String,
        #[arg(short = 'X', long, default_value = "GET")]
        method: String,
        /// Request header, `Name: value`. Repeatable.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Request body.
        #[arg(short = 'd', long)]
        data: Option<String>,
        #[arg(long, value_enum, default_value = "mpc")]
        mode: Mode,
        /// Tier id; default: the smallest one that fits the request.
        #[arg(long)]
        tier: Option<String>,
        /// Expected response size; default: the tier's maximum.
        #[arg(long)]
        max_recv: Option<usize>,
        /// Refuse to pay unless the notary's key is this (hex).
        #[arg(long)]
        expect_key: Option<String>,
        /// Output prefix: writes PREFIX.attestation and PREFIX.secrets.
        #[arg(short, long, default_value = "notarized")]
        out: PathBuf,
        /// Reuse a ticket from an earlier failed attempt instead of paying.
        #[arg(long)]
        ticket: Option<String>,
        /// Pay with this token (cashuA…/cashuB…) instead of the wallet.
        #[arg(long)]
        token: Option<String>,
    },
    /// Build a presentation (selective disclosure) from an attestation.
    Present {
        /// Prefix used with `notarize --out`.
        #[arg(default_value = "notarized")]
        prefix: PathBuf,
        /// Request headers whose values to reveal (default: host).
        #[arg(long)]
        request_header: Vec<String>,
        /// Reveal the request body.
        #[arg(long)]
        request_body: bool,
        /// Hide the request path and query.
        #[arg(long)]
        hide_target: bool,
        /// Response headers whose values to reveal (default: date, content-type).
        #[arg(long)]
        response_header: Vec<String>,
        /// Reveal only these JSON paths of the response body (repeatable).
        #[arg(long)]
        json: Vec<String>,
        /// Hide the response body entirely.
        #[arg(long, conflicts_with = "json")]
        hide_body: bool,
        /// Allow revealing Authorization, Cookie and similar values.
        #[arg(long)]
        allow_credentials: bool,
        #[arg(short, long, default_value = "notarized.presentation")]
        out: PathBuf,
    },
    /// Verify a presentation against trusted keys (default: the notary's
    /// published keys).
    Verify {
        presentation: PathBuf,
        /// Trusted notary key (hex) instead of the notary's. Repeatable.
        #[arg(long)]
        key: Vec<String>,
    },
    /// Wallet balance per mint.
    Balance,
    /// Top up the wallet: a number creates a Lightning invoice for that many
    /// sat, anything else is received as a Cashu token.
    Receive {
        /// `cashuB…` token, or an amount in sat.
        value: String,
        /// Mint for a Lightning top-up; default: the notary's first mint.
        #[arg(long)]
        mint: Option<String>,
    },
    /// Print a token worth AMOUNT sat (to move funds out of the wallet).
    Send {
        amount: u64,
        /// Default: the mint with the largest balance.
        #[arg(long)]
        mint: Option<String>,
    },
    /// Print the wallet's 12 backup words.
    Backup,
    /// Recreate a wallet from backup words and recover its funds.
    Restore {
        /// The 12 words, quoted.
        words: String,
        /// Mints to scan; default: the notary's mints. Repeatable.
        #[arg(long)]
        mint: Vec<String>,
    },
}

fn wallet_dir(arg: Option<PathBuf>) -> Result<PathBuf> {
    match arg {
        Some(dir) => Ok(dir),
        None => Ok(PathBuf::from(std::env::var("HOME").context("HOME is not set; pass --wallet")?).join(".tlsnc")),
    }
}

/// The MPC-TLS prover's futures are deep: on the main thread (8 MiB on
/// macOS) a session against a remote notary overflowed the stack. Every
/// thread that polls them gets 64 MiB.
const STACK: usize = 64 << 20;

fn main() -> Result<()> {
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(STACK)
                .build()?
                .block_on(run())
        })?
        .join()
        .unwrap_or_else(|_| bail!("the CLI thread panicked"))
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn,mpc_tls=error".into()),
        )
        .init();
    let cli = Cli::parse();
    let notary_url = || {
        cli.notary.clone().context(
            "no notary: pass --notary URL or set TLSNC_NOTARY (there is no public notary; \
             see https://github.com/jooray/tlsnotary-cashu/blob/main/deploy/DEPLOY.md)",
        )
    };
    let wallet = wallet_dir(cli.wallet)?;
    match cli.command {
        Command::Info => {
            let info = Notary::new(&notary_url()?).info().await?;
            println!("{}", serde_json::to_string_pretty(&info)?);
            if let Err(e) = info.check_compatible() {
                eprintln!("warning: incompatible notary: {e}");
            }
            Ok(())
        }
        Command::Notarize {
            url,
            method,
            headers,
            data,
            mode,
            tier,
            max_recv,
            expect_key,
            out,
            ticket,
            token,
        } => {
            let mut request = HttpRequestSpec::get(url);
            request.method = method.to_ascii_uppercase();
            for h in headers {
                let (k, v) = h.split_once(':').with_context(|| format!("bad header `{h}`"))?;
                request.headers.push((k.trim().to_string(), v.trim().to_string()));
            }
            request.body = data;
            let payer = match token {
                Some(t) => Payer::Token(t),
                None => Payer::Wallet(ClientWallet::open(&wallet).await?),
            };
            notarize(&notary_url()?, request, mode, tier, max_recv, expect_key, &out, ticket, payer).await
        }
        Command::Present {
            prefix,
            request_header,
            request_body,
            hide_target,
            response_header,
            json,
            hide_body,
            allow_credentials,
            out,
        } => {
            let mut spec = RevealSpec {
                allow_credentials,
                ..Default::default()
            };
            spec.request = RequestReveal {
                target: !hide_target,
                headers: if request_header.is_empty() {
                    RequestReveal::default().headers
                } else {
                    request_header
                },
                body: request_body,
            };
            spec.response = ResponseReveal {
                headers: if response_header.is_empty() {
                    ResponseReveal::default().headers
                } else {
                    response_header
                },
                body: if hide_body {
                    BodyReveal::None
                } else if !json.is_empty() {
                    BodyReveal::JsonPaths(json)
                } else {
                    BodyReveal::All
                },
            };
            let attestation = std::fs::read(with_ext(&prefix, "attestation"))?;
            let secrets = std::fs::read(with_ext(&prefix, "secrets"))?;
            let presentation = tlsnc_client::present_bytes(&attestation, &secrets, &spec)?;
            std::fs::write(&out, presentation)?;
            eprintln!("wrote {}", out.display());
            Ok(())
        }
        Command::Verify { presentation, key } => {
            let trusted: Vec<NotaryKeyInfo> = if key.is_empty() {
                Notary::new(&notary_url()?).well_known().await?.keys
            } else {
                key.into_iter()
                    .map(|k| NotaryKeyInfo {
                        alg: "k256".into(),
                        key: k,
                        valid_from: None,
                        valid_until: None,
                    })
                    .collect()
            };
            let bytes = std::fs::read(&presentation)?;
            let verified = tlsnc_verify::verify(&bytes, &trusted)?;
            println!("{}", serde_json::to_string_pretty(&verified)?);
            Ok(())
        }
        Command::Balance => {
            let w = ClientWallet::open(&wallet).await?;
            print_balances(&w).await;
            Ok(())
        }
        Command::Receive { value, mint } => {
            let w = ClientWallet::open(&wallet).await?;
            let value = value.trim();
            if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
                let amount: u64 = value.parse().context("amount")?;
                if amount == 0 {
                    bail!("amount must be positive");
                }
                let mint = match mint {
                    Some(m) => m,
                    None => {
                        let info = Notary::new(&notary_url()?).info().await?;
                        info.mints.first().context("the notary lists no mints")?.clone()
                    }
                };
                let got = w.mint(&mint, amount).await?;
                println!("received {got} sat at {mint}");
            } else {
                let (mint, amount) = w.receive(value).await?;
                println!("received {amount} sat at {mint}");
            }
            print_balances(&w).await;
            Ok(())
        }
        Command::Send { amount, mint } => {
            let w = ClientWallet::open(&wallet).await?;
            let mint = match mint {
                Some(m) => m,
                None => {
                    let mut best: Option<(String, u64)> = None;
                    for (m, b) in w.balances().await {
                        if let Ok(b) = b
                            && best.as_ref().is_none_or(|(_, x)| b > *x)
                        {
                            best = Some((m, b));
                        }
                    }
                    best.context("the wallet is empty")?.0
                }
            };
            println!("{}", w.send(&mint, amount).await?);
            Ok(())
        }
        Command::Backup => {
            let w = ClientWallet::open(&wallet).await?;
            match w.words() {
                Some(words) => {
                    println!("{words}");
                    eprintln!(
                        "\nThese words restore the wallet's funds at any mint it used \
                         (`tlsnc restore`). Keep them offline; anyone with them can spend."
                    );
                }
                None => bail!(
                    "this wallet predates backup words; move its funds with `tlsnc send` \
                     into a new wallet"
                ),
            }
            Ok(())
        }
        Command::Restore { words, mint } => {
            let w = ClientWallet::from_words(&wallet, &words).await?;
            let mints = if mint.is_empty() {
                Notary::new(&notary_url()?).info().await?.mints
            } else {
                mint
            };
            for m in mints {
                match w.restore(&m).await {
                    Ok(sat) => eprintln!("{sat:>10} sat  {m}"),
                    Err(e) => eprintln!("{:>10}      {m}  ({e})", "?"),
                }
            }
            print_balances(&w).await;
            Ok(())
        }
    }
}

async fn print_balances(w: &ClientWallet) {
    let mut total = 0;
    for (mint, b) in w.balances().await {
        match b {
            Ok(b) => {
                total += b;
                println!("{b:>10} sat  {mint}");
            }
            Err(e) => println!("{:>10}      {mint}  ({e})", "?"),
        }
    }
    println!("{total:>10} sat  total");
}

fn with_ext(prefix: &std::path::Path, ext: &str) -> PathBuf {
    let mut s = prefix.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

#[allow(clippy::too_many_arguments)]
async fn notarize(
    notary_url: &str,
    request: HttpRequestSpec,
    mode: Mode,
    tier: Option<String>,
    max_recv: Option<usize>,
    expect_key: Option<String>,
    out: &std::path::Path,
    ticket: Option<String>,
    payer: Payer,
) -> Result<()> {
    let notary = Notary::new(notary_url);
    let info = notary.info().await?;
    info.check_compatible().map_err(anyhow::Error::msg)?;
    if let Some(expected) = &expect_key
        && !info.notary_key.key.eq_ignore_ascii_case(expected) {
            bail!("notary key is {}, expected {expected}", info.notary_key.key);
        }

    let endpoint = request.endpoint()?;
    let egress = if mode == Mode::Mpc { Egress::Client } else { Egress::Notary };
    if egress == Egress::Notary && endpoint.port != info.egress.port {
        bail!("the notary only connects to port {}", info.egress.port);
    }
    let sent = request.wire_len()? + tlsnc_client::REQUEST_LEN_MARGIN;
    let tier = match tier {
        Some(id) => info.tier(&id).with_context(|| format!("no tier `{id}`"))?.clone(),
        None => info
            .smallest_tier_for(sent, max_recv.unwrap_or(0))
            .with_context(|| format!("no tier fits a {sent}-byte request"))?
            .clone(),
    };
    if sent > tier.max_sent {
        bail!("request is ~{sent} bytes, tier {} allows {}", tier.id, tier.max_sent);
    }
    let limits = Limits {
        max_sent: tier.max_sent,
        max_recv: max_recv.unwrap_or(tier.max_recv).min(tier.max_recv),
    };

    let ticket = match ticket {
        Some(t) => t,
        None => {
            eprintln!(
                "buying a tier {} ticket (egress={}) for {} sat",
                tier.id,
                egress.as_str(),
                tier.price.for_egress(egress)
            );
            let t = notary.buy_ticket(&info, &tier.id, egress, &payer).await?;
            // Printed so a failed attempt can be retried with --ticket.
            eprintln!("ticket: {} ({} attempts)", t.ticket, t.attempts);
            t.ticket
        }
    };

    let base = ws::ws_base(&notary.base);
    let notary_io = ws::connect(&format!("{base}/v1/notarize"), &ticket).await?;
    let on_step = |s: tlsnc_client::Step| eprintln!("… {}", s.as_str());
    let result = match mode {
        Mode::Mpc => {
            let (host, port) = (endpoint.host.clone(), endpoint.port);
            let server = Lazy::new(async move {
                let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
                    .await
                    .with_context(|| format!("connecting to {host}:{port}"))?;
                tcp.set_nodelay(true)?;
                Ok(tcp.compat())
            });
            tlsnc_client::notarize(notary_io.compat(), Target::Mpc(server), &request, limits, on_step).await
        }
        Mode::Proxy => {
            tlsnc_client::notarize(notary_io.compat(), Target::<tokio_util::compat::Compat<tokio::net::TcpStream>>::Proxy, &request, limits, on_step).await
        }
        Mode::Bridge => {
            let url = format!("{base}/v1/bridge?host={}", endpoint.host);
            let ticket = ticket.clone();
            let bridge = Lazy::new(async move {
                ws::connect(&url, &ticket).await.map(|s| s.compat()).context("bridge")
            });
            tlsnc_client::notarize(notary_io.compat(), Target::Mpc(bridge), &request, limits, on_step).await
        }
    };
    let notarized = result.map_err(|e| anyhow::anyhow!("{e}\n(retry with --ticket {ticket})"))?;

    std::fs::write(with_ext(out, "attestation"), notarized.attestation_bytes()?)?;
    std::fs::write(with_ext(out, "secrets"), notarized.secrets_bytes()?)?;
    eprintln!(
        "HTTP {} — wrote {} and {}",
        notarized.response.status,
        with_ext(out, "attestation").display(),
        with_ext(out, "secrets").display()
    );
    println!("{}", String::from_utf8_lossy(&notarized.response.body));
    Ok(())
}

/// A server stream that connects on first use. The prover touches it only
/// after MPC setup, which takes a minute or more over the internet: a TCP
/// connection opened before setup sits idle long enough for servers to
/// close it, and the notary opens a bridge only for a running session.
struct Lazy<S> {
    state: LazyState<S>,
}

type Connect<S> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<S>> + Send>>;

enum LazyState<S> {
    // Futures do nothing until polled, so this connects on first use.
    Connecting(Connect<S>),
    Ready(S),
    Failed,
}

impl<S: Unpin> Lazy<S> {
    fn new(connect: impl std::future::Future<Output = Result<S>> + Send + 'static) -> Self {
        Self {
            state: LazyState::Connecting(Box::pin(connect)),
        }
    }

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<&mut S>> {
        use std::task::Poll;
        if let LazyState::Connecting(fut) = &mut self.state {
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(s)) => self.state = LazyState::Ready(s),
                Poll::Ready(Err(e)) => {
                    self.state = LazyState::Failed;
                    return Poll::Ready(Err(std::io::Error::other(format!("{e:#}"))));
                }
            }
        }
        match &mut self.state {
            LazyState::Ready(s) => Poll::Ready(Ok(s)),
            _ => Poll::Ready(Err(std::io::Error::other("connection failed"))),
        }
    }
}

impl<S: futures::AsyncRead + Unpin> futures::AsyncRead for Lazy<S> {
    fn poll_read(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut [u8]) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut().poll_ready(cx) {
            std::task::Poll::Ready(Ok(s)) => std::pin::Pin::new(s).poll_read(cx, buf),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<S: futures::AsyncWrite + Unpin> futures::AsyncWrite for Lazy<S> {
    fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut().poll_ready(cx) {
            std::task::Poll::Ready(Ok(s)) => std::pin::Pin::new(s).poll_write(cx, buf),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match &mut self.get_mut().state {
            LazyState::Ready(s) => std::pin::Pin::new(s).poll_flush(cx),
            _ => std::task::Poll::Ready(Ok(())),
        }
    }

    fn poll_close(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match &mut self.get_mut().state {
            LazyState::Ready(s) => std::pin::Pin::new(s).poll_close(cx),
            _ => std::task::Poll::Ready(Ok(())),
        }
    }
}
