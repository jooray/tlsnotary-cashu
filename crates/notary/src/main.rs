use std::{path::PathBuf, str::FromStr};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tlsnc_notary::{app, build_state, config::Config, egress::Egress, load_signing_key, wallet};
use tracing::info;

#[derive(Parser)]
#[command(version, about = "TLSNotary notary paid per session with Cashu")]
struct Cli {
    /// Path to config.toml.
    #[arg(short, long, default_value = "/etc/tlsnc/config.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server.
    Serve,
    /// Create the signing key if it does not exist, print the public key.
    Keygen,
    /// Print the notary's public key info as JSON.
    Pubkey,
    /// Check whether the egress policy allows a host (resolves it).
    CheckHost { host: String },
    /// Ticket and revenue counters.
    Stats,
    #[command(subcommand)]
    Wallet(WalletCommand),
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Balance per mint.
    Balance,
    /// Print a token worth AMOUNT sat from MINT's balance (for sweeping).
    Send {
        #[arg(long)]
        mint: String,
        #[arg(long)]
        amount: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tlsn=warn,mpz=warn,cdk=warn".into()),
        )
        .init();
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    match cli.command {
        Command::Serve => serve(config).await,
        Command::Keygen => {
            let path = &config.signing_key_file;
            if !path.exists() {
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                let key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
                wallet::write_private(path, hex::encode(key.to_bytes()).as_bytes())?;
                eprintln!("created {}", path.display());
            }
            let key = app::notary_key(&load_signing_key(path)?, config.key_valid_from)?;
            println!("{}", serde_json::to_string_pretty(&key)?);
            Ok(())
        }
        Command::Pubkey => {
            let key = app::notary_key(&load_signing_key(&config.signing_key_file)?, config.key_valid_from)?;
            println!("{}", serde_json::to_string_pretty(&key)?);
            Ok(())
        }
        Command::CheckHost { host } => {
            let egress = Egress::new(&config.egress)?;
            match egress.resolve(&host).await {
                Ok(addr) => println!("allowed: {host} -> {addr}"),
                Err(e) => println!("refused: {e}"),
            }
            Ok(())
        }
        Command::Stats => {
            let store = tlsnc_notary::tickets::Store::open(&config.data_dir.join("tickets.sqlite"))?;
            let (tickets, spent, amount) = store.stats()?;
            println!("tickets sold: {tickets}\nattestations issued: {spent}\nreceived: {amount} sat");
            Ok(())
        }
        Command::Wallet(cmd) => {
            let wallets = wallet::Wallets::open(&config.data_dir, &config.mints).await?;
            match cmd {
                WalletCommand::Balance => {
                    for (mint, balance) in wallets.balances().await {
                        match balance {
                            Ok(b) => println!("{b:>10} sat  {mint}"),
                            Err(e) => println!("{:>10}      {mint}  ({e})", "?"),
                        }
                    }
                }
                WalletCommand::Send { mint, amount } => println!("{}", wallets.send(&mint, amount).await?),
            }
            Ok(())
        }
    }
}

async fn serve(config: Config) -> Result<()> {
    let listen = config.listen.clone();
    let state = build_state(config).await?;
    info!(
        name = %state.info.name,
        key = %state.info.notary_key.key,
        mints = state.info.mints.len(),
        "notary starting"
    );
    let router = app::router(state);
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    if listen == "systemd" {
        // Socket activation: systemd passes the listening socket as fd 3.
        use std::os::fd::FromRawFd;
        if std::env::var("LISTEN_FDS").ok().as_deref() != Some("1") {
            bail!("listen = \"systemd\" but no socket was passed (LISTEN_FDS)");
        }
        let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
        std_listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(std_listener)?;
        info!("listening on the socket passed by systemd");
        axum::serve(listener, router).with_graceful_shutdown(shutdown).await?;
    } else if let Some(path) = listen.strip_prefix("unix:") {
        let _ = std::fs::remove_file(path);
        let listener = tokio::net::UnixListener::bind(path).with_context(|| format!("binding {path}"))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        info!(%path, "listening");
        axum::serve(listener, router).with_graceful_shutdown(shutdown).await?;
    } else {
        let addr = std::net::SocketAddr::from_str(&listen).context("listen must be systemd, unix:PATH or IP:PORT")?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        info!(%addr, "listening");
        axum::serve(listener, router).with_graceful_shutdown(shutdown).await?;
    }
    Ok(())
}
