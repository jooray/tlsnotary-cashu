//! The notary's Cashu wallet: one cdk wallet per whitelisted mint, sharing
//! one SQLite store and one seed. It only receives (swaps incoming tokens)
//! and, for sweeping, sends.

use std::{collections::BTreeMap, path::Path, str::FromStr, sync::Arc};

use anyhow::{Context, Result};
use cdk::{
    Amount,
    mint_url::MintUrl,
    nuts::{CurrencyUnit, Token, nut18::PaymentRequest},
    wallet::{ReceiveOptions, SendOptions, Wallet},
};
use cdk_sqlite::wallet::WalletSqliteDatabase;
use rand::RngCore;
use tracing::{info, warn};

#[derive(Debug, thiserror::Error)]
pub enum PayError {
    #[error("not a Cashu token")]
    NotAToken,
    #[error("tokens from {0} are not accepted")]
    WrongMint(String),
    #[error("unit must be sat")]
    WrongUnit,
    #[error("token is worth {got}, the price is {price}")]
    Insufficient { got: u64, price: u64 },
    #[error("token already spent")]
    Spent,
    #[error("the mint is unreachable, the token was not spent: {0}")]
    MintUnavailable(String),
    #[error("redeemed {got} after mint fees, the price is {price}; the refund token returns it")]
    ShortAfterFees { got: u64, price: u64, refund: Option<String> },
    #[error("wallet error: {0}")]
    Other(String),
}

/// A successful payment.
pub struct Received {
    pub mint: String,
    pub amount: u64,
}

pub struct Wallets {
    /// Keyed by the mint URL as configured (and advertised).
    wallets: BTreeMap<String, Wallet>,
}

fn load_or_create_seed(path: &Path) -> Result<[u8; 64]> {
    if path.exists() {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        return bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} must hold exactly 64 bytes", path.display()));
    }
    let mut seed = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    write_private(path, &seed)?;
    info!(path = %path.display(), "created wallet seed");
    Ok(seed)
}

/// Writes a file readable only by the owner.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}

fn normalize(url: &str) -> Option<String> {
    MintUrl::from_str(url).ok().map(|u| u.to_string())
}

impl Wallets {
    pub async fn open(data_dir: &Path, mints: &[String]) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let seed = load_or_create_seed(&data_dir.join("wallet.seed"))?;
        let db = Arc::new(
            WalletSqliteDatabase::new(data_dir.join("wallet.sqlite"))
                .await
                .context("opening wallet database")?,
        );
        let mut wallets = BTreeMap::new();
        for mint in mints {
            let wallet = Wallet::new(mint, CurrencyUnit::Sat, db.clone(), seed, None)
                .with_context(|| format!("wallet for {mint}"))?;
            // Finish or roll back any swap interrupted by a crash.
            match wallet.recover_incomplete_sagas().await {
                Ok(r) if r.recovered + r.compensated + r.failed > 0 => {
                    info!(%mint, recovered = r.recovered, compensated = r.compensated, failed = r.failed, "recovered wallet operations")
                }
                Ok(_) => {}
                Err(e) => warn!(%mint, "saga recovery failed: {e}"),
            }
            let key = normalize(mint).unwrap_or_else(|| mint.clone());
            wallets.insert(key, wallet);
        }
        Ok(Self { wallets })
    }

    pub fn mints(&self) -> Vec<String> {
        self.wallets.keys().cloned().collect()
    }

    /// NUT-18 payment request for `price` sat, from any whitelisted mint.
    pub fn payment_request(&self, price: u64, description: &str) -> String {
        let mints = self
            .wallets
            .keys()
            .filter_map(|m| MintUrl::from_str(m).ok())
            .collect();
        PaymentRequest::builder()
            .amount(price)
            .unit(CurrencyUnit::Sat)
            .single_use(true)
            .mints(mints)
            .description(description.to_string())
            .build()
            .to_string()
    }

    /// Checks a token against the whitelist and price, then swaps it at its
    /// mint. The received amount is net of the mint's input fees.
    pub async fn receive(&self, encoded: &str, price: u64) -> Result<Received, PayError> {
        let token = Token::from_str(encoded.trim()).map_err(|_| PayError::NotAToken)?;
        let mint_url = token.mint_url().map_err(|_| PayError::NotAToken)?.to_string();
        let wallet = self
            .wallets
            .get(&mint_url)
            .ok_or_else(|| PayError::WrongMint(mint_url.clone()))?;
        if token.unit().unwrap_or_default() != CurrencyUnit::Sat {
            return Err(PayError::WrongUnit);
        }
        let gross = u64::from(token.value().map_err(|_| PayError::NotAToken)?);
        if gross < price {
            return Err(PayError::Insufficient { got: gross, price });
        }

        let received = wallet
            .receive(encoded.trim(), ReceiveOptions::default())
            .await
            .map_err(|e| match e {
                cdk::Error::TokenAlreadySpent | cdk::Error::TokenPending => PayError::Spent,
                cdk::Error::HttpError(None, msg) => PayError::MintUnavailable(msg),
                cdk::Error::HttpError(Some(status), msg) if status >= 500 || status == 429 => {
                    PayError::MintUnavailable(format!("{status}: {msg}"))
                }
                other => PayError::Other(other.to_string()),
            })?;
        let net = u64::from(received);
        if net < price {
            // The mint's input fees ate into the payment. Hand back what we
            // got instead of keeping it for nothing.
            let refund = self.send(&mint_url, net).await.ok();
            return Err(PayError::ShortAfterFees { got: net, price, refund });
        }
        info!(mint = %mint_url, amount = net, "payment received");
        Ok(Received { mint: mint_url, amount: net })
    }

    pub async fn balances(&self) -> Vec<(String, Result<u64, String>)> {
        let mut out = Vec::new();
        for (mint, wallet) in &self.wallets {
            out.push((
                mint.clone(),
                wallet.total_balance().await.map(u64::from).map_err(|e| e.to_string()),
            ));
        }
        out
    }

    /// Creates a token worth `amount` from `mint`'s balance (sweeping).
    pub async fn send(&self, mint: &str, amount: u64) -> Result<String> {
        let key = normalize(mint).unwrap_or_else(|| mint.to_string());
        let wallet = self
            .wallets
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("{mint} is not a configured mint"))?;
        let prepared = wallet
            .prepare_send(Amount::from(amount), SendOptions::default())
            .await?;
        let token = prepared.confirm(None).await?;
        Ok(token.to_string())
    }
}
