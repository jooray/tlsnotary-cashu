//! A small client-side Cashu wallet (cdk), so the CLI can pay notaries on
//! its own. One directory: seed, SQLite store, list of mints.

use std::{
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use cdk::{
    Amount,
    amount::SplitTarget,
    mint_url::MintUrl,
    nuts::{CurrencyUnit, MintQuoteState, PaymentMethod, Token, nut18::PaymentRequest},
    wallet::{ReceiveOptions, SendOptions, Wallet},
};
use cdk_sqlite::wallet::WalletSqliteDatabase;

pub struct ClientWallet {
    dir: PathBuf,
    seed: [u8; 64],
    db: Arc<WalletSqliteDatabase>,
}

impl ClientWallet {
    /// Opens the wallet in `dir`, creating it (with a new 12-word
    /// mnemonic) if it does not exist yet.
    pub async fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let seed = match Self::load_seed(dir)? {
            Some(seed) => seed,
            None => {
                let words = bip39::Mnemonic::generate(12)?;
                write_private(&dir.join("mnemonic"), format!("{words}\n").as_bytes())?;
                eprintln!(
                    "created a new wallet in {}; back up its words with `tlsnc backup`",
                    dir.display()
                );
                words.to_seed("")
            }
        };
        Self::with_seed(dir, seed).await
    }

    /// Creates a wallet in `dir` from backed-up words. Refuses to replace
    /// an existing wallet.
    pub async fn from_words(dir: &Path, words: &str) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        if Self::load_seed(dir)?.is_some() {
            bail!("{} already holds a wallet; restore into another directory", dir.display());
        }
        let words = bip39::Mnemonic::parse_normalized(words.trim()).context("not a valid BIP39 mnemonic")?;
        write_private(&dir.join("mnemonic"), format!("{words}\n").as_bytes())?;
        Self::with_seed(dir, words.to_seed("")).await
    }

    /// `mnemonic` (current) or `seed` (64 raw bytes, early versions).
    fn load_seed(dir: &Path) -> Result<Option<[u8; 64]>> {
        let words_path = dir.join("mnemonic");
        if words_path.exists() {
            let words = bip39::Mnemonic::parse_normalized(std::fs::read_to_string(&words_path)?.trim())
                .with_context(|| format!("{} is not a valid mnemonic", words_path.display()))?;
            return Ok(Some(words.to_seed("")));
        }
        let seed_path = dir.join("seed");
        if seed_path.exists() {
            let seed = std::fs::read(&seed_path)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("{} must hold 64 bytes", seed_path.display()))?;
            return Ok(Some(seed));
        }
        Ok(None)
    }

    async fn with_seed(dir: &Path, seed: [u8; 64]) -> Result<Self> {
        let db = Arc::new(WalletSqliteDatabase::new(dir.join("wallet.sqlite")).await?);
        Ok(Self {
            dir: dir.to_path_buf(),
            seed,
            db,
        })
    }

    /// The backup words, if this wallet has them.
    pub fn words(&self) -> Option<String> {
        std::fs::read_to_string(self.dir.join("mnemonic")).ok().map(|w| w.trim().to_string())
    }

    /// Recovers the proofs this seed ever received at `mint` (NUT-09/13).
    pub async fn restore(&self, mint: &str) -> Result<u64> {
        let mint = MintUrl::from_str(mint)?.to_string();
        let restored = self.wallet(&mint)?.restore().await?;
        let unspent = u64::from(restored.unspent);
        if unspent > 0 {
            self.remember(&mint)?;
        }
        Ok(unspent)
    }

    fn mints_file(&self) -> PathBuf {
        self.dir.join("mints.json")
    }

    pub fn mints(&self) -> Vec<String> {
        std::fs::read_to_string(self.mints_file())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn remember(&self, mint: &str) -> Result<()> {
        let mut mints = self.mints();
        if !mints.iter().any(|m| m == mint) {
            mints.push(mint.to_string());
            std::fs::write(self.mints_file(), serde_json::to_string_pretty(&mints)?)?;
        }
        Ok(())
    }

    pub fn wallet(&self, mint: &str) -> Result<Wallet> {
        Ok(Wallet::new(mint, CurrencyUnit::Sat, self.db.clone(), self.seed, None)?)
    }

    pub async fn balances(&self) -> Vec<(String, Result<u64>)> {
        let mut out = Vec::new();
        for mint in self.mints() {
            let b = match self.wallet(&mint) {
                Ok(w) => {
                    claim_paid(&w, &mint).await;
                    w.total_balance().await.map(u64::from).map_err(Into::into)
                }
                Err(e) => Err(e),
            };
            out.push((mint, b));
        }
        out
    }

    pub async fn receive(&self, token: &str) -> Result<(String, u64)> {
        let parsed = Token::from_str(token.trim()).context("not a Cashu token")?;
        let mint = parsed.mint_url()?.to_string();
        let wallet = self.wallet(&mint)?;
        let amount = wallet.receive(token.trim(), ReceiveOptions::default()).await?;
        self.remember(&mint)?;
        Ok((mint, u64::from(amount)))
    }

    /// Mints `amount` sat at `mint` over Lightning: prints the invoice and
    /// waits for it to be paid (test mints pay their own invoices).
    pub async fn mint(&self, mint: &str, amount: u64) -> Result<u64> {
        let mint = MintUrl::from_str(mint)?.to_string();
        let wallet = self.wallet(&mint)?;
        let quote = wallet
            .mint_quote(PaymentMethod::BOLT11, Some(Amount::from(amount)), None, None)
            .await?;
        // Remembered before waiting, so `balance` can claim a quote paid
        // after this process gave up.
        self.remember(&mint)?;
        print_invoice(&quote.request);
        eprintln!("waiting for payment…");
        let deadline = std::time::Instant::now() + Duration::from_secs(600);
        let mut delay = Duration::from_secs(3);
        loop {
            // Mints rate-limit quote checks (429); back off instead of failing.
            match wallet.check_mint_quote(&quote.id).await {
                Ok(q) if matches!(q.state, MintQuoteState::Paid | MintQuoteState::Issued) => break,
                Ok(_) => delay = Duration::from_secs(3),
                Err(e) => {
                    delay = (delay * 2).min(Duration::from_secs(30));
                    eprintln!("checking the invoice failed ({e}); retrying in {}s", delay.as_secs());
                }
            }
            if std::time::Instant::now() > deadline {
                bail!("invoice not paid within 10 minutes; if you pay it later, `tlsnc balance` claims it");
            }
            tokio::time::sleep(delay).await;
        }
        let proofs = wallet.mint(&quote.id, SplitTarget::default(), None).await?;
        Ok(proofs.iter().map(|p| u64::from(p.amount)).sum())
    }

    pub async fn send(&self, mint: &str, amount: u64) -> Result<String> {
        let mint = MintUrl::from_str(mint)?.to_string();
        let wallet = self.wallet(&mint)?;
        let prepared = wallet.prepare_send(Amount::from(amount), SendOptions::default()).await?;
        Ok(prepared.confirm(None).await?.to_string())
    }

    /// Pays a NUT-18 request from the first listed mint that has enough.
    pub async fn pay(&self, request: &PaymentRequest) -> Result<String> {
        let amount = request.amount.context("payment request without an amount")?;
        let ours = self.mints();
        for mint in &request.mints {
            let mint = mint.to_string();
            if !ours.contains(&mint) {
                continue;
            }
            let wallet = self.wallet(&mint)?;
            claim_paid(&wallet, &mint).await;
            if wallet.total_balance().await? < amount {
                continue;
            }
            // `a` is net of the receiver's input fees, so include them.
            let opts = SendOptions {
                include_fee: true,
                ..Default::default()
            };
            let prepared = wallet.prepare_send(amount, opts).await?;
            return Ok(prepared.confirm(None).await?.to_string());
        }
        bail!(
            "no wallet mint with {amount} sat among the notary's mints: {}",
            request.mints.iter().map(|m| m.to_string()).collect::<Vec<_>>().join(", ")
        )
    }
}

/// Mints Lightning invoices that were paid after `receive` stopped waiting.
async fn claim_paid(wallet: &Wallet, mint: &str) {
    match wallet.mint_unissued_quotes().await {
        Ok(a) if a > Amount::ZERO => eprintln!("claimed {a} sat from a paid invoice at {mint}"),
        Ok(_) => {}
        Err(e) => eprintln!("could not check unpaid invoices at {mint}: {e}"),
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

/// The invoice as a terminal QR code, then as text.
fn print_invoice(invoice: &str) {
    let uri = format!("lightning:{}", invoice.to_uppercase());
    if let Ok(code) = qrcode::QrCode::new(uri.as_bytes()) {
        let qr = code
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .build();
        eprintln!("{qr}");
    }
    eprintln!("pay this invoice:\n{invoice}\n");
}
