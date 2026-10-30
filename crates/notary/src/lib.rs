//! tlsnotary-cashu notary server. See DESIGN.md at the repository root.

pub mod app;
pub mod bridge;
pub mod config;
pub mod egress;
pub mod session;
pub mod tickets;
pub mod wallet;
pub mod ws;

use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};

/// Reads the 32-byte signing key (hex) from `path`.
pub fn load_signing_key(path: &Path) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let bytes = hex::decode(text.trim()).context("signing key must be hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))
}

/// Builds the whole application state from a config.
pub async fn build_state(config: config::Config) -> Result<Arc<app::AppState>> {
    let signing_key = load_signing_key(&config.signing_key_file)?;
    let wallets = wallet::Wallets::open(&config.data_dir, &config.mints).await?;
    let tickets = tickets::Store::open(&config.data_dir.join("tickets.sqlite"))?;
    let egress = Arc::new(egress::Egress::new(&config.egress)?);
    let key = app::notary_key(&signing_key, config.key_valid_from)?;
    let info = app::build_info(&config, config.mints.clone(), key);
    let capacity = Arc::new(tokio::sync::Semaphore::new(config.memory_budget_mb as usize));
    Ok(Arc::new(app::AppState {
        config,
        info,
        wallets,
        tickets,
        egress,
        capacity,
        signing_key,
        active: Default::default(),
    }))
}
