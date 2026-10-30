//! `config.toml`.

use std::{net::IpAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::Deserialize;
use tlsnc_protocol::{NotaryKeyInfo, Prices, TierInfo};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// `unix:/run/tlsnc/notary.sock` or `127.0.0.1:7150`.
    pub listen: String,
    /// Wallet, tickets, seed.
    pub data_dir: PathBuf,
    /// 32-byte secp256k1 key, hex. Created by `tlsnc-notary keygen`.
    pub signing_key_file: PathBuf,
    /// Unix seconds since which the current key signs; published so verifiers
    /// can tell it from retired keys.
    #[serde(default)]
    pub key_valid_from: Option<u64>,
    /// Retired keys, still published so old attestations keep verifying.
    #[serde(default)]
    pub previous_keys: Vec<NotaryKeyInfo>,
    /// Accepted mints, exactly as advertised in payment requests.
    pub mints: Vec<String>,
    #[serde(default = "default_ticket_ttl")]
    pub ticket_ttl_secs: u64,
    #[serde(default = "default_ticket_attempts")]
    pub ticket_attempts: u32,
    /// Total memory the notary may commit to concurrent sessions. Each
    /// session reserves its tier's `memory_mb` before the upgrade, when the
    /// mode (MPC or proxy) is not known yet.
    #[serde(default = "default_memory_budget")]
    pub memory_budget_mb: u32,
    pub egress: EgressConfig,
    pub tiers: Vec<TierConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressConfig {
    /// Public resolvers used for every target lookup (never /etc/resolv.conf).
    pub resolvers: Vec<IpAddr>,
    /// Networks the notary must never connect to, on top of every
    /// non-global range (our own hosts, home, VPN).
    #[serde(default)]
    pub deny: Vec<IpNet>,
    #[serde(default = "default_per_host")]
    pub per_host_per_hour: u32,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierConfig {
    pub id: String,
    pub max_sent: usize,
    pub max_recv: usize,
    #[serde(default = "default_recv_online")]
    pub max_recv_online: usize,
    pub timeout_secs: u64,
    /// Memory estimate reserved for one MPC session of this tier.
    pub memory_mb: u32,
    pub price: Prices,
}

fn default_ticket_ttl() -> u64 {
    1800
}
fn default_ticket_attempts() -> u32 {
    3
}
fn default_memory_budget() -> u32 {
    6000
}
fn default_per_host() -> u32 {
    30
}
fn default_connect_timeout() -> u64 {
    10
}
fn default_recv_online() -> usize {
    16 * 1024
}

impl TierConfig {
    pub fn info(&self) -> TierInfo {
        TierInfo {
            id: self.id.clone(),
            max_sent: self.max_sent,
            max_recv: self.max_recv,
            max_recv_online: self.max_recv_online,
            timeout_secs: self.timeout_secs,
            price: self.price,
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Config = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.mints.is_empty() {
            bail!("no mints configured");
        }
        if self.tiers.is_empty() {
            bail!("no tiers configured");
        }
        if self.egress.resolvers.is_empty() {
            bail!("egress.resolvers is empty");
        }
        for t in &self.tiers {
            if t.memory_mb > self.memory_budget_mb {
                bail!("tier {} needs {} MB, more than the whole budget", t.id, t.memory_mb);
            }
            if t.price.client == 0 || t.price.notary == 0 {
                bail!("tier {} has a zero price", t.id);
            }
            if t.price.notary < t.price.client {
                bail!("tier {}: notary egress must not be cheaper than client egress", t.id);
            }
        }
        Ok(())
    }

    pub fn tier(&self, id: &str) -> Option<&TierConfig> {
        self.tiers.iter().find(|t| t.id == id)
    }
}
