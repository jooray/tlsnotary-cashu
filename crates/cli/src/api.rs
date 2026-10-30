//! The notary's HTTP API: `/info` and buying tickets (NUT-24).

use std::str::FromStr;

use anyhow::{Context, Result, bail};
use cdk::nuts::{CurrencyUnit, nut18::PaymentRequest};
use tlsnc_protocol::{Egress, ErrorBody, Info, TicketResponse, WellKnown};

use crate::wallet::ClientWallet;

pub enum Payer {
    /// A token the user already has.
    Token(String),
    Wallet(ClientWallet),
}

pub struct Notary {
    pub base: String,
    http: reqwest::Client,
}

async fn error_text(resp: reqwest::Response) -> String {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    match serde_json::from_str::<ErrorBody>(&body) {
        Ok(e) => format!("{status} {}: {}", e.code, e.error),
        Err(_) => format!("{status}: {body}"),
    }
}

impl Notary {
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn info(&self) -> Result<Info> {
        let resp = self.http.get(format!("{}/info", self.base)).send().await?;
        if !resp.status().is_success() {
            bail!("info: {}", error_text(resp).await);
        }
        Ok(resp.json().await?)
    }

    pub async fn well_known(&self) -> Result<WellKnown> {
        let resp = self
            .http
            .get(format!("{}/.well-known/tlsnc-notary.json", self.base))
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!("well-known: {}", error_text(resp).await);
        }
        Ok(resp.json().await?)
    }

    /// Buys a ticket: asks for the payment request, checks it against what
    /// `/info` promised, pays it, and returns the ticket.
    pub async fn buy_ticket(&self, info: &Info, tier: &str, egress: Egress, payer: &Payer) -> Result<TicketResponse> {
        let url = format!("{}/v1/tickets?tier={tier}&egress={}", self.base, egress.as_str());
        let tier_info = info.tier(tier).context("unknown tier")?;
        let expected = tier_info.price.for_egress(egress);

        let resp = self.http.post(&url).send().await?;
        if resp.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            bail!("expected 402, got {}", error_text(resp).await);
        }
        let creq = resp
            .headers()
            .get("x-cashu")
            .and_then(|v| v.to_str().ok())
            .context("402 without an X-Cashu payment request")?
            .to_string();
        let request = PaymentRequest::from_str(&creq).context("bad payment request")?;
        let amount = request.amount.map(u64::from).context("payment request without amount")?;
        if amount != expected {
            bail!("notary asks {amount} sat but advertises {expected}; refusing to pay");
        }
        if request.unit.as_ref() != Some(&CurrencyUnit::Sat) {
            bail!("unexpected unit {:?}", request.unit);
        }

        let token = match payer {
            Payer::Token(t) => t.clone(),
            Payer::Wallet(w) => w.pay(&request).await?,
        };
        let resp = self.http.post(&url).header("X-Cashu", token.trim()).send().await?;
        if !resp.status().is_success() {
            let text = error_text(resp).await;
            if let Payer::Wallet(_) = payer {
                // The token left the wallet; print it so it is not lost.
                eprintln!("payment failed; the unspent token, if the notary did not take it:\n{token}");
            }
            bail!("ticket: {text}");
        }
        Ok(resp.json().await?)
    }
}
