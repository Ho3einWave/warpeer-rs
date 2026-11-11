//! Cloudflare WARP registration API client.
//!
//! Mirrors warp-plus `warp/api.go`. Phase 1 uses standard TLS (rustls via reqwest);
//! the uTLS-style ClientHello camouflage can be added later if needed.

use std::time::Duration;

use anyhow::{anyhow, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde_json::json;

use super::identity::{Account, Identity};

const API_BASE: &str = "https://api.cloudflareclient.com/v0a4005";
const CF_CLIENT_VERSION: &str = "a-6.30-3596";
const UA: &str = "okhttp/3.12.1";

pub struct WarpApi {
    client: reqwest::Client,
}

impl WarpApi {
    pub fn new() -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=UTF-8"),
        );
        headers.insert(USER_AGENT, HeaderValue::from_static(UA));
        headers.insert(
            "CF-Client-Version",
            HeaderValue::from_static(CF_CLIENT_VERSION),
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            // Without these a blackholed connection would hang startup forever.
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(WarpApi { client })
    }

    /// Register a new device, returning the issued identity.
    pub async fn register(&self, public_key: &str) -> Result<Identity> {
        let tos = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        let body = json!({
            "install_id": "",
            "fcm_token": "",
            "tos": tos,
            "key": public_key,
            "type": "Android",
            "model": "PC",
            "locale": "en_US",
            "warp_enabled": true,
        });

        let url = format!("{API_BASE}/reg");
        let resp = self.client.post(&url).json(&body).send().await?;
        ensure_ok(&resp)?;
        let ident = resp.json::<Identity>().await?;
        Ok(ident)
    }

    /// Fetch the account for a device.
    pub async fn get_account(&self, auth_token: &str, device_id: &str) -> Result<Account> {
        let url = format!("{API_BASE}/reg/{device_id}/account");
        let resp = self
            .client
            .get(&url)
            .header(AUTHORIZATION, bearer(auth_token)?)
            .send()
            .await?;
        ensure_ok(&resp)?;
        Ok(resp.json::<Account>().await?)
    }

    /// Apply a WARP+ license key to an account.
    pub async fn update_account(
        &self,
        auth_token: &str,
        device_id: &str,
        license: &str,
    ) -> Result<Account> {
        let url = format!("{API_BASE}/reg/{device_id}/account");
        let resp = self
            .client
            .put(&url)
            .header(AUTHORIZATION, bearer(auth_token)?)
            .json(&json!({ "license": license }))
            .send()
            .await?;
        ensure_ok(&resp)?;
        Ok(resp.json::<Account>().await?)
    }
}

fn bearer(token: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(&format!("Bearer {token}")).map_err(|e| anyhow!("bad auth token: {e}"))
}

fn ensure_ok(resp: &reqwest::Response) -> Result<()> {
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow!("WARP API request failed with status: {status}"));
    }
    Ok(())
}
