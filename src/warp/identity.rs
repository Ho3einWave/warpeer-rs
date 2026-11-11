//! WARP identity model + on-disk persistence.
//!
//! The JSON layout matches warp-plus / wgcf `wgcf-identity.json`, so identities
//! created by those tools can be loaded here and vice-versa.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const IDENTITY_FILE: &str = "wgcf-identity.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Account {
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub id: String,
    #[serde(default, rename = "account_type")]
    pub account_type: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerEndpoint {
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub v6: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Peer {
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub endpoint: PeerEndpoint,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceAddresses {
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub v6: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceConfig {
    #[serde(default)]
    pub addresses: InterfaceAddresses,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub peers: Vec<Peer>,
    #[serde(default)]
    pub interface: InterfaceConfig,
    #[serde(default)]
    pub client_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Identity {
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub account: Account,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub config: Config,
    /// Any other fields present in the file are preserved on round-trip.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Identity {
    /// First peer of the identity, or an error if there are none.
    pub fn peer(&self) -> Result<&Peer> {
        self.config
            .peers
            .first()
            .ok_or_else(|| anyhow!("identity contains 0 peers"))
    }

    /// Decode the 3-byte WARP reserved value from the base64 `client_id`.
    pub fn reserved(&self) -> Result<[u8; 3]> {
        let raw = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            self.config.client_id.trim(),
        )
        .with_context(|| "decoding client_id")?;
        if raw.len() < 3 {
            return Err(anyhow!("client_id shorter than 3 bytes"));
        }
        Ok([raw[0], raw[1], raw[2]])
    }
}

fn identity_path(dir: &Path) -> PathBuf {
    dir.join(IDENTITY_FILE)
}

/// Load an identity from `dir/wgcf-identity.json`.
pub fn load(dir: &Path) -> Result<Identity> {
    let path = identity_path(dir);
    let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let ident: Identity = serde_json::from_slice(&bytes).with_context(|| "parsing identity")?;
    if ident.config.peers.is_empty() {
        return Err(anyhow!("identity contains 0 peers"));
    }
    Ok(ident)
}

/// Persist an identity to `dir/wgcf-identity.json` (pretty-printed).
pub fn save(dir: &Path, ident: &Identity) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    restrict_dir_permissions(dir)?;
    let path = identity_path(dir);
    let json = serde_json::to_vec_pretty(ident)?;
    write_private(&path, &json)?;
    Ok(())
}

/// Write the identity file with owner-only permissions: it holds the device's
/// WireGuard private key.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;

    // `mode` only applies on creation; also tighten identities written by older
    // versions (or copied in from other tools).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_dir_permissions(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting permissions on {}", dir.display()))
}
