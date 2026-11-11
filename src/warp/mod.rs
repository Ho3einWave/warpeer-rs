//! WARP identity + endpoint logic.

pub mod api;
pub mod endpoint;
pub mod identity;
pub mod key;

use anyhow::Result;
use std::path::Path;
use tracing::info;

pub use identity::Identity;

/// Load an identity from `dir`, or create + register a new one if none exists.
/// If a `license` is provided and differs from the stored one, the account is updated.
pub async fn load_or_create_identity(dir: &Path, license: &str) -> Result<Identity> {
    let api = api::WarpApi::new()?;

    let existing = identity::load(dir);
    let mut ident = match existing {
        Ok(i) => {
            info!(path = %dir.display(), "loaded existing warp identity");
            i
        }
        Err(e) => {
            info!(path = %dir.display(), error = %e, "no usable identity, creating a new one");
            // Keep the old file (even if it cannot be parsed) so a private key can be
            // recovered by hand; never silently destroy an identity.
            let path = dir.join(identity::IDENTITY_FILE);
            if path.exists() {
                let backup = dir.join(format!("{}.bak", identity::IDENTITY_FILE));
                let _ = std::fs::copy(&path, &backup);
            }
            let created = create_identity(&api, license).await?;
            identity::save(dir, &created)?;
            created
        }
    };

    // Update the license if it changed.
    if !license.is_empty() && ident.account.license != license {
        info!("updating account license key");
        api.update_account(&ident.token, &ident.id, license).await?;
        ident.account = api.get_account(&ident.token, &ident.id).await?;
        identity::save(dir, &ident)?;
    }

    Ok(ident)
}

async fn create_identity(api: &api::WarpApi, license: &str) -> Result<Identity> {
    let sk = key::generate_private_key();
    let pk = key::public_from_private(&sk);
    let private_b64 = key::encode_key_b64(&sk.to_bytes());
    let public_b64 = key::encode_key_b64(pk.as_bytes());

    info!("creating new warp identity");
    let mut ident = api.register(&public_b64).await?;

    if !license.is_empty() {
        info!("applying license key to new identity");
        api.update_account(&ident.token, &ident.id, license).await?;
        ident.account = api.get_account(&ident.token, &ident.id).await?;
    }

    // The API issues the public side; we keep our private key alongside it.
    ident.private_key = private_b64;
    Ok(ident)
}
