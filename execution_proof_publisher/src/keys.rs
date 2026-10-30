use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use bls::{PublicKeyBytes, SecretKey};
use eip_2335::Keystore;

/// A keystore found in the participant's keystore artifact, not yet
/// decrypted.
///
/// The layout is Teku's, which ethereum-package hands to Grandine:
/// `teku-keys/<name>.json` with its password in `teku-secrets/<name>.txt`.
pub struct KeystoreFile {
    pubkey: PublicKeyBytes,
    keystore_path: PathBuf,
    password_path: PathBuf,
}

impl KeystoreFile {
    pub const fn pubkey(&self) -> PublicKeyBytes {
        self.pubkey
    }

    pub fn decrypt(&self) -> Result<SecretKey> {
        let password = fs_err::read(&self.password_path)?;
        let normalized_password = eip_2335::normalize_password(password)?;

        let secret_key_bytes = parse(&self.keystore_path)?
            .decrypt(normalized_password.as_str())
            .with_context(|| format!("failed to decrypt {}", self.keystore_path.display()))?;

        Ok(secret_key_bytes.try_into()?)
    }
}

/// Lists the keystores in `keystore_dir`, in file-name order, paired with
/// their passwords in `password_dir`.
pub fn discover(keystore_dir: &Path, password_dir: &Path) -> Result<Vec<KeystoreFile>> {
    let mut paths = fs_err::read_dir(keystore_dir)?
        .map(|entry| Ok(entry?.path()))
        .collect::<Result<Vec<_>>>()?;

    paths.retain(|path| {
        path.extension()
            .is_some_and(|extension| extension == "json")
    });
    paths.sort();

    paths
        .into_iter()
        .map(|keystore_path| {
            let pubkey = parse(&keystore_path)?
                .pubkey()
                .with_context(|| format!("{} has no pubkey", keystore_path.display()))?;

            let file_stem = keystore_path
                .file_stem()
                .with_context(|| format!("{} has no file name", keystore_path.display()))?;

            let password_path = password_dir.join(file_stem).with_extension("txt");

            Ok(KeystoreFile {
                pubkey,
                keystore_path,
                password_path,
            })
        })
        .collect()
}

fn parse(keystore_path: &Path) -> Result<Keystore> {
    let bytes = fs_err::read(keystore_path)?;

    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse keystore {}", keystore_path.display()))
}
