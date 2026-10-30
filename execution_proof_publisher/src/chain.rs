use std::path::Path;

use anyhow::{Result, ensure};
use types::{config::Config, phase0::primitives::ChainId};

/// Loads the enclave's network configuration from `config.yaml`, as
/// Grandine does for `--configuration-file`.
pub fn load_config(path: &Path) -> Result<Config> {
    let bytes = fs_err::read(path)?;
    let mut config = serde_yaml::from_slice::<Config>(&bytes)?;

    // Grandine warns about unknown variables and ignores them. So does this.
    config.unknown.clear();

    ensure_not_predefined(config.deposit_chain_id)?;

    Ok(config)
}

/// The chain IDs of the networks Grandine predefines.
///
/// The publisher signs with real validator keys and sends hostile proofs, so
/// it refuses to run against any of them.
#[must_use]
pub fn predefined_chain_ids() -> [ChainId; 4] {
    [
        Config::mainnet().deposit_chain_id,
        Config::sepolia().deposit_chain_id,
        Config::holesky().deposit_chain_id,
        Config::hoodi().deposit_chain_id,
    ]
}

pub fn ensure_not_predefined(chain_id: ChainId) -> Result<()> {
    ensure!(
        !predefined_chain_ids().contains(&chain_id),
        "DEPOSIT_CHAIN_ID {chain_id} belongs to a predefined network; \
         the publisher runs only against a devnet",
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn refuses_every_predefined_network() {
        for config in [
            Config::mainnet(),
            Config::sepolia(),
            Config::holesky(),
            Config::hoodi(),
        ] {
            ensure_not_predefined(config.deposit_chain_id)
                .expect_err("a predefined network should be refused");
        }
    }

    #[test]
    fn accepts_the_devnet() -> Result<()> {
        ensure_not_predefined(3_151_908)
    }

    #[test]
    fn load_config_refuses_a_predefined_chain_id() -> Result<()> {
        let mut file = tempfile::NamedTempFile::new()?;
        writeln!(file, "PRESET_BASE: mainnet\nDEPOSIT_CHAIN_ID: 11155111")?;

        load_config(file.path()).expect_err("Sepolia's chain ID should be refused");

        let mut file = tempfile::NamedTempFile::new()?;
        writeln!(
            file,
            "PRESET_BASE: mainnet\nDEPOSIT_CHAIN_ID: 3151908\nUNKNOWN_VARIABLE: 1"
        )?;

        assert_eq!(load_config(file.path())?.deposit_chain_id, 3_151_908);

        Ok(())
    }
}
