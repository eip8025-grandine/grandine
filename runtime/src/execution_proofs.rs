use std::sync::Arc;

use anyhow::{Context as _, Result};
use logging::info_with_peers;
use proof_engine::{BackendSpec, NullProofEngine, ProofEngine, ZkvmProofEngine};
use thiserror::Error;
use types::{
    config::Config as ChainConfig,
    eip8025::primitives::{ProofType, get_supported_proof_types},
};

#[cfg(any(feature = "execution-proof-sp1", test))]
use types::phase0::primitives::H256;

/// Parses one `--execution-proof-type` value, `TYPE=mock` or `TYPE=sp1:VK`.
///
/// Duplicate types, mock verification on mainnet and verifying keys that do not decode are left
/// to [`ZkvmProofEngine::new`], which owns those rules.
pub fn parse_execution_proof_type(string: &str) -> Result<(ProofType, BackendSpec), Error> {
    let (proof_type, backend) = string.split_once('=').ok_or(Error::MissingBackend)?;

    let proof_type = proof_type
        .parse::<ProofType>()
        .map_err(|_| Error::InvalidProofType)?;

    if !get_supported_proof_types().contains(&proof_type) {
        return Err(Error::UnsupportedProofType { proof_type });
    }

    if backend == "mock" {
        return Ok((proof_type, BackendSpec::ZkboostMock));
    }

    let Some(program_vk) = backend.strip_prefix("sp1:") else {
        return Err(Error::UnknownBackend);
    };

    Ok((proof_type, sp1_backend(program_vk)?))
}

#[cfg(feature = "execution-proof-sp1")]
fn sp1_backend(program_vk: &str) -> Result<BackendSpec, Error> {
    let H256(program_vk) = program_vk.parse().map_err(|_| Error::InvalidVerifyingKey)?;
    Ok(BackendSpec::Sp1 { program_vk })
}

// `proof_engine/sp1` may still be enabled through feature unification. The parser refuses SP1
// regardless, so the node fails closed.
#[cfg(not(feature = "execution-proof-sp1"))]
const fn sp1_backend(_program_vk: &str) -> Result<BackendSpec, Error> {
    Err(Error::Sp1NotBuilt)
}

/// Builds the proof engine for `backends`, as parsed from `--execution-proof-type`.
///
/// With no backends the node opts out and gets [`NullProofEngine`].
pub fn build_proof_engine(
    chain_config: &ChainConfig,
    backends: &[(ProofType, BackendSpec)],
) -> Result<Arc<dyn ProofEngine>> {
    if backends.is_empty() {
        return Ok(Arc::new(NullProofEngine));
    }

    let engine = ZkvmProofEngine::new(chain_config, backends.iter().copied())
        .context("invalid --execution-proof-type")?;

    for (proof_type, backend_spec) in backends {
        info_with_peers!(
            "execution proofs of type {proof_type} are verified with {}",
            describe(*backend_spec),
        );
    }

    Ok(Arc::new(engine))
}

fn describe(backend_spec: BackendSpec) -> String {
    if backend_spec == BackendSpec::ZkboostMock {
        return "zkboost mock verification".to_owned();
    }

    #[cfg(feature = "execution-proof-sp1")]
    if let BackendSpec::Sp1 { program_vk } = backend_spec {
        return format!(
            "SP1 verification against verifying key {:#x}",
            H256(program_vk)
        );
    }

    format!("{backend_spec:?}")
}

#[derive(PartialEq, Eq, Debug, Error)]
pub enum Error {
    #[error("expected TYPE=BACKEND")]
    MissingBackend,
    #[error("TYPE must be a decimal proof type")]
    InvalidProofType,
    #[error(
        "proof type {proof_type} is not supported; supported proof types are {:?}",
        get_supported_proof_types()
    )]
    UnsupportedProofType { proof_type: ProofType },
    #[error("BACKEND must be mock or sp1:<VK>")]
    UnknownBackend,
    #[cfg(feature = "execution-proof-sp1")]
    #[error("VK must be exactly 32 bytes of hex, with or without 0x")]
    InvalidVerifyingKey,
    #[cfg(not(feature = "execution-proof-sp1"))]
    #[error("sp1 is not available: Grandine was built without `execution-proof-sp1`")]
    Sp1NotBuilt,
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use proof_engine::ConstructionError;
    use test_case::test_case;

    use super::*;

    // ethrex v26.0.0 on SP1, as `proof_engine` tests it.
    const ETHREX_VK: &str = "0x00662ca6c9db4ecb22d9ac4c320612caeac9c320f92e3ab019af4f544e35c88b";
    const ETHREX_VK_BYTES: [u8; 32] =
        hex!("00662ca6c9db4ecb22d9ac4c320612caeac9c320f92e3ab019af4f544e35c88b");

    #[test_case("1=mock", 1)]
    #[test_case("2=mock", 2)]
    #[test_case("3=mock", 3)]
    fn parses_mock(string: &str, expected_proof_type: ProofType) {
        let (proof_type, backend_spec) =
            parse_execution_proof_type(string).expect("value should parse");

        assert_eq!(proof_type, expected_proof_type);
        assert_eq!(backend_spec, BackendSpec::ZkboostMock);
    }

    #[test_case("0=mock" => Error::UnsupportedProofType { proof_type: 0 }; "type 0")]
    #[test_case("4=mock" => Error::UnsupportedProofType { proof_type: 4 }; "type 4")]
    #[test_case("256=mock" => Error::InvalidProofType; "type 256")]
    #[test_case("-1=mock" => Error::InvalidProofType; "negative type")]
    #[test_case("0x01=mock" => Error::InvalidProofType; "hex type")]
    #[test_case("1=foo" => Error::UnknownBackend; "unknown backend")]
    #[test_case("1=sp1" => Error::UnknownBackend; "sp1 without VK separator")]
    #[test_case("1=" => Error::UnknownBackend; "empty backend")]
    #[test_case("1" => Error::MissingBackend; "no backend")]
    #[test_case("=mock" => Error::InvalidProofType; "no type")]
    #[test_case("" => Error::MissingBackend; "empty")]
    fn rejects(string: &str) -> Error {
        parse_execution_proof_type(string).expect_err("value should be rejected")
    }

    #[test_case("2=sp1:"; "empty")]
    #[test_case("2=sp1:0x"; "prefix only")]
    #[test_case("2=sp1:0x00662ca6c9db4ecb22d9ac4c320612caeac9c320f92e3ab019af4f544e35c8"; "31 bytes")]
    #[test_case("2=sp1:0x00662ca6c9db4ecb22d9ac4c320612caeac9c320f92e3ab019af4f544e35c88b00"; "33 bytes")]
    #[test_case("2=sp1:0x00662ca6c9db4ecb22d9ac4c320612caeac9c320f92e3ab019af4f544e35c88"; "odd length")]
    #[test_case("2=sp1:0xzz662ca6c9db4ecb22d9ac4c320612caeac9c320f92e3ab019af4f544e35c88b"; "non-hex")]
    #[test_case("2=sp1:0X00662ca6c9db4ecb22d9ac4c320612caeac9c320f92e3ab019af4f544e35c88b"; "upper-case prefix")]
    fn rejects_malformed_verifying_key(string: &str) {
        let error = parse_execution_proof_type(string).expect_err("value should be rejected");

        // Without the feature every `sp1:` value is refused before its key is read.
        #[cfg(feature = "execution-proof-sp1")]
        assert_eq!(error, Error::InvalidVerifyingKey);
        #[cfg(not(feature = "execution-proof-sp1"))]
        assert_eq!(error, Error::Sp1NotBuilt);
    }

    #[cfg(not(feature = "execution-proof-sp1"))]
    #[test]
    fn refuses_sp1_without_feature() {
        let error = parse_execution_proof_type(&format!("2={}", sp1(ETHREX_VK)))
            .expect_err("sp1 should be refused without the feature");

        assert_eq!(error, Error::Sp1NotBuilt);
    }

    #[cfg(feature = "execution-proof-sp1")]
    #[test_case(ETHREX_VK; "with prefix")]
    #[test_case(ETHREX_VK.trim_start_matches("0x"); "without prefix")]
    fn parses_sp1(program_vk: &str) {
        let (proof_type, backend_spec) =
            parse_execution_proof_type(&format!("2={}", sp1(program_vk)))
                .expect("value should parse");

        assert_eq!(proof_type, 2);
        assert_eq!(
            backend_spec,
            BackendSpec::Sp1 {
                program_vk: ETHREX_VK_BYTES,
            },
        );
    }

    #[test]
    fn no_backends_build_null_engine() {
        let engine = build_proof_engine(&ChainConfig::mainnet(), &[])
            .expect("an empty list should build the null engine");

        assert!(engine.is_null());
    }

    #[test]
    fn mock_builds_engine_off_mainnet() {
        let engine = build_proof_engine(&ChainConfig::sepolia(), &[(1, BackendSpec::ZkboostMock)])
            .expect("mock should be accepted off mainnet");

        assert!(!engine.is_null());
    }

    #[test]
    fn mock_on_mainnet_is_refused() {
        let error = build_proof_engine(&ChainConfig::mainnet(), &[(1, BackendSpec::ZkboostMock)])
            .err()
            .expect("mock should be refused on mainnet");

        assert!(matches!(
            error.downcast_ref(),
            Some(ConstructionError::MockOnMainnet { proof_type: 1 }),
        ));
    }

    #[test]
    fn duplicate_type_is_refused() {
        let error = build_proof_engine(
            &ChainConfig::sepolia(),
            &[(1, BackendSpec::ZkboostMock), (1, BackendSpec::ZkboostMock)],
        )
        .err()
        .expect("a duplicate type should be refused");

        assert!(matches!(
            error.downcast_ref(),
            Some(ConstructionError::DuplicateProofType { proof_type: 1 }),
        ));
    }

    #[cfg(feature = "execution-proof-sp1")]
    #[test]
    fn non_canonical_verifying_key_is_refused() {
        let mut program_vk = [0; 32];
        program_vk[0] = 1;

        let error = build_proof_engine(
            &ChainConfig::mainnet(),
            &[(2, BackendSpec::Sp1 { program_vk })],
        )
        .err()
        .expect("a non-canonical verifying key should be refused");

        assert!(matches!(
            error.downcast_ref(),
            Some(ConstructionError::InvalidVerifyingKey { proof_type: 2, .. }),
        ));
    }

    #[cfg(feature = "execution-proof-sp1")]
    #[test]
    fn sp1_builds_engine_on_mainnet() {
        let engine = build_proof_engine(
            &ChainConfig::mainnet(),
            &[(
                2,
                BackendSpec::Sp1 {
                    program_vk: ETHREX_VK_BYTES,
                },
            )],
        )
        .expect("a real backend should be accepted on mainnet");

        assert!(!engine.is_null());
    }

    #[test]
    fn describes_verifying_key_in_full() {
        assert_eq!(format!("{:#x}", H256(ETHREX_VK_BYTES)), ETHREX_VK);
    }

    fn sp1(program_vk: &str) -> String {
        format!("sp1:{program_vk}")
    }
}
