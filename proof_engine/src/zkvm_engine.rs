use core::panic::AssertUnwindSafe;
use std::{collections::BTreeMap, panic};

use logging::{debug_with_peers, warn_with_peers};
use ssz::{SszSize as _, SszWrite as _};
use thiserror::Error;
use types::{
    config::Config,
    eip8025::{
        containers::{ExecutionProof, PublicInput},
        primitives::ProofType,
    },
    phase0::primitives::ChainId,
};

#[cfg(feature = "sp1")]
use ere_verifier_sp1::{SP1ProgramVk, SP1Verifier, codec::Decode as _};

use crate::{backend::Backend, engine::ProofEngine, zkboost_mock::ZkboostMockBackend};
#[cfg(feature = "sp1")]
use crate::{backend::Binding, ere_backend::EreBackend};

// Also covers mainnet shadow forks, which keep the mainnet chain ID.
const MAINNET_CHAIN_ID: ChainId = 1;

/// How proofs of one proof type are verified.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackendSpec {
    /// Mock verification of zkboost `MockProof`s, with no cryptography.
    ///
    /// Only the public values a mock proof claims are checked.
    /// [`ZkvmProofEngine::new`] refuses it on mainnet.
    ZkboostMock,
    /// Real verification of ere SP1 proofs against one guest's verifying
    /// key.
    ///
    /// `program_vk` is the `bytes32` digest of the guest ELF, as
    /// `cargo prove vkey` prints it. It is the trust root.
    #[cfg(feature = "sp1")]
    Sp1 { program_vk: [u8; 32] },
}

#[derive(Debug, Error)]
pub enum ConstructionError {
    #[error("no proof types are configured; use NullProofEngine to opt out")]
    NoBackends,
    #[error("proof type {proof_type} is configured more than once")]
    DuplicateProofType { proof_type: ProofType },
    #[error("proof type {proof_type} uses mock verification, which is refused on mainnet")]
    MockOnMainnet { proof_type: ProofType },
    #[cfg(feature = "sp1")]
    #[error("proof type {proof_type} has an SP1 verifying key that does not decode")]
    InvalidVerifyingKey {
        proof_type: ProofType,
        source: ere_verifier_sp1::Error,
    },
}

/// Why [`ZkvmProofEngine::check`] rejected a proof.
///
/// Variants are listed in the order the checks run.
#[derive(Debug, Error)]
pub enum Rejection {
    #[error("proof type {proof_type} is not supported")]
    UnsupportedProofType { proof_type: ProofType },
    #[error("public input does not report successful validation")]
    UnsuccessfulValidation,
    #[error("mock proofs are not accepted for chain ID {MAINNET_CHAIN_ID}")]
    MockOnMainnet,
    #[error("proof data could not be decoded: {0}")]
    Decode(anyhow::Error),
    #[error("proof failed verification: {0}")]
    Verify(anyhow::Error),
    #[error("committed public values do not match the public input")]
    PublicValuesMismatch,
    #[error("verifier panicked: {0}")]
    Panic(anyhow::Error),
}

struct Entry {
    backend: Box<dyn Backend>,
    mock: bool,
}

/// A [`ProofEngine`] that verifies proofs with one fixed backend per
/// proof type.
///
/// The engine does not derive the `PublicInput`. It checks that the
/// public values a proof commits to bind the one it is given, and reads
/// only `successful_validation` and, for mock types, `chain_id`.
///
/// The public values are compared with the SSZ serialization of the
/// `PublicInput`, as zkboost and ere-guests commit them. This deviates
/// from consensus-specs, which binds `hash_tree_root(public_input)`.
pub struct ZkvmProofEngine {
    backends: BTreeMap<ProofType, Entry>,
}

impl ZkvmProofEngine {
    /// Builds an engine that verifies proofs of each given type with its
    /// backend. Proofs of any other type are rejected.
    ///
    /// Only `config.deposit_chain_id` is read, to refuse mock backends on
    /// mainnet.
    pub fn new(
        config: &Config,
        backends: impl IntoIterator<Item = (ProofType, BackendSpec)>,
    ) -> Result<Self, ConstructionError> {
        let mut entries = BTreeMap::new();

        for (proof_type, backend_spec) in backends {
            let entry = match backend_spec {
                BackendSpec::ZkboostMock => {
                    if config.deposit_chain_id == MAINNET_CHAIN_ID {
                        return Err(ConstructionError::MockOnMainnet { proof_type });
                    }

                    Entry {
                        backend: Box::new(ZkboostMockBackend),
                        mock: true,
                    }
                }
                #[cfg(feature = "sp1")]
                BackendSpec::Sp1 { program_vk } => {
                    let program_vk =
                        SP1ProgramVk::decode_from_slice(&program_vk).map_err(|source| {
                            ConstructionError::InvalidVerifyingKey { proof_type, source }
                        })?;

                    // This initializes ere's process-wide SP1 verifier, so its
                    // one-time setup cost falls on construction rather than on
                    // the first proof. Every SP1 backend shares it.
                    let verifier = SP1Verifier::new(program_vk);

                    // SP1 commits the public values unpadded.
                    Entry {
                        backend: Box::new(EreBackend::new(verifier, Binding::Exact)),
                        mock: false,
                    }
                }
            };

            if entries.insert(proof_type, entry).is_some() {
                return Err(ConstructionError::DuplicateProofType { proof_type });
            }
        }

        Self::from_entries(entries)
    }

    fn from_entries(backends: BTreeMap<ProofType, Entry>) -> Result<Self, ConstructionError> {
        if backends.is_empty() {
            return Err(ConstructionError::NoBackends);
        }

        for (proof_type, entry) in &backends {
            if entry.mock {
                warn_with_peers!(
                    "execution proofs of type {proof_type} use mock verification, \
                     with no cryptographic check"
                );
            }
        }

        Ok(Self { backends })
    }

    /// Checks an execution proof, cheapest checks first.
    pub fn check(&self, execution_proof: &ExecutionProof) -> Result<(), Rejection> {
        let ExecutionProof {
            proof_data,
            proof_type,
            public_input,
        } = execution_proof;

        let entry = self
            .backends
            .get(proof_type)
            .ok_or(Rejection::UnsupportedProofType {
                proof_type: *proof_type,
            })?;

        if !public_input.successful_validation {
            return Err(Rejection::UnsuccessfulValidation);
        }

        if entry.mock && public_input.chain_id == MAINNET_CHAIN_ID {
            return Err(Rejection::MockOnMainnet);
        }

        let public_values = panic::catch_unwind(AssertUnwindSafe(|| {
            entry.backend.public_values(proof_data.as_bytes())
        }))
        .map_err(|payload| Rejection::Panic(panics::payload_into_error(payload)))??;

        let mut serialized_public_input = [0; PublicInput::SIZE.fixed_part()];
        public_input.write_fixed(&mut serialized_public_input);

        if !entry
            .backend
            .binding()
            .matches(&public_values, &serialized_public_input)
        {
            return Err(Rejection::PublicValuesMismatch);
        }

        Ok(())
    }
}

impl ProofEngine for ZkvmProofEngine {
    fn is_null(&self) -> bool {
        false
    }

    fn verify_execution_proof(&self, execution_proof: ExecutionProof) -> bool {
        match self.check(&execution_proof) {
            Ok(()) => true,
            Err(rejection) => {
                debug_with_peers!(
                    "execution proof rejected (error: {rejection}, proof_type: {})",
                    execution_proof.proof_type,
                );

                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::anyhow;
    use ssz::{ByteList, H256, SszHash as _, SszReadDefault as _};
    use types::{
        eip8025::{
            consts::STATELESS_INPUT_SCHEMA_ID,
            containers::{NewPayloadRequest, ProofData},
        },
        preset::Mainnet,
    };

    use crate::{backend::Binding, zkboost_mock::MockProof};

    use super::*;

    // reth on SP1 in zkboost's provisional numbering, configured as mock.
    const MOCK_PROOF_TYPE: ProofType = 5;

    // devnet-8, the chain of the zkboost request fixture.
    const DEVNET_CHAIN_ID: ChainId = 7_091_047_534;

    // The zkboost devnet-8 request checked in by `types`. See
    // `types/src/eip8025/tests.rs` for its provenance.
    const ZKBOOST_NEW_PAYLOAD_REQUEST: &[u8] =
        include_bytes!("../../types/src/eip8025/fixtures/zkboost_new_payload_request.ssz");

    #[test]
    fn mock_accepts_matching_public_values() {
        let proof = mock_proof(test_public_input());

        check(&mock_engine(), proof).expect("matching mock proof should be accepted");
    }

    #[test]
    fn mock_rejects_changed_public_values() {
        let mut public_values = serialize(test_public_input());
        public_values[0] ^= 1;

        let proof = proof_with_values(MOCK_PROOF_TYPE, &public_values, test_public_input());

        assert_rejection(&mock_engine(), proof, |rejection| {
            matches!(rejection, Rejection::PublicValuesMismatch)
        });
    }

    // zkVMs with fixed-size public values zero-pad them, but zkboost mock
    // proofs commit the unpadded bytes, so padding does not bind.
    #[test]
    fn mock_rejects_zero_padded_public_values() {
        let mut public_values = serialize(test_public_input());
        public_values.resize(64, 0);

        let proof = proof_with_values(MOCK_PROOF_TYPE, &public_values, test_public_input());

        assert_rejection(&mock_engine(), proof, |rejection| {
            matches!(rejection, Rejection::PublicValuesMismatch)
        });
    }

    #[test]
    fn rejects_changed_public_input() {
        let committed = test_public_input();

        let changed_inputs = [
            PublicInput {
                new_payload_request_root: H256::repeat_byte(0x22),
                ..committed
            },
            PublicInput {
                chain_id: DEVNET_CHAIN_ID + 1,
                ..committed
            },
            PublicInput {
                schema_id: STATELESS_INPUT_SCHEMA_ID + 1,
                ..committed
            },
        ];

        for public_input in changed_inputs {
            let proof = ExecutionProof {
                public_input,
                ..mock_proof(committed)
            };

            assert_rejection(&mock_engine(), proof, |rejection| {
                matches!(rejection, Rejection::PublicValuesMismatch)
            });
        }
    }

    // The proof commits to the same unsuccessful input, so only the
    // validation check can reject it.
    #[test]
    fn rejects_unsuccessful_validation() {
        let public_input = PublicInput {
            successful_validation: false,
            ..test_public_input()
        };

        assert_rejection(&mock_engine(), mock_proof(public_input), |rejection| {
            matches!(rejection, Rejection::UnsuccessfulValidation)
        });
    }

    #[test]
    fn rejects_unsupported_proof_types() {
        for proof_type in [0, 255, 2] {
            let proof = ExecutionProof {
                proof_type,
                ..mock_proof(test_public_input())
            };

            assert_rejection(&mock_engine(), proof, |rejection| {
                matches!(
                    rejection,
                    Rejection::UnsupportedProofType { proof_type: rejected } if *rejected == proof_type
                )
            });
        }
    }

    // The proof commits to chain ID 1, so only the mainnet check can
    // reject it.
    #[test]
    fn mock_rejects_mainnet_chain_id() {
        let public_input = PublicInput {
            chain_id: MAINNET_CHAIN_ID,
            ..test_public_input()
        };

        assert_rejection(&mock_engine(), mock_proof(public_input), |rejection| {
            matches!(rejection, Rejection::MockOnMainnet)
        });
    }

    #[test]
    fn mock_rejects_undecodable_proof_data() {
        let valid = mock_proof(test_public_input())
            .proof_data
            .as_bytes()
            .to_vec();

        let undecodable = [
            // Empty.
            vec![],
            // Truncated inside `public_values`, so the second offset
            // points past the end.
            valid[..8 + 20].to_vec(),
            // Garbage: the first offset is not 8.
            vec![0xff; 64],
        ];

        for proof_data in undecodable {
            assert_rejection(
                &mock_engine(),
                proof_with_data(&proof_data, test_public_input()),
                |rejection| matches!(rejection, Rejection::Decode(_)),
            );
        }
    }

    #[test]
    fn mock_rejects_bad_offsets() {
        let valid = mock_proof(test_public_input())
            .proof_data
            .as_bytes()
            .to_vec();
        let length = u32::try_from(valid.len()).expect("mock proof length fits in u32");

        let with_offsets = |first: u32, second: u32| {
            let mut bytes = valid.clone();
            bytes[..4].copy_from_slice(&first.to_le_bytes());
            bytes[4..8].copy_from_slice(&second.to_le_bytes());
            bytes
        };

        let bad_offsets = [
            // The first offset must equal the fixed part.
            with_offsets(9, 51),
            // Offsets must not decrease.
            with_offsets(8, 7),
            // Offsets must not point past the end.
            with_offsets(8, length + 1),
        ];

        for proof_data in bad_offsets {
            assert_rejection(
                &mock_engine(),
                proof_with_data(&proof_data, test_public_input()),
                |rejection| matches!(rejection, Rejection::Decode(_)),
            );
        }
    }

    // Standard SSZ offsets treat appended bytes as part of the final
    // `proof` field. When decoding succeeds, the mock backend ignores
    // those bytes.
    #[test]
    fn mock_accepts_appended_bytes_as_part_of_proof() {
        let mut proof_data = mock_proof(test_public_input())
            .proof_data
            .as_bytes()
            .to_vec();
        proof_data.extend([0xcc; 5]);

        check(
            &mock_engine(),
            proof_with_data(&proof_data, test_public_input()),
        )
        .expect("appended bytes should be part of the ignored proof");
    }

    #[test]
    fn contains_backend_panics() {
        let engine = engine_with_backend(PanickingBackend);

        assert_rejection(&engine, mock_proof(test_public_input()), |rejection| {
            matches!(rejection, Rejection::Panic(_))
        });
    }

    #[test]
    fn reports_backend_verification_failures() {
        let engine = engine_with_backend(FailingBackend);

        assert_rejection(&engine, mock_proof(test_public_input()), |rejection| {
            matches!(rejection, Rejection::Verify(_))
        });
    }

    // PR 1's root, as Grandine builds `PublicInput` from a payload, binds
    // a zkboost mock proof of the same request. The canonical root does
    // not.
    #[test]
    fn zkboost_mock_proof_binds_zkboost_compatible_root() {
        let request = NewPayloadRequest::<Mainnet>::from_ssz_default(ZKBOOST_NEW_PAYLOAD_REQUEST)
            .expect("zkboost fixture should decode");

        let public_input = PublicInput {
            new_payload_request_root: request.zkboost_compatible_root(),
            successful_validation: true,
            chain_id: DEVNET_CHAIN_ID,
            schema_id: STATELESS_INPUT_SCHEMA_ID,
        };

        let proof = mock_proof(public_input);

        check(&mock_engine(), proof.clone())
            .expect("mock proof of the zkboost root should be accepted");

        let canonical = ExecutionProof {
            public_input: PublicInput {
                new_payload_request_root: request.hash_tree_root(),
                ..public_input
            },
            ..proof
        };

        assert_rejection(&mock_engine(), canonical, |rejection| {
            matches!(rejection, Rejection::PublicValuesMismatch)
        });
    }

    #[test]
    fn construction_rejects_empty_backends() {
        let result = ZkvmProofEngine::new(&Config::minimal(), []);

        assert!(
            matches!(result, Err(ConstructionError::NoBackends)),
            "{:?}",
            result.err(),
        );
    }

    #[test]
    fn construction_rejects_duplicate_proof_types() {
        let result = ZkvmProofEngine::new(
            &Config::minimal(),
            [
                (MOCK_PROOF_TYPE, BackendSpec::ZkboostMock),
                (MOCK_PROOF_TYPE, BackendSpec::ZkboostMock),
            ],
        );

        assert!(
            matches!(
                result,
                Err(ConstructionError::DuplicateProofType {
                    proof_type: MOCK_PROOF_TYPE,
                }),
            ),
            "{:?}",
            result.err(),
        );
    }

    #[test]
    fn construction_rejects_mock_on_mainnet() {
        let result = ZkvmProofEngine::new(
            &Config::mainnet(),
            [(MOCK_PROOF_TYPE, BackendSpec::ZkboostMock)],
        );

        assert!(
            matches!(
                result,
                Err(ConstructionError::MockOnMainnet {
                    proof_type: MOCK_PROOF_TYPE,
                }),
            ),
            "{:?}",
            result.err(),
        );
    }

    #[test]
    fn construction_accepts_mock_off_mainnet() {
        let engine = ZkvmProofEngine::new(
            &Config::minimal(),
            [(MOCK_PROOF_TYPE, BackendSpec::ZkboostMock)],
        )
        .expect("mock backends should be accepted off mainnet");

        assert!(!engine.is_null());
    }

    struct PanickingBackend;

    impl Backend for PanickingBackend {
        fn public_values(&self, _proof_data: &[u8]) -> Result<Vec<u8>, Rejection> {
            panic!("backend panicked");
        }

        fn binding(&self) -> Binding {
            Binding::Exact
        }
    }

    struct FailingBackend;

    impl Backend for FailingBackend {
        fn public_values(&self, _proof_data: &[u8]) -> Result<Vec<u8>, Rejection> {
            Err(Rejection::Verify(anyhow!("backend failed")))
        }

        fn binding(&self) -> Binding {
            Binding::Exact
        }
    }

    // Asserts that the engine upcast to `Arc<dyn ProofEngine>` agrees
    // with `check`, as callers hold it.
    fn check(engine: &Arc<ZkvmProofEngine>, proof: ExecutionProof) -> Result<(), Rejection> {
        let result = engine.check(&proof);
        let dyn_engine: Arc<dyn ProofEngine> = Arc::<ZkvmProofEngine>::clone(engine);

        assert_eq!(dyn_engine.verify_execution_proof(proof), result.is_ok());

        result
    }

    fn assert_rejection(
        engine: &Arc<ZkvmProofEngine>,
        proof: ExecutionProof,
        expected: impl FnOnce(&Rejection) -> bool,
    ) {
        match check(engine, proof) {
            Ok(()) => panic!("proof should be rejected"),
            Err(rejection) => assert!(expected(&rejection), "unexpected rejection: {rejection}"),
        }
    }

    fn mock_engine() -> Arc<ZkvmProofEngine> {
        let engine = ZkvmProofEngine::new(
            &Config::minimal(),
            [(MOCK_PROOF_TYPE, BackendSpec::ZkboostMock)],
        )
        .expect("mock backends should be accepted off mainnet");

        Arc::new(engine)
    }

    fn engine_with_backend(backend: impl Backend + 'static) -> Arc<ZkvmProofEngine> {
        let entry = Entry {
            backend: Box::new(backend),
            mock: false,
        };

        let engine = ZkvmProofEngine::from_entries([(MOCK_PROOF_TYPE, entry)].into())
            .expect("one backend should be accepted");

        Arc::new(engine)
    }

    fn test_public_input() -> PublicInput {
        PublicInput {
            new_payload_request_root: H256::repeat_byte(0x11),
            successful_validation: true,
            chain_id: DEVNET_CHAIN_ID,
            schema_id: STATELESS_INPUT_SCHEMA_ID,
        }
    }

    // A zkboost mock proof committing to `public_input`.
    fn mock_proof(public_input: PublicInput) -> ExecutionProof {
        proof_with_values(MOCK_PROOF_TYPE, &serialize(public_input), public_input)
    }

    fn proof_with_values(
        proof_type: ProofType,
        public_values: &[u8],
        public_input: PublicInput,
    ) -> ExecutionProof {
        let mock_proof = MockProof {
            public_values: ByteList::try_from(public_values.to_vec())
                .expect("public values should fit"),
            proof: ByteList::try_from(vec![0xbb; 32]).expect("proof should fit"),
        };

        ExecutionProof {
            proof_type,
            ..proof_with_data(
                &mock_proof
                    .to_ssz()
                    .expect("mock proof should be serializable"),
                public_input,
            )
        }
    }

    fn proof_with_data(proof_data: &[u8], public_input: PublicInput) -> ExecutionProof {
        ExecutionProof {
            proof_data: ProofData::try_from(proof_data.to_vec())
                .expect("proof data should be within bounds"),
            proof_type: MOCK_PROOF_TYPE,
            public_input,
        }
    }

    fn serialize(public_input: PublicInput) -> Vec<u8> {
        public_input
            .to_ssz()
            .expect("public input should be serializable")
    }

    // Real verification. These cases use `Config::mainnet()`, which shows
    // the mainnet guard does not affect real verification.
    #[cfg(feature = "sp1")]
    mod sp1 {
        use hex_literal::hex;

        use super::*;

        // ethrex on SP1 in zkboost's provisional numbering.
        const SP1_PROOF_TYPE: ProofType = 2;

        // A genuine zkboost execution proof and the public values its guest
        // commits, from zkboost `b83a23f9`
        // `crates/mock-beacon-node/tests/fixture/`. The blobs equal
        // Lighthouse `274af519`'s copies. sha256:
        // - `stateless-validator-ethrex-sp1-v6.4.0.proof`:
        //   `bc57e1a62930472a8a45d0b0490105deb3c10e4c9eedeca0f226a6409c4e8237`
        // - `public_values.bin`:
        //   `2bb490a0d717c8b53c9001b112a523bbaf58348f27a9d75d979e5d3aa66ae0e8`
        const ETHREX_SP1_PROOF: &[u8] =
            include_bytes!("fixtures/stateless-validator-ethrex-sp1-v6.4.0.proof");
        const COMMITTED_PUBLIC_VALUES: &[u8] = include_bytes!("fixtures/public_values.bin");

        // The proof embeds its public values here, after an 8-byte length.
        const EMBEDDED_PUBLIC_VALUES_OFFSET: usize = 1_272_554;

        // Guest VKs, as `cargo prove vkey` prints them. Each matches its
        // guest's GitHub release, ere-guests v0.17.0's `vk_sha256` and
        // Lighthouse's hex.
        // ethrex v26.0.0, sha256
        // `5e614b666d4f9a60a68d826833b94e2c5afa029b2dc501a45f3656059811a4d7`.
        const ETHREX_VK: [u8; 32] =
            hex!("00662ca6c9db4ecb22d9ac4c320612caeac9c320f92e3ab019af4f544e35c88b");
        // reth v0.1.0-rc.3, sha256
        // `420933f79a82fcb40880a97f0efb7780e6f939cbf6a0bbec716de24b8033df28`.
        const RETH_VK: [u8; 32] =
            hex!("00a03cbfa95559cfee3b45ef925f3f7a631181e35e774e92b040277d893511dd");

        #[test]
        fn fixture_embeds_committed_public_values() {
            let end = EMBEDDED_PUBLIC_VALUES_OFFSET + COMMITTED_PUBLIC_VALUES.len();

            assert_eq!(
                &ETHREX_SP1_PROOF[EMBEDDED_PUBLIC_VALUES_OFFSET - 8..EMBEDDED_PUBLIC_VALUES_OFFSET],
                43_u64.to_le_bytes(),
            );
            assert_eq!(
                &ETHREX_SP1_PROOF[EMBEDDED_PUBLIC_VALUES_OFFSET..end],
                COMMITTED_PUBLIC_VALUES,
            );
            assert_eq!(
                committed_public_input(),
                PublicInput {
                    new_payload_request_root: H256(hex!(
                        "68e2250786a622ab175a8149c63d220704e7ed9610a12b7864047510235e7bb7"
                    )),
                    successful_validation: true,
                    chain_id: MAINNET_CHAIN_ID,
                    schema_id: STATELESS_INPUT_SCHEMA_ID,
                },
            );
        }

        #[test]
        fn primary_proof_verifies() {
            check(
                &sp1_engine(ETHREX_VK),
                sp1_proof(ETHREX_SP1_PROOF, committed_public_input()),
            )
            .expect("genuine proof should verify under its guest's VK");
        }

        #[test]
        fn primary_proof_fails_under_other_vk() {
            assert_rejection(
                &sp1_engine(RETH_VK),
                sp1_proof(ETHREX_SP1_PROOF, committed_public_input()),
                |rejection| matches!(rejection, Rejection::Verify(_)),
            );
        }

        // The input matches the tampered values, so only the proof can
        // reject them.
        #[test]
        fn tampered_public_values_fail_verification() {
            let mut proof_data = ETHREX_SP1_PROOF.to_vec();
            proof_data[EMBEDDED_PUBLIC_VALUES_OFFSET] ^= 1;

            let mut root = committed_public_input().new_payload_request_root;
            root.as_bytes_mut()[0] ^= 1;

            let public_input = PublicInput {
                new_payload_request_root: root,
                ..committed_public_input()
            };

            assert_rejection(
                &sp1_engine(ETHREX_VK),
                sp1_proof(&proof_data, public_input),
                |rejection| matches!(rejection, Rejection::Verify(_)),
            );
        }

        #[test]
        fn rejects_undecodable_proof_data() {
            let undecodable = [
                // Empty.
                &[][..],
                // Truncated.
                &ETHREX_SP1_PROOF[..ETHREX_SP1_PROOF.len() - 1],
                // Garbage.
                &[0xff; 1024][..],
            ];

            for proof_data in undecodable {
                assert_rejection(
                    &sp1_engine(ETHREX_VK),
                    sp1_proof(proof_data, committed_public_input()),
                    |rejection| matches!(rejection, Rejection::Decode(_)),
                );
            }
        }

        #[test]
        fn rejects_trailing_bytes() {
            let mut proof_data = ETHREX_SP1_PROOF.to_vec();
            proof_data.push(0);

            assert_rejection(
                &sp1_engine(ETHREX_VK),
                sp1_proof(&proof_data, committed_public_input()),
                |rejection| matches!(rejection, Rejection::Decode(_)),
            );
        }

        #[test]
        fn rejects_changed_public_input() {
            let committed = committed_public_input();

            let changed_inputs = [
                PublicInput {
                    new_payload_request_root: H256::repeat_byte(0x22),
                    ..committed
                },
                PublicInput {
                    chain_id: DEVNET_CHAIN_ID,
                    ..committed
                },
                PublicInput {
                    schema_id: STATELESS_INPUT_SCHEMA_ID + 1,
                    ..committed
                },
            ];

            for public_input in changed_inputs {
                assert_rejection(
                    &sp1_engine(ETHREX_VK),
                    sp1_proof(ETHREX_SP1_PROOF, public_input),
                    |rejection| matches!(rejection, Rejection::PublicValuesMismatch),
                );
            }
        }

        #[test]
        fn rejects_unsuccessful_validation() {
            let public_input = PublicInput {
                successful_validation: false,
                ..committed_public_input()
            };

            assert_rejection(
                &sp1_engine(ETHREX_VK),
                sp1_proof(ETHREX_SP1_PROOF, public_input),
                |rejection| matches!(rejection, Rejection::UnsuccessfulValidation),
            );
        }

        #[test]
        fn rejects_unsupported_proof_types() {
            for proof_type in [0, 255, MOCK_PROOF_TYPE] {
                let proof = ExecutionProof {
                    proof_type,
                    ..sp1_proof(ETHREX_SP1_PROOF, committed_public_input())
                };

                assert_rejection(&sp1_engine(ETHREX_VK), proof, |rejection| {
                    matches!(
                        rejection,
                        Rejection::UnsupportedProofType { proof_type: rejected }
                            if *rejected == proof_type
                    )
                });
            }
        }

        // A real type never falls back to mock verification, even when the
        // engine also has a mock type.
        #[test]
        fn mock_proof_under_sp1_type_fails_to_decode() {
            let engine = ZkvmProofEngine::new(
                &Config::minimal(),
                [
                    (
                        SP1_PROOF_TYPE,
                        BackendSpec::Sp1 {
                            program_vk: ETHREX_VK,
                        },
                    ),
                    (MOCK_PROOF_TYPE, BackendSpec::ZkboostMock),
                ],
            )
            .expect("SP1 and mock backends should be accepted off mainnet");

            let engine = Arc::new(engine);
            let mock_proof = mock_proof(test_public_input());

            check(&engine, mock_proof.clone()).expect("mock proof should pass under its mock type");

            let under_sp1 = ExecutionProof {
                proof_type: SP1_PROOF_TYPE,
                ..mock_proof
            };

            assert_rejection(&engine, under_sp1, |rejection| {
                matches!(rejection, Rejection::Decode(_))
            });
        }

        #[test]
        fn construction_rejects_undecodable_vk() {
            // Not a canonical packing of KoalaBear field elements.
            let result = ZkvmProofEngine::new(
                &Config::mainnet(),
                [(
                    SP1_PROOF_TYPE,
                    BackendSpec::Sp1 {
                        program_vk: [0xff; 32],
                    },
                )],
            );

            assert!(
                matches!(
                    result,
                    Err(ConstructionError::InvalidVerifyingKey {
                        proof_type: SP1_PROOF_TYPE,
                        ..
                    }),
                ),
                "{:?}",
                result.err(),
            );
        }

        fn sp1_engine(program_vk: [u8; 32]) -> Arc<ZkvmProofEngine> {
            let engine = ZkvmProofEngine::new(
                &Config::mainnet(),
                [(SP1_PROOF_TYPE, BackendSpec::Sp1 { program_vk })],
            )
            .expect("SP1 backends should be accepted on mainnet");

            Arc::new(engine)
        }

        fn sp1_proof(proof_data: &[u8], public_input: PublicInput) -> ExecutionProof {
            ExecutionProof {
                proof_type: SP1_PROOF_TYPE,
                ..proof_with_data(proof_data, public_input)
            }
        }

        fn committed_public_input() -> PublicInput {
            PublicInput::from_ssz_default(COMMITTED_PUBLIC_VALUES)
                .expect("committed public values should decode")
        }
    }
}
