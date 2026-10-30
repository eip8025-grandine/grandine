//! Checks the publisher's messages against the code Grandine runs on them.

use std::{collections::HashSet, sync::Arc};

use anyhow::Result;
use bls::{SecretKey, SecretKeyBytes, traits::SecretKey as _};
use fork_choice_store::{Storage, Store, StoreConfig};
use proof_engine::{BackendSpec, ProofEngine as _, ProofVerdict, ZkvmProofEngine};
use pubkey_cache::PubkeyCache;
use scc::HashMap as SccHashMap;
use ssz::{Hc, ProgressiveList, SszHash as _};
use types::{
    combined::{BeaconState, SignedBeaconBlock},
    config::Config,
    deneb::primitives::KzgCommitment,
    eip8025::containers::ExecutionProofEnvelope,
    gloas::{
        beacon_state::BeaconState as GloasBeaconState,
        containers::{ExecutionPayload, ExecutionPayloadBid, ExecutionPayloadEnvelope},
    },
    nonstandard::{ForkInfo, StorageMode},
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        consts::FAR_FUTURE_EPOCH,
        containers::{
            BeaconBlock as Phase0BeaconBlock, BeaconBlockBody as Phase0BeaconBlockBody,
            BeaconBlockHeader, SignedBeaconBlock as Phase0SignedBeaconBlock, Validator,
        },
        primitives::{ExecutionAddress, H256},
    },
    preset::Minimal,
    traits::{BeaconState as _, SszValidatorList},
};

use crate::messages::{self, MOCK_PROOF_TYPE, SP1_FIXTURE, STEP_1_MOCK_PROOF, TAMPERED_BYTE};

// The ethereum-package default network ID.
const DEVNET_CHAIN_ID: u64 = 3_151_908;

struct NoopStorage;

impl Storage<Minimal> for NoopStorage {
    fn storage_mode(&self) -> StorageMode {
        StorageMode::default()
    }

    fn stored_state_by_block_root(
        &self,
        _block_root: H256,
        _finalized_validators: Option<&dyn SszValidatorList>,
    ) -> Result<Option<Arc<BeaconState<Minimal>>>> {
        Ok(None)
    }
}

fn devnet_config() -> Arc<Config> {
    Arc::new(Config {
        deposit_chain_id: DEVNET_CHAIN_ID,
        ..Config::minimal()
    })
}

// A Store anchored at an empty phase0 genesis, as `fork_choice_store`'s own
// execution-proof tests build one. Only its chain config and pubkey cache
// are used.
fn store(config: Arc<Config>) -> Store<Minimal, NoopStorage> {
    let body = Phase0BeaconBlockBody::<Minimal>::default();

    let state = Arc::new(BeaconState::<Minimal>::from(Phase0BeaconState {
        latest_block_header: BeaconBlockHeader {
            body_root: body.hash_tree_root(),
            ..Default::default()
        },
        ..Default::default()
    }));

    let block = Phase0SignedBeaconBlock {
        message: Hc::from(Phase0BeaconBlock {
            state_root: state.hash_tree_root(),
            body,
            ..Default::default()
        }),
        ..Default::default()
    };

    Store::new(
        config,
        Arc::new(PubkeyCache::default()),
        StoreConfig::default(),
        Arc::new(SignedBeaconBlock::<Minimal>::from(block)),
        state,
        Arc::new(NoopStorage),
        false,
        false,
        HashSet::default(),
        Arc::new(SccHashMap::new()),
    )
}

fn signing_key() -> SecretKey {
    let mut bytes = SecretKeyBytes::default();
    bytes.as_mut()[31] = 1;
    bytes.try_into().expect("scalar one is a valid secret key")
}

// B's envelope and the bid in B's block. Every field the request root reads
// is set, so a mix-up between sources changes the root.
fn payload_fixture() -> (
    ExecutionPayloadEnvelope<Minimal>,
    ExecutionPayloadBid<Minimal>,
) {
    let envelope = ExecutionPayloadEnvelope {
        payload: ExecutionPayload {
            fee_recipient: ExecutionAddress::repeat_byte(0xfe),
            block_number: 42,
            gas_used: 21_000,
            timestamp: 1_800_000_000,
            ..Default::default()
        },
        builder_index: 7,
        beacon_block_root: H256::repeat_byte(0xbb),
        parent_beacon_block_root: H256::repeat_byte(0xaa),
        ..Default::default()
    };

    let bid = ExecutionPayloadBid {
        slot: 8,
        blob_kzg_commitments: ProgressiveList::try_from(vec![
            KzgCommitment::repeat_byte(0x11),
            KzgCommitment::repeat_byte(0x22),
        ])
        .expect("two commitments fit"),
        ..Default::default()
    };

    (envelope, bid)
}

fn post_state(bid: ExecutionPayloadBid<Minimal>, key: &SecretKey) -> BeaconState<Minimal> {
    BeaconState::from(GloasBeaconState::<Minimal> {
        slot: 8,
        validators: core::iter::once(Validator {
            pubkey: key.to_public_key().into(),
            activation_epoch: 0,
            exit_epoch: FAR_FUTURE_EPOCH,
            ..Validator::default()
        })
        .collect(),
        latest_execution_payload_bid: bid,
        ..GloasBeaconState::default()
    })
}

#[test]
fn mock_proof_is_valid_for_the_public_input_the_store_builds() -> Result<()> {
    let config = devnet_config();
    let (payload_envelope, bid) = payload_fixture();

    let public_input = messages::public_input(&config, &payload_envelope, &bid)?;
    let envelope = messages::envelope(
        messages::mock_proof_data(public_input, STEP_1_MOCK_PROOF)?,
        MOCK_PROOF_TYPE,
        payload_envelope.beacon_block_root,
    );

    let state = post_state(bid, &signing_key());
    let execution_proof =
        store(Arc::clone(&config)).get_execution_proof(&state, &envelope, &payload_envelope)?;

    assert_eq!(execution_proof.public_input, public_input);

    let engine = ZkvmProofEngine::new(&config, [(MOCK_PROOF_TYPE, BackendSpec::ZkboostMock)])?;

    assert_eq!(
        engine.verify_execution_proof(execution_proof),
        ProofVerdict::Valid
    );

    Ok(())
}

#[test]
fn mock_proof_for_another_payload_is_invalid() -> Result<()> {
    let config = devnet_config();
    let (payload_envelope, bid) = payload_fixture();

    let mut other_bid = bid.clone();
    other_bid.blob_kzg_commitments = ProgressiveList::default();

    // Bound to B with no blobs, checked against B as it is.
    let public_input = messages::public_input(&config, &payload_envelope, &other_bid)?;
    let envelope = messages::envelope(
        messages::mock_proof_data(public_input, STEP_1_MOCK_PROOF)?,
        MOCK_PROOF_TYPE,
        payload_envelope.beacon_block_root,
    );

    let state = post_state(bid, &signing_key());
    let execution_proof =
        store(Arc::clone(&config)).get_execution_proof(&state, &envelope, &payload_envelope)?;

    let engine = ZkvmProofEngine::new(&config, [(MOCK_PROOF_TYPE, BackendSpec::ZkboostMock)])?;

    assert_eq!(
        engine.verify_execution_proof(execution_proof),
        ProofVerdict::Invalid
    );

    Ok(())
}

#[test]
fn envelope_signature_verifies_with_grandine_verification() -> Result<()> {
    let config = devnet_config();
    let key = signing_key();
    let (_, bid) = payload_fixture();
    let state = post_state(bid, &key);

    let envelope = ExecutionProofEnvelope {
        proof_data: messages::sp1_proof_data()?,
        proof_type: MOCK_PROOF_TYPE,
        beacon_block_root: H256::repeat_byte(0xbb),
    };

    let signed = messages::sign::<Minimal>(
        &config,
        ForkInfo::from_state(&state),
        state.slot(),
        envelope.clone(),
        0,
        &key,
    );

    store(Arc::clone(&config)).verify_execution_proof_envelope(&state, &signed)?;

    // The signature binds the fork: one made for another chain does not verify.
    let other_fork = ForkInfo {
        genesis_validators_root: H256::repeat_byte(1),
        ..ForkInfo::from_state(&state)
    };
    let signed = messages::sign::<Minimal>(&config, other_fork, state.slot(), envelope, 0, &key);

    store(config)
        .verify_execution_proof_envelope(&state, &signed)
        .expect_err("a signature for another fork should not verify");

    Ok(())
}

#[test]
fn tamper_flips_exactly_the_first_committed_public_value_byte() -> Result<()> {
    let tampered = messages::tampered_sp1_proof_data()?;
    let tampered = tampered.as_bytes();

    assert_eq!(tampered.len(), SP1_FIXTURE.len());
    assert_eq!(SP1_FIXTURE.len(), 1_272_611);

    let differing = SP1_FIXTURE
        .iter()
        .zip(tampered)
        .enumerate()
        .filter(|(_, (original, tampered))| original != tampered)
        .map(|(index, (original, tampered))| (index, original ^ tampered))
        .collect::<Vec<_>>();

    assert_eq!(differing, [(1_272_554, 1)]);
    assert_eq!(TAMPERED_BYTE, 1_272_554);

    // The committed public values follow their 8-byte little-endian length.
    assert_eq!(
        SP1_FIXTURE.get(TAMPERED_BYTE - 8..TAMPERED_BYTE),
        Some(43_u64.to_le_bytes().as_slice()),
    );

    Ok(())
}

#[test]
fn step_1_and_step_2_envelopes_differ() -> Result<()> {
    let config = devnet_config();
    let (payload_envelope, bid) = payload_fixture();
    let public_input = messages::public_input(&config, &payload_envelope, &bid)?;

    let envelope = |proof: &[u8]| -> Result<ExecutionProofEnvelope> {
        Ok(messages::envelope(
            messages::mock_proof_data(public_input, proof)?,
            MOCK_PROOF_TYPE,
            payload_envelope.beacon_block_root,
        ))
    };

    assert_ne!(
        envelope(STEP_1_MOCK_PROOF)?.hash_tree_root(),
        envelope(messages::STEP_2_MOCK_PROOF)?.hash_tree_root(),
    );

    Ok(())
}
