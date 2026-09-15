use bls::SecretKeyBytes;
use hex_literal::hex;
use ssz::Hc;
use std_ext::CopyExt as _;
use tap::{Conv as _, TryConv as _};
use types::{
    eip8025::{
        consts::STATELESS_INPUT_SCHEMA_ID,
        containers::{
            ExecutionProof, ExecutionProofEnvelope, ProofData, PublicInput,
            SignedExecutionProofEnvelope,
        },
        primitives::ProofType,
    },
    phase0::{beacon_state::BeaconState as Phase0BeaconState, containers::Fork},
    preset::Minimal,
};

use super::*;
use crate::error::Error;

const BEACON_BLOCK_ROOT: H256 = H256(hex!(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
));
const PROOF_TYPE: ProofType = 7;
const PROOF_DATA_LENGTH: usize = 100;

fn genesis_fork_state() -> Phase0BeaconState<Minimal> {
    let config = Config::minimal();

    Phase0BeaconState::<Minimal> {
        fork: Fork {
            previous_version: config.genesis_fork_version,
            current_version: config.genesis_fork_version,
            epoch: 0,
        },
        ..Phase0BeaconState::default()
    }
}

fn test_envelope() -> ExecutionProofEnvelope {
    let proof_data =
        ProofData::try_from(test_bytes(PROOF_DATA_LENGTH)).expect("proof data is within bounds");

    ExecutionProofEnvelope {
        proof_data,
        proof_type: PROOF_TYPE,
        beacon_block_root: BEACON_BLOCK_ROOT,
    }
}

fn test_bytes(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index % 256).expect("value modulo 256 should fit in u8"))
        .collect()
}

fn secret_key() -> SecretKey {
    b"????????????????????????????????"
        .copy()
        .conv::<SecretKeyBytes>()
        .try_conv::<SecretKey>()
        .expect("bytes encode a valid secret key")
}

fn signed_setup() -> (
    Config,
    Phase0BeaconState<Minimal>,
    ExecutionProofEnvelope,
    SecretKey,
    Arc<PublicKey>,
) {
    let config = Config::minimal();
    let state = genesis_fork_state();
    let envelope = test_envelope();
    let key = secret_key();
    let public_key = Arc::new(key.to_public_key());

    (config, state, envelope, key, public_key)
}

// (a) Independent transcription; do not call `get_domain`.
fn assert_signing_root_matches_formula(
    envelope: &ExecutionProofEnvelope,
    state: &Phase0BeaconState<Minimal>,
    slot: Slot,
) {
    let config = Config::minimal();
    let epoch = misc::compute_epoch_at_slot::<Minimal>(slot);
    let fork = state.fork();

    let fork_version = if epoch < fork.epoch {
        fork.previous_version
    } else {
        fork.current_version
    };

    let domain = misc::compute_domain(
        &config,
        DOMAIN_EXECUTION_PROOF,
        Some(fork_version),
        Some(state.genesis_validators_root()),
    );

    assert_eq!(
        domain,
        H256(hex!(
            "0f00000018ae4ccbda9538839d79bb18ca09e23e24ae8c1550f56cbb3d84b053"
        )),
    );

    assert_eq!(
        envelope.signing_root(&config, state, slot),
        misc::compute_signing_root(envelope, domain),
    );
}

#[test]
fn signing_root_matches_formula_in_current_fork() {
    let state = genesis_fork_state();
    let envelope = test_envelope();

    assert_signing_root_matches_formula(&envelope, &state, 0);
}

#[test]
fn signing_root_matches_formula_across_fork_boundary() {
    let config = Config::minimal();

    let state = Phase0BeaconState::<Minimal> {
        fork: Fork {
            previous_version: config.genesis_fork_version,
            current_version: hex!("01000001").into(),
            epoch: 1,
        },
        ..Phase0BeaconState::default()
    };

    let envelope = test_envelope();

    assert_signing_root_matches_formula(&envelope, &state, 0);
}

// (b) Pins from container suite + out-of-band script; not pyspec-checked.
#[test]
fn signing_root_matches_pinned_vector() {
    let config = Config::minimal();
    let state = genesis_fork_state();
    let envelope = test_envelope();

    assert_eq!(
        envelope.hash_tree_root(),
        H256(hex!(
            "024c73d1626ebced9a5e284ec4bd9d4f893e36609dd302c6e0a3b41d84ba396d"
        )),
    );

    assert_eq!(
        envelope.signing_root(&config, &state, 0),
        H256(hex!(
            "cde2fa0216202a493abf3206102c5367ed597806a7387cef9dc8e21e341fbc18"
        )),
    );
}

// (c) Round trip.
#[test]
fn sign_and_verify_round_trip() {
    let (config, state, envelope, key, public_key) = signed_setup();

    let signature = envelope.sign(&config, &state, 0, &key);

    envelope
        .verify(&config, &state, 0, signature.into(), public_key)
        .expect("signature should verify");
}

// (d) Tampering must fail with `SignatureKind::ExecutionProof`.
#[test]
fn tampered_message_is_rejected() {
    let (config, state, envelope, key, public_key) = signed_setup();

    let signature = envelope.sign(&config, &state, 0, &key).into();

    let mut tampered_envelope = test_envelope();
    tampered_envelope.beacon_block_root = H256::repeat_byte(0xff);

    let error = tampered_envelope
        .verify(&config, &state, 0, signature, public_key)
        .expect_err("tampered message should be rejected");

    assert!(matches!(
        error
            .downcast_ref::<Error>()
            .expect("error should be a signing error"),
        Error::SignatureInvalid(SignatureKind::ExecutionProof),
    ));

    assert_eq!(error.to_string(), "execution proof signature is invalid");
}

// (e) `Hc` delegates `hash_tree_root`, so bare and wrapped signatures match.
#[test]
fn hc_wrapper_preserves_envelope_signature() {
    let (config, state, envelope, key, public_key) = signed_setup();

    let signature = envelope.sign(&config, &state, 0, &key);

    let signed = SignedExecutionProofEnvelope {
        message: Hc::from(envelope.clone()),
        validator_index: 0,
        signature: signature.clone().into(),
    };

    assert_eq!(signed.message.hash_tree_root(), envelope.hash_tree_root());

    envelope
        .verify(&config, &state, 0, signature.into(), public_key)
        .expect("signature over envelope should verify");
}

// (f) Envelope signs `beacon_block_root`, not `public_input`.
#[test]
fn envelope_root_differs_from_bare_proof_root() {
    let config = Config::minimal();
    let envelope = test_envelope();

    let proof = ExecutionProof {
        proof_data: ProofData::try_from(test_bytes(PROOF_DATA_LENGTH))
            .expect("proof data is within bounds"),
        proof_type: PROOF_TYPE,
        public_input: PublicInput {
            new_payload_request_root: H256(hex!(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            )),
            successful_validation: true,
            chain_id: config.deposit_chain_id,
            schema_id: STATELESS_INPUT_SCHEMA_ID,
        },
    };

    assert_ne!(envelope.hash_tree_root(), proof.hash_tree_root());
}
