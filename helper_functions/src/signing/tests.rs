use bls::SecretKeyBytes;
use hex_literal::hex;
use ssz::Hc;
use std_ext::CopyExt as _;
use tap::{Conv as _, TryConv as _};
use types::{
    eip8025::{
        containers::{ExecutionProof, ProofData, PublicInput, SignedExecutionProof},
        primitives::ProofType,
    },
    phase0::{beacon_state::BeaconState as Phase0BeaconState, containers::Fork},
    preset::Minimal,
};

use super::*;
use crate::error::Error;

// Sample values mirrored exactly in the reference implementation.
const NEW_PAYLOAD_REQUEST_ROOT: H256 = H256(hex!(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
));
const PROOF_TYPE: ProofType = 7;
const PROOF_DATA_LENGTH: usize = 100;

// The base state forks at genesis (`fork.epoch == 0`), so the domain is always built from
// `fork.current_version` unless a test opts into the `previous_version` path.
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

fn test_proof() -> ExecutionProof {
    let proof_data =
        ProofData::try_from(test_bytes(PROOF_DATA_LENGTH)).expect("proof data is within bounds");

    ExecutionProof {
        proof_data,
        proof_type: PROOF_TYPE,
        public_input: PublicInput {
            new_payload_request_root: NEW_PAYLOAD_REQUEST_ROOT,
        },
    }
}

// Matches `test_bytes` in the reference implementation.
fn test_bytes(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index % 256).expect("value modulo 256 should fit in u8"))
        .collect()
}

// Mirrors the private `secret_key` helper in `verifier.rs`'s test module.
fn secret_key() -> SecretKey {
    b"????????????????????????????????"
        .copy()
        .conv::<SecretKeyBytes>()
        .try_conv::<SecretKey>()
        .expect("bytes encode a valid secret key")
}

// (a) Formula: `signing_root` must equal an independent transcription of the spec recipe.
// The fork version is selected the way `accessors::get_domain` selects it
// (`accessors.rs:551`): the epoch at the slot is compared against `fork.epoch`. The domain
// is additionally pinned to a literal computed out-of-band, the way `test_compute_domain`
// pins one in `misc.rs`; that anchors the domain independently of `get_domain`.
fn assert_signing_root_matches_formula(
    proof: &ExecutionProof,
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
        proof.signing_root(&config, state, slot),
        misc::compute_signing_root(proof, domain),
    );
}

#[test]
fn signing_root_matches_formula_in_current_fork() {
    let state = genesis_fork_state();
    let proof = test_proof();

    // Slot 0 is in epoch 0, the state's current fork epoch.
    assert_signing_root_matches_formula(&proof, &state, 0);
}

#[test]
fn signing_root_matches_formula_across_fork_boundary() {
    let config = Config::minimal();

    let state = Phase0BeaconState::<Minimal> {
        fork: Fork {
            previous_version: config.genesis_fork_version,
            // Minimal's Altair fork version. Distinct from `previous_version` so that a
            // wrong fork selection changes the domain and fails the pinned domain below.
            current_version: hex!("01000001").into(),
            epoch: 1,
        },
        ..Phase0BeaconState::default()
    };

    let proof = test_proof();

    // Slot 0 is in epoch 0, which is before `fork.epoch` 1.
    assert_signing_root_matches_formula(&proof, &state, 0);
}

// (b) Pinned vector. The object root is the length-100 reference root from the container
// workstream (`types/src/eip8025/tests.rs`), produced by an independent implementation of
// the EIP-8025 merkleization rules and not cross-checked against the pyspec. The signing
// root was computed out-of-band by an independent script as
// `sha256(object_root ++ domain)` over the pinned domain, mirroring `SigningData`
// merkleization; it inherits the same caveat.
#[test]
fn signing_root_matches_pinned_vector() {
    let config = Config::minimal();
    let state = genesis_fork_state();
    let proof = test_proof();

    assert_eq!(
        proof.hash_tree_root(),
        H256(hex!(
            "9727e301e9d88ac931277369c166b74568fd7b5172417944a7245a43a08cfbf5"
        )),
    );

    assert_eq!(
        proof.signing_root(&config, &state, 0),
        H256(hex!(
            "437b6ffa8ebcc64190a33c510af5a1ed19f649eff7bca884bc6dac505548f160"
        )),
    );
}

// (c) Round trip.
#[test]
fn sign_and_verify_round_trip() {
    let config = Config::minimal();
    let state = genesis_fork_state();
    let proof = test_proof();
    let key = secret_key();
    let public_key = Arc::new(key.to_public_key());

    let signature = proof.sign(&config, &state, 0, &key);

    proof
        .verify(&config, &state, 0, signature.into(), public_key)
        .expect("signature should verify");
}

// (d) Negative: a signature over one message must not verify for a tampered one, and the
// failure must name the signature kind.
#[test]
fn tampered_message_is_rejected() {
    let config = Config::minimal();
    let state = genesis_fork_state();
    let proof = test_proof();
    let key = secret_key();
    let public_key = Arc::new(key.to_public_key());

    let signature = proof.sign(&config, &state, 0, &key).into();

    let mut tampered_proof = test_proof();
    tampered_proof.public_input.new_payload_request_root = H256::repeat_byte(0xff);

    let error = tampered_proof
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

// (e) `SignedExecutionProof.message` wraps the bare proof in `Hc`, which delegates
// `hash_tree_root`, so a signature over the bare proof is exactly the signature the signed
// container carries.
#[test]
fn hc_wrapped_message_signs_identically_to_bare_proof() {
    let config = Config::minimal();
    let state = genesis_fork_state();
    let proof = test_proof();
    let key = secret_key();
    let public_key = Arc::new(key.to_public_key());

    let signature = proof.sign(&config, &state, 0, &key);

    let signed = SignedExecutionProof {
        message: Hc::from(proof.clone()),
        validator_index: 0,
        signature: signature.clone().into(),
    };

    assert_eq!(signed.message.hash_tree_root(), proof.hash_tree_root());

    proof
        .verify(&config, &state, 0, signature.into(), public_key)
        .expect("signature over bare proof should verify");
}
