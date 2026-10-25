use std::collections::HashMap as StdHashMap;

use super::*;
use bls::{SecretKey, SecretKeyBytes, traits::SecretKey as _};
use spec_test_utils::Case;
use ssz::{Hc, SszRead as _, SszWrite as _};
use types::{
    eip8025::containers::ProofData,
    gloas::{
        beacon_state::BeaconState as GloasBeaconState,
        containers::{
            BeaconBlock as GloasBeaconBlock, BeaconBlockBody as GloasBeaconBlockBody,
            ExecutionPayload as GloasExecutionPayload, ExecutionRequests,
            SignedBeaconBlock as GloasSignedBeaconBlock,
        },
    },
    phase0::{
        beacon_state::BeaconState as Phase0BeaconState,
        consts::FAR_FUTURE_EPOCH,
        containers::{
            BeaconBlock as Phase0BeaconBlock, BeaconBlockBody as Phase0BeaconBlockBody,
            BeaconBlockHeader, Checkpoint, SignedBeaconBlock as Phase0SignedBeaconBlock, Validator,
        },
    },
    preset::Minimal,
};

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

#[derive(Clone, Default)]
struct ContextStorage {
    states: Arc<Mutex<StdHashMap<H256, Arc<BeaconState<Minimal>>>>>,
    requested_roots: Arc<Mutex<Vec<H256>>>,
    fail_reads: bool,
    fail_root: Option<H256>,
}

impl Storage<Minimal> for ContextStorage {
    fn storage_mode(&self) -> StorageMode {
        StorageMode::default()
    }

    fn stored_state_by_block_root(
        &self,
        block_root: H256,
        _finalized_validators: Option<&dyn SszValidatorList>,
    ) -> Result<Option<Arc<BeaconState<Minimal>>>> {
        self.requested_roots.lock().push(block_root);
        if self.fail_reads || self.fail_root == Some(block_root) {
            anyhow::bail!("synthetic persisted-state read failure");
        }

        Ok(self.states.lock().get(&block_root).cloned())
    }
}

fn gloas_context_store(
    storage: Arc<ContextStorage>,
    genesis_time: u64,
) -> (
    Store<Minimal, ContextStorage>,
    Arc<BeaconState<Minimal>>,
    H256,
) {
    let body = GloasBeaconBlockBody::<Minimal>::default();
    let state = Arc::new(BeaconState::from(GloasBeaconState::<Minimal> {
        genesis_time,
        latest_block_header: BeaconBlockHeader {
            body_root: body.hash_tree_root(),
            ..Default::default()
        },
        ..Default::default()
    }));
    let block = GloasSignedBeaconBlock {
        message: Hc::from(GloasBeaconBlock {
            state_root: state.hash_tree_root(),
            body,
            ..Default::default()
        }),
        signature: <_>::default(),
    };
    let block_root = block.message.hash_tree_root();
    assert_eq!(accessors::latest_block_root(&state), block_root);

    let store = Store::new(
        Arc::new(ChainConfig::default()),
        Arc::new(PubkeyCache::default()),
        StoreConfig::default(),
        Arc::new(SignedBeaconBlock::<Minimal>::from(block)),
        state.clone_arc(),
        storage,
        false,
        false,
        StdHashSet::default(),
        Arc::new(SccHashMap::new()),
    );

    (store, state, block_root)
}

fn cache_accepted_test_payload(
    store: &mut Store<Minimal, ContextStorage>,
    block_root: H256,
    slot: Slot,
) -> Arc<SignedExecutionPayloadEnvelope<Minimal>> {
    // Unit fixtures model a payload already accepted by Store; they do not
    // establish execution-layer validity or exercise payload admission.
    let envelope = Arc::new(SignedExecutionPayloadEnvelope {
        message: ExecutionPayloadEnvelope {
            payload: GloasExecutionPayload {
                slot_number: slot,
                ..Default::default()
            },
            beacon_block_root: block_root,
            ..Default::default()
        },
        ..Default::default()
    });
    store.payloads.insert(block_root);
    store
        .execution_payload_envelope_cache
        .insert(envelope.clone_arc());
    envelope
}

fn context_signed_envelope(block_root: H256) -> SignedExecutionProofEnvelope {
    precheck_fixture(block_root, 1, 0, vec![0x42])
}

fn context_prechecked<'a, S: Storage<Minimal>>(
    store: &Store<Minimal, S>,
    signed_envelope: &'a SignedExecutionProofEnvelope,
) -> crate::prepared_execution_proof::PrecheckedExecutionProof<'a> {
    match crate::prepared_execution_proof::precheck_execution_proof(store, signed_envelope) {
        Ok(crate::prepared_execution_proof::ExecutionProofPrecheck::Continue(prechecked)) => {
            prechecked
        }
        Ok(crate::prepared_execution_proof::ExecutionProofPrecheck::Ignore(reason)) => {
            panic!("fixture envelope should pass ordered precheck: {reason}")
        }
        Err(error) => panic!("fixture envelope should pass ordered precheck: {error:#}"),
    }
}

type ExecutionProofBookkeeping = (
    HashMap<H256, HashMap<ProofType, ExecutionProofEnvelope>>,
    HashMap<H256, HashSet<H256>>,
    HashSet<(H256, ProofType, ValidatorIndex)>,
);

fn execution_proof_bookkeeping<S: Storage<Minimal>>(
    store: &Store<Minimal, S>,
) -> ExecutionProofBookkeeping {
    (
        store.execution_proofs.clone(),
        store.execution_proof_roots.clone(),
        store.execution_proof_provers.clone(),
    )
}

fn assert_execution_proof_bookkeeping_unchanged<S: Storage<Minimal>>(
    store: &Store<Minimal, S>,
    before: &ExecutionProofBookkeeping,
) {
    assert_eq!(
        store.execution_proofs, before.0,
        "context loading must not store verified proofs"
    );
    assert_eq!(
        store.execution_proof_roots, before.1,
        "context loading must not mark envelope roots Seen"
    );
    assert_eq!(
        store.execution_proof_provers, before.2,
        "context loading must not mark provers Seen"
    );
}

fn seed_execution_proof_bookkeeping<S: Storage<Minimal>>(
    store: &mut Store<Minimal, S>,
    block_root: H256,
) {
    let envelope = precheck_fixture(block_root, 2, 7, vec![0x91]);
    store
        .execution_proofs
        .entry(block_root)
        .or_default()
        .insert(2, envelope.message.as_ref().clone());
    store
        .execution_proof_roots
        .entry(block_root)
        .or_default()
        .insert(H256::repeat_byte(0x92));
    store.execution_proof_provers.insert((block_root, 2, 7));
}

fn genesis_store() -> Store<Minimal, NoopStorage> {
    let body = Phase0BeaconBlockBody::<Minimal>::default();
    let body_root = body.hash_tree_root();

    let phase0_state = Phase0BeaconState::<Minimal> {
        latest_block_header: BeaconBlockHeader {
            body_root,
            ..Default::default()
        },
        ..Default::default()
    };

    let state = Arc::new(BeaconState::<Minimal>::from(phase0_state));
    let state_root = state.hash_tree_root();

    let block = Phase0SignedBeaconBlock {
        message: Hc::from(Phase0BeaconBlock {
            state_root,
            body,
            ..Default::default()
        }),
        ..Default::default()
    };

    Store::new(
        Arc::new(ChainConfig::default()),
        Arc::new(PubkeyCache::default()),
        StoreConfig::default(),
        Arc::new(SignedBeaconBlock::<Minimal>::from(block)),
        state,
        Arc::new(NoopStorage),
        false,
        false,
        StdHashSet::default(),
        Arc::new(SccHashMap::new()),
    )
}

#[test]
fn execution_proof_state_shapes_empty_at_genesis() {
    let store = genesis_store();

    assert!(store.execution_proofs().is_empty());
    assert!(store.execution_proof_roots().is_empty());
    assert!(store.execution_proof_provers().is_empty());
}

fn precheck_fixture(
    beacon_block_root: H256,
    proof_type: u8,
    validator_index: ValidatorIndex,
    proof_data: Vec<u8>,
) -> SignedExecutionProofEnvelope {
    SignedExecutionProofEnvelope {
        message: Hc::from(ExecutionProofEnvelope {
            proof_data: ProofData::try_from(proof_data)
                .expect("test proof bytes should be within the proof-data bound"),
            proof_type,
            beacon_block_root,
        }),
        validator_index,
        ..SignedExecutionProofEnvelope::default()
    }
}

fn assert_precheck_bookkeeping_unchanged(
    store: &Store<Minimal, NoopStorage>,
    execution_proofs: &HashMap<H256, HashMap<ProofType, ExecutionProofEnvelope>>,
    execution_proof_roots: &HashMap<H256, HashSet<H256>>,
    execution_proof_provers: &HashSet<(H256, ProofType, ValidatorIndex)>,
) {
    assert_eq!(store.execution_proofs(), execution_proofs);
    assert_eq!(store.execution_proof_roots(), execution_proof_roots);
    assert_eq!(store.execution_proof_provers(), execution_proof_provers);
}

#[test]
fn execution_proof_precheck_rejects_empty_and_unsupported_before_store_ignores() {
    use crate::prepared_execution_proof::precheck_execution_proof;

    let mut store = genesis_store();
    let known_root = store.head().block_root;
    let duplicate = precheck_fixture(known_root, 1, 7, vec![0x42]);
    store
        .execution_proofs
        .entry(known_root)
        .or_default()
        .insert(1, duplicate.message.as_ref().clone());
    store
        .execution_proof_roots
        .entry(known_root)
        .or_default()
        .insert(duplicate.message.hash_tree_root());
    store.execution_proof_provers.insert((known_root, 1, 7));
    let snapshots = (
        store.execution_proofs.clone(),
        store.execution_proof_roots.clone(),
        store.execution_proof_provers.clone(),
    );

    let cases = [
        (
            precheck_fixture(H256::repeat_byte(0xee), 1, 7, vec![]),
            false,
        ),
        (precheck_fixture(known_root, 1, 7, vec![]), false),
        (precheck_fixture(known_root, 0, 7, vec![]), false),
        (
            precheck_fixture(H256::repeat_byte(0xee), 0, 7, vec![0x42]),
            true,
        ),
        (precheck_fixture(known_root, 0, 7, vec![0x42]), true),
    ];
    for (envelope, unsupported) in cases {
        let error = precheck_execution_proof(&store, &envelope)
            .err()
            .expect("empty/type rejection must precede block and duplicate checks");
        match error.downcast_ref::<Error<Minimal>>() {
            Some(Error::ExecutionProofEnvelopeEmptyProof) if !unsupported => {}
            Some(Error::ExecutionProofEnvelopeUnsupportedProofType { proof_type: 0 })
                if unsupported => {}
            _ => panic!("empty/type rejection must precede block and duplicate checks"),
        }
    }
    assert_precheck_bookkeeping_unchanged(&store, &snapshots.0, &snapshots.1, &snapshots.2);
}

#[test]
fn execution_proof_precheck_ignores_valid_supported_unknown_block() {
    use crate::prepared_execution_proof::{ExecutionProofPrecheck, precheck_execution_proof};

    let mut store = genesis_store();
    let unknown_root = H256::repeat_byte(0xee);
    let envelope = precheck_fixture(unknown_root, 1, 7, vec![0x42]);
    store
        .execution_proof_roots
        .entry(unknown_root)
        .or_default()
        .insert(envelope.message.hash_tree_root());
    store.execution_proof_provers.insert((unknown_root, 1, 7));
    let snapshots = (
        store.execution_proofs.clone(),
        store.execution_proof_roots.clone(),
        store.execution_proof_provers.clone(),
    );
    assert!(matches!(
        precheck_execution_proof(&store, &envelope),
        Ok(ExecutionProofPrecheck::Ignore(
            "execution proof's beacon block has not been seen"
        ))
    ));
    assert_precheck_bookkeeping_unchanged(&store, &snapshots.0, &snapshots.1, &snapshots.2);
}

#[test]
fn execution_proof_precheck_same_root_different_validator_uses_root_seen_key() {
    use crate::prepared_execution_proof::{ExecutionProofPrecheck, precheck_execution_proof};

    let mut store = genesis_store();
    let block_root = store.head().block_root;
    let first_validator = precheck_fixture(block_root, 1, 7, vec![0x42]);
    let different_validator = precheck_fixture(block_root, 1, 8, vec![0x42]);
    assert_eq!(
        first_validator.message.hash_tree_root(),
        different_validator.message.hash_tree_root()
    );
    store
        .execution_proof_roots
        .entry(block_root)
        .or_default()
        .insert(first_validator.message.hash_tree_root());
    let snapshots = (
        store.execution_proofs.clone(),
        store.execution_proof_roots.clone(),
        store.execution_proof_provers.clone(),
    );

    assert!(matches!(
        precheck_execution_proof(&store, &different_validator),
        Ok(ExecutionProofPrecheck::Ignore(
            "execution proof has already been processed"
        ))
    ));
    assert_precheck_bookkeeping_unchanged(&store, &snapshots.0, &snapshots.1, &snapshots.2);
}

#[test]
fn execution_proof_precheck_verified_proof_is_scoped_by_type() {
    use crate::prepared_execution_proof::{ExecutionProofPrecheck, precheck_execution_proof};

    let mut store = genesis_store();
    let block_root = store.head().block_root;
    let verified_type_one = precheck_fixture(block_root, 1, 7, vec![0x42]);
    store
        .execution_proofs
        .entry(block_root)
        .or_default()
        .insert(1, verified_type_one.message.as_ref().clone());
    let type_two = precheck_fixture(block_root, 2, 7, vec![0x43]);
    let snapshots = (
        store.execution_proofs.clone(),
        store.execution_proof_roots.clone(),
        store.execution_proof_provers.clone(),
    );

    assert!(matches!(
        precheck_execution_proof(&store, &type_two),
        Ok(ExecutionProofPrecheck::Continue(_))
    ));
    assert_precheck_bookkeeping_unchanged(&store, &snapshots.0, &snapshots.1, &snapshots.2);
}

#[test]
fn execution_proof_precheck_seen_bookkeeping_is_scoped_by_block_root() {
    use crate::prepared_execution_proof::{ExecutionProofPrecheck, precheck_execution_proof};

    let mut store = genesis_store();
    let first_root = store.head().block_root;
    let second_root = H256::repeat_byte(0xee);

    // Make the second synthetic root the only finalized block lookup entry.
    // The first root remains a bookkeeping key, not a block lookup entry.
    store.finalized[0].block_root = second_root;
    store.finalized_indices.remove(&first_root);
    store.finalized_indices.insert(second_root, 0);

    let first_attempt = precheck_fixture(first_root, 1, 7, vec![0x42]);
    store
        .execution_proofs
        .entry(first_root)
        .or_default()
        .insert(1, first_attempt.message.as_ref().clone());
    store
        .execution_proof_roots
        .entry(first_root)
        .or_default()
        .insert(first_attempt.message.hash_tree_root());
    store.execution_proof_provers.insert((first_root, 1, 7));

    let second_attempt = precheck_fixture(second_root, 1, 7, vec![0x42]);
    assert_ne!(
        first_attempt.message.hash_tree_root(),
        second_attempt.message.hash_tree_root()
    );
    let snapshots = (
        store.execution_proofs.clone(),
        store.execution_proof_roots.clone(),
        store.execution_proof_provers.clone(),
    );

    assert!(matches!(
        precheck_execution_proof(&store, &second_attempt),
        Ok(ExecutionProofPrecheck::Continue(_))
    ));
    assert_precheck_bookkeeping_unchanged(&store, &snapshots.0, &snapshots.1, &snapshots.2);
}

#[test]
fn execution_proof_precheck_candidate_root_under_wrong_block_root_does_not_mask_continue() {
    use crate::prepared_execution_proof::{ExecutionProofPrecheck, precheck_execution_proof};

    let mut store = genesis_store();
    let wrong_block_root = store.head().block_root;
    let candidate_block_root = H256::repeat_byte(0xee);

    // This synthetic cross-key placement isolates the collection
    // lookup contract. A proof root normally binds its beacon
    // block root; this is not a protocol-valid root collision or
    // a claim about network-reachable state.
    store.finalized[0].block_root = candidate_block_root;
    store.finalized_indices.remove(&wrong_block_root);
    store.finalized_indices.insert(candidate_block_root, 0);

    let candidate = precheck_fixture(candidate_block_root, 1, 7, vec![0x42]);
    let candidate_root = candidate.message.hash_tree_root();
    store
        .execution_proofs
        .entry(wrong_block_root)
        .or_default()
        .insert(1, candidate.message.as_ref().clone());
    store
        .execution_proof_roots
        .entry(wrong_block_root)
        .or_default()
        .insert(candidate_root);
    store
        .execution_proof_provers
        .insert((wrong_block_root, 1, 7));
    let snapshots = (
        store.execution_proofs.clone(),
        store.execution_proof_roots.clone(),
        store.execution_proof_provers.clone(),
    );

    assert!(matches!(
        precheck_execution_proof(&store, &candidate),
        Ok(ExecutionProofPrecheck::Continue(_))
    ));
    assert_precheck_bookkeeping_unchanged(&store, &snapshots.0, &snapshots.1, &snapshots.2);
}

#[test]
fn execution_proof_precheck_duplicate_order_and_seen_keys_are_read_only() {
    use crate::prepared_execution_proof::{ExecutionProofPrecheck, precheck_execution_proof};

    let mut store = genesis_store();
    let block_root = store.head().block_root;
    let envelope = precheck_fixture(block_root, 1, 7, vec![0x42]);
    let envelope_root = envelope.message.hash_tree_root();
    store
        .execution_proofs
        .entry(block_root)
        .or_default()
        .insert(1, envelope.message.as_ref().clone());
    store
        .execution_proof_roots
        .entry(block_root)
        .or_default()
        .insert(envelope_root);
    store.execution_proof_provers.insert((block_root, 1, 7));
    let snapshots = (
        store.execution_proofs.clone(),
        store.execution_proof_roots.clone(),
        store.execution_proof_provers.clone(),
    );
    assert!(matches!(
        precheck_execution_proof(&store, &envelope),
        Ok(ExecutionProofPrecheck::Ignore(
            "verified proof already known for this beacon block and proof type"
        ))
    ));
    assert_precheck_bookkeeping_unchanged(&store, &snapshots.0, &snapshots.1, &snapshots.2);

    store.execution_proofs.clear();
    let snapshots = (
        store.execution_proofs.clone(),
        store.execution_proof_roots.clone(),
        store.execution_proof_provers.clone(),
    );
    assert!(matches!(
        precheck_execution_proof(&store, &envelope),
        Ok(ExecutionProofPrecheck::Ignore(
            "execution proof has already been processed"
        ))
    ));
    assert_precheck_bookkeeping_unchanged(&store, &snapshots.0, &snapshots.1, &snapshots.2);

    store.execution_proof_roots.clear();
    let different_bytes = precheck_fixture(block_root, 1, 7, vec![0x43]);
    assert_ne!(envelope_root, different_bytes.message.hash_tree_root());
    let snapshots = (
        store.execution_proofs.clone(),
        store.execution_proof_roots.clone(),
        store.execution_proof_provers.clone(),
    );
    assert!(matches!(
        precheck_execution_proof(&store, &different_bytes),
        Ok(ExecutionProofPrecheck::Ignore(
            "proof already seen from this prover for this beacon block and proof type"
        ))
    ));
    assert_precheck_bookkeeping_unchanged(&store, &snapshots.0, &snapshots.1, &snapshots.2);

    let different_type = precheck_fixture(block_root, 2, 7, vec![0x43]);
    let snapshots = (
        store.execution_proofs.clone(),
        store.execution_proof_roots.clone(),
        store.execution_proof_provers.clone(),
    );
    match precheck_execution_proof(&store, &different_type) {
        Ok(ExecutionProofPrecheck::Continue(prechecked)) => {
            assert_eq!(prechecked.proof_type(), 2);
            assert_eq!(prechecked.validator_index(), 7);
        }
        _ => panic!("prover duplicate key must be scoped by proof type"),
    }
    assert_precheck_bookkeeping_unchanged(&store, &snapshots.0, &snapshots.1, &snapshots.2);
}

#[test]
fn execution_proof_precheck_continues_with_bare_root_without_mutation_or_context() {
    use crate::prepared_execution_proof::{ExecutionProofPrecheck, precheck_execution_proof};

    let store = genesis_store();
    let block_root = store.head().block_root;
    let envelope = precheck_fixture(block_root, 1, 7, vec![0x42]);
    assert!(!store.payloads.contains(&block_root));
    let bare_root = envelope.message.hash_tree_root();
    assert_ne!(bare_root, envelope.hash_tree_root());
    let snapshots = (
        store.execution_proofs.clone(),
        store.execution_proof_roots.clone(),
        store.execution_proof_provers.clone(),
    );
    match precheck_execution_proof(&store, &envelope) {
        Ok(ExecutionProofPrecheck::Continue(prechecked)) => {
            assert_eq!(prechecked.beacon_block_root(), block_root);
            assert_eq!(prechecked.proof_type(), 1);
            assert_eq!(prechecked.validator_index(), 7);
            assert_eq!(prechecked.envelope_root(), bare_root);
        }
        _ => panic!("known supported envelope with no payload must reach continuation"),
    }
    assert_precheck_bookkeeping_unchanged(&store, &snapshots.0, &snapshots.1, &snapshots.2);
}

fn proof_signing_key() -> SecretKey {
    let mut bytes = SecretKeyBytes::default();
    bytes.as_mut()[31] = 1; // Deterministic scalar-one test key.
    bytes.try_into().expect("scalar one is a valid secret key")
}

fn proof_fixture(
    validator_exit_epoch: Epoch,
) -> (
    Store<Minimal, NoopStorage>,
    BeaconState<Minimal>,
    SignedExecutionProofEnvelope,
) {
    let store = genesis_store();
    let key = proof_signing_key();
    let gloas_state = GloasBeaconState::<Minimal> {
        slot: 8, // Minimal: first slot of epoch 1.
        validators: core::iter::once(Validator {
            pubkey: key.to_public_key().into(),
            activation_epoch: 0,
            exit_epoch: validator_exit_epoch,
            ..Validator::default()
        })
        .collect(),
        ..GloasBeaconState::default()
    };
    let state = BeaconState::from(gloas_state);
    let envelope = ExecutionProofEnvelope {
        proof_data: ProofData::try_from(vec![0x42])
            .expect("one byte is within the proof-data bound"),
        proof_type: 1,
        beacon_block_root: H256::zero(),
    };
    let signature = envelope
        .sign(&store.chain_config, &state, state.slot(), &key)
        .into();
    let signed_proof = SignedExecutionProofEnvelope {
        message: Hc::from(envelope),
        validator_index: 0,
        signature,
    };

    (store, state, signed_proof)
}

fn proof_preparation_fixture(
    validator_exit_epoch: Epoch,
    accepted_payload: bool,
) -> (
    Store<Minimal, ContextStorage>,
    Arc<BeaconState<Minimal>>,
    SignedExecutionProofEnvelope,
) {
    let storage = Arc::new(ContextStorage::default());
    let key = proof_signing_key();
    let body = GloasBeaconBlockBody::<Minimal>::default();
    let state = Arc::new(BeaconState::from(GloasBeaconState::<Minimal> {
        validators: core::iter::once(Validator {
            pubkey: key.to_public_key().into(),
            activation_epoch: 0,
            exit_epoch: validator_exit_epoch,
            ..Validator::default()
        })
        .collect(),
        latest_block_header: BeaconBlockHeader {
            body_root: body.hash_tree_root(),
            ..Default::default()
        },
        ..GloasBeaconState::default()
    }));
    let block = GloasSignedBeaconBlock {
        message: Hc::from(GloasBeaconBlock {
            state_root: state.hash_tree_root(),
            body,
            ..Default::default()
        }),
        signature: <_>::default(),
    };
    let block_root = block.message.hash_tree_root();
    assert_eq!(accessors::latest_block_root(&state), block_root);

    let mut store = Store::new(
        Arc::new(ChainConfig::default()),
        Arc::new(PubkeyCache::default()),
        StoreConfig::default(),
        Arc::new(SignedBeaconBlock::<Minimal>::from(block)),
        state.clone_arc(),
        storage,
        false,
        false,
        StdHashSet::default(),
        Arc::new(SccHashMap::new()),
    );
    if accepted_payload {
        cache_accepted_test_payload(&mut store, block_root, state.slot());
    }

    let envelope = ExecutionProofEnvelope {
        proof_data: ProofData::try_from(vec![0x42])
            .expect("one byte is within the proof-data bound"),
        proof_type: 1,
        beacon_block_root: block_root,
    };
    // Sign only after the trusted state and its block root are fixed.
    let signature = envelope
        .sign(&store.chain_config, &state, state.slot(), &key)
        .into();
    let signed_proof = SignedExecutionProofEnvelope {
        message: Hc::from(envelope),
        validator_index: 0,
        signature,
    };

    (store, state, signed_proof)
}

fn pre_gloas_proof_preparation_fixture() -> (
    Store<Minimal, ContextStorage>,
    Arc<BeaconState<Minimal>>,
    SignedExecutionProofEnvelope,
) {
    let storage = Arc::new(ContextStorage::default());
    let key = proof_signing_key();
    let body = Phase0BeaconBlockBody::<Minimal>::default();
    let state = Arc::new(BeaconState::from(Phase0BeaconState::<Minimal> {
        validators: types::Validators::<Minimal>::try_from([Validator {
            pubkey: key.to_public_key().into(),
            activation_epoch: 0,
            exit_epoch: FAR_FUTURE_EPOCH,
            ..Validator::default()
        }])
        .expect("one validator fits in the validator registry"),
        latest_block_header: BeaconBlockHeader {
            body_root: body.hash_tree_root(),
            ..Default::default()
        },
        ..Phase0BeaconState::default()
    }));
    let block = Phase0SignedBeaconBlock {
        message: Hc::from(Phase0BeaconBlock {
            state_root: state.hash_tree_root(),
            body,
            ..Default::default()
        }),
        ..Default::default()
    };
    let block_root = block.message.hash_tree_root();
    assert_eq!(accessors::latest_block_root(&state), block_root);

    let mut store = Store::new(
        Arc::new(ChainConfig::default()),
        Arc::new(PubkeyCache::default()),
        StoreConfig::default(),
        Arc::new(SignedBeaconBlock::<Minimal>::from(block)),
        state.clone_arc(),
        storage,
        false,
        false,
        StdHashSet::default(),
        Arc::new(SccHashMap::new()),
    );
    cache_accepted_test_payload(&mut store, block_root, state.slot());

    let envelope = ExecutionProofEnvelope {
        proof_data: ProofData::try_from(vec![0x42])
            .expect("one byte is within the proof-data bound"),
        proof_type: 1,
        beacon_block_root: block_root,
    };
    let signature = envelope
        .sign(&store.chain_config, &state, state.slot(), &key)
        .into();
    let signed_proof = SignedExecutionProofEnvelope {
        message: Hc::from(envelope),
        validator_index: 0,
        signature,
    };

    (store, state, signed_proof)
}

fn assert_execution_proof_rejected(
    store: &Store<Minimal, NoopStorage>,
    state: &BeaconState<Minimal>,
    signed_proof: &SignedExecutionProofEnvelope,
    expected: impl FnOnce(&Error<Minimal>) -> bool,
) {
    let error = store
        .verify_execution_proof_envelope(state, signed_proof)
        .expect_err("invalid execution proof envelope should be rejected");
    let store_error = error
        .downcast_ref::<Error<Minimal>>()
        .expect("validation should preserve the typed store error");
    assert!(
        expected(store_error),
        "unexpected validation error: {store_error:?}"
    );
}

fn assert_preparation_rejected<S: Storage<Minimal>>(
    store: &Store<Minimal, S>,
    signed_proof: &SignedExecutionProofEnvelope,
    expected: impl FnOnce(&Error<Minimal>) -> bool,
) {
    let Err(error) = crate::prepare_execution_proof(store, signed_proof) else {
        panic!("invalid execution proof should be rejected");
    };
    let store_error = error
        .downcast_ref::<Error<Minimal>>()
        .expect("protocol rejection should preserve its typed Store error");
    assert!(
        expected(store_error),
        "unexpected preparation rejection: {store_error:?}"
    );
}

#[test]
fn execution_proof_envelope_authentication_accepts_valid_signature() {
    let (store, state, signed_proof) = proof_fixture(FAR_FUTURE_EPOCH);

    store
        .verify_execution_proof_envelope(&state, &signed_proof)
        .expect("valid signed envelope should authenticate");
}

#[test]
fn execution_proof_envelope_authentication_rejects_tampered_block_root() {
    let (store, state, mut signed_proof) = proof_fixture(FAR_FUTURE_EPOCH);
    signed_proof.message.beacon_block_root = H256::repeat_byte(1);

    assert_execution_proof_rejected(&store, &state, &signed_proof, |error| {
        matches!(error, Error::ExecutionProofEnvelopeInvalidSignature { .. })
    });
}

#[test]
fn execution_proof_envelope_authentication_rejects_invalid_validator_index() {
    let (store, state, mut signed_proof) = proof_fixture(FAR_FUTURE_EPOCH);
    signed_proof.validator_index = 1;

    assert_execution_proof_rejected(&store, &state, &signed_proof, |error| {
        matches!(
            error,
            Error::ExecutionProofEnvelopeInvalidValidatorIndex { .. }
        )
    });
}

#[test]
fn execution_proof_envelope_authentication_rejects_empty_proof() {
    let (store, state, mut signed_proof) = proof_fixture(FAR_FUTURE_EPOCH);
    signed_proof.message.proof_data = ProofData::default();

    assert_execution_proof_rejected(&store, &state, &signed_proof, |error| {
        matches!(error, Error::ExecutionProofEnvelopeEmptyProof)
    });
}

#[test]
fn execution_proof_envelope_authentication_rejects_unsupported_type() {
    let (store, state, mut signed_proof) = proof_fixture(FAR_FUTURE_EPOCH);

    for proof_type in [0, 4, u8::MAX] {
        signed_proof.message.proof_type = proof_type;

        assert_execution_proof_rejected(&store, &state, &signed_proof, |error| {
            matches!(
                error,
                Error::ExecutionProofEnvelopeUnsupportedProofType { proof_type: actual }
                    if *actual == proof_type
            )
        });
    }
}

#[test]
fn execution_proof_envelope_authentication_preserves_check_order() {
    let (store, state, mut signed_proof) = proof_fixture(0);
    signed_proof.validator_index = 1;
    signed_proof.message.proof_data = ProofData::default();
    signed_proof.message.proof_type = 0;

    assert_execution_proof_rejected(&store, &state, &signed_proof, |error| {
        matches!(
            error,
            Error::ExecutionProofEnvelopeInvalidValidatorIndex { .. }
        )
    });

    signed_proof.validator_index = 0;
    assert_execution_proof_rejected(&store, &state, &signed_proof, |error| {
        matches!(error, Error::ExecutionProofEnvelopeEmptyProof)
    });

    signed_proof.message.proof_data =
        ProofData::try_from(vec![0x42]).expect("one byte is within the proof-data bound");
    assert_execution_proof_rejected(&store, &state, &signed_proof, |error| {
        matches!(
            error,
            Error::ExecutionProofEnvelopeUnsupportedProofType { .. }
        )
    });
}

#[test]
fn execution_proof_envelope_authentication_rejects_inactive_validator() {
    let (store, state, signed_proof) = proof_fixture(0);

    assert_execution_proof_rejected(&store, &state, &signed_proof, |error| {
        matches!(error, Error::ExecutionProofEnvelopeInactiveValidator { .. })
    });
}

#[test]
fn execution_proof_envelope_authentication_rejects_invalid_signature() {
    let (store, state, mut signed_proof) = proof_fixture(FAR_FUTURE_EPOCH);
    signed_proof.signature = SignedExecutionProofEnvelope::default().signature;

    assert_execution_proof_rejected(&store, &state, &signed_proof, |error| {
        matches!(error, Error::ExecutionProofEnvelopeInvalidSignature { .. })
    });
}

#[test]
fn get_execution_proof_rejects_pre_gloas_state() {
    let store = genesis_store();
    let state = BeaconState::from(Phase0BeaconState::<Minimal>::default());

    store
        .get_execution_proof(
            &state,
            &ExecutionProofEnvelope::default(),
            &ExecutionPayloadEnvelope::default(),
        )
        .expect_err("a pre-Gloas state has no latest execution payload bid");
}

#[test]
fn get_execution_proof_binds_the_payload_request_root() {
    let store = genesis_store();
    let commitments = [
        KzgCommitment::repeat_byte(0x11),
        KzgCommitment::repeat_byte(0x22),
    ];
    let mut gloas_state = GloasBeaconState::<Minimal>::default();
    gloas_state
        .latest_execution_payload_bid
        .blob_kzg_commitments = ProgressiveList::try_from(commitments.to_vec())
        .expect("fixture commitments should fit in the progressive list");
    let state = BeaconState::from(gloas_state);
    let payload_envelope = ExecutionPayloadEnvelope {
        payload: GloasExecutionPayload {
            block_number: 42,
            ..Default::default()
        },
        parent_beacon_block_root: H256::repeat_byte(3),
        execution_requests: ExecutionRequests::default(),
        ..Default::default()
    };
    let envelope = ExecutionProofEnvelope {
        proof_data: ProofData::try_from(vec![0x42])
            .expect("one byte is within the proof-data bound"),
        proof_type: 1,
        beacon_block_root: payload_envelope.beacon_block_root,
    };
    // Build the spec's four fields directly, independently of the service's
    // NewPayloadRequest::new call, to catch a binding-field mix-up.
    let expected_request = NewPayloadRequest {
        execution_payload: payload_envelope.payload.clone(),
        versioned_hashes: commitments
            .into_iter()
            .map(misc::kzg_commitment_to_versioned_hash)
            .collect::<Vec<_>>()
            .try_into()
            .expect("fixture hashes should fit in VersionedHashes"),
        parent_beacon_block_root: payload_envelope.parent_beacon_block_root,
        execution_requests: payload_envelope.execution_requests.clone(),
    };

    let proof = store
        .get_execution_proof(&state, &envelope, &payload_envelope)
        .expect("accepted payload should bind to an execution proof");

    assert_eq!(
        proof.public_input.new_payload_request_root,
        expected_request.zkboost_compatible_root(),
    );
    assert_ne!(
        proof.public_input.new_payload_request_root,
        expected_request.hash_tree_root(),
        "zkBoost proofs bind the compatible root, not the canonical progressive root",
    );
    assert_eq!(proof.proof_data, envelope.proof_data);
    assert_eq!(proof.proof_type, envelope.proof_type);
    assert!(proof.public_input.successful_validation);
    assert_eq!(
        proof.public_input.chain_id,
        store.chain_config().deposit_chain_id,
    );
    assert_eq!(proof.public_input.schema_id, STATELESS_INPUT_SCHEMA_ID);
}

#[test]
fn execution_proof_context_loads_accepted_payload_and_exact_resident_post_state() {
    use crate::prepared_execution_proof::{
        ExecutionProofContextLoad, load_execution_proof_context,
    };

    let storage = Arc::new(ContextStorage::default());
    let (mut store, state, block_root) = gloas_context_store(storage, 0);
    let payload = cache_accepted_test_payload(&mut store, block_root, state.slot());
    seed_execution_proof_bookkeeping(&mut store, block_root);
    let bookkeeping = execution_proof_bookkeeping(&store);

    let block_context_envelope = context_signed_envelope(block_root);
    let block_prechecked = context_prechecked(&store, &block_context_envelope);
    match load_execution_proof_context(&store, &block_prechecked) {
        ExecutionProofContextLoad::Continue {
            state: loaded_state,
            payload_envelope,
        } => {
            assert!(Arc::ptr_eq(&loaded_state, &state));
            assert!(Arc::ptr_eq(&payload_envelope, &payload));
        }
        ExecutionProofContextLoad::Ignore(reason) => {
            panic!("coherent accepted context should continue: {reason}")
        }
    }
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);
}

#[test]
fn execution_proof_context_requires_payload_marker_and_full_cache_before_state_loading() {
    use crate::prepared_execution_proof::{
        ExecutionProofContextLoad, load_execution_proof_context,
    };

    let storage = Arc::new(ContextStorage::default());
    let (mut marker_only, _, marker_root) = gloas_context_store(storage.clone_arc(), 0);
    marker_only
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = None;
    marker_only.payloads.insert(marker_root);
    seed_execution_proof_bookkeeping(&mut marker_only, marker_root);
    let marker_bookkeeping = execution_proof_bookkeeping(&marker_only);
    let marker_context_envelope = context_signed_envelope(marker_root);
    let marker_prechecked = context_prechecked(&marker_only, &marker_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&marker_only, &marker_prechecked),
        ExecutionProofContextLoad::Ignore(
            "execution proof's accepted payload envelope is unavailable"
        )
    ));
    assert!(storage.requested_roots.lock().is_empty());
    assert_execution_proof_bookkeeping_unchanged(&marker_only, &marker_bookkeeping);

    let (mut cache_only, _, cache_root) = gloas_context_store(storage.clone_arc(), 1);
    cache_only
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = None;
    cache_accepted_test_payload(&mut cache_only, cache_root, 0);
    cache_only.payloads.remove(&cache_root);
    seed_execution_proof_bookkeeping(&mut cache_only, cache_root);
    let cache_bookkeeping = execution_proof_bookkeeping(&cache_only);
    let cache_context_envelope = context_signed_envelope(cache_root);
    let cache_prechecked = context_prechecked(&cache_only, &cache_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&cache_only, &cache_prechecked),
        ExecutionProofContextLoad::Ignore("execution proof's payload has not been accepted")
    ));
    assert!(storage.requested_roots.lock().is_empty());
    assert_execution_proof_bookkeeping_unchanged(&cache_only, &cache_bookkeeping);
}

#[test]
fn execution_proof_context_loads_unloaded_exact_state_from_cache_or_persistence() {
    use crate::prepared_execution_proof::{
        ExecutionProofContextLoad, load_execution_proof_context,
    };

    let cache_storage = Arc::new(ContextStorage::default());
    let (mut cached, cached_state, cached_root) = gloas_context_store(cache_storage.clone_arc(), 2);
    cached
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = None;
    cache_accepted_test_payload(&mut cached, cached_root, cached_state.slot());
    cached
        .state_cache
        .get_or_insert_with(cached_root, cached_state.slot(), true, || {
            Ok((cached_state.clone_arc(), None))
        })
        .expect("preloading the exact post-state into the state cache should succeed");
    seed_execution_proof_bookkeeping(&mut cached, cached_root);
    let cached_bookkeeping = execution_proof_bookkeeping(&cached);
    let cached_context_envelope = context_signed_envelope(cached_root);
    let cached_prechecked = context_prechecked(&cached, &cached_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&cached, &cached_prechecked),
        ExecutionProofContextLoad::Continue { .. }
    ));
    assert!(cache_storage.requested_roots.lock().is_empty());
    assert_execution_proof_bookkeeping_unchanged(&cached, &cached_bookkeeping);

    let persisted_storage = Arc::new(ContextStorage::default());
    let (mut persisted, persisted_state, persisted_root) =
        gloas_context_store(persisted_storage.clone_arc(), 3);
    persisted
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = None;
    persisted_storage
        .states
        .lock()
        .insert(persisted_root, persisted_state.clone_arc());
    cache_accepted_test_payload(&mut persisted, persisted_root, persisted_state.slot());
    seed_execution_proof_bookkeeping(&mut persisted, persisted_root);
    let persisted_bookkeeping = execution_proof_bookkeeping(&persisted);
    let persisted_context_envelope = context_signed_envelope(persisted_root);
    let persisted_prechecked = context_prechecked(&persisted, &persisted_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&persisted, &persisted_prechecked),
        ExecutionProofContextLoad::Continue { .. }
    ));
    assert_eq!(*persisted_storage.requested_roots.lock(), [persisted_root]);
    assert_execution_proof_bookkeeping_unchanged(&persisted, &persisted_bookkeeping);
}

#[test]
fn execution_proof_context_turns_missing_seed_and_storage_failures_into_ignore() {
    use crate::prepared_execution_proof::{
        ExecutionProofContextLoad, load_execution_proof_context,
    };

    let storage = Arc::new(ContextStorage::default());
    let (mut missing, _, missing_root) = gloas_context_store(storage.clone_arc(), 4);
    missing
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = None;
    cache_accepted_test_payload(&mut missing, missing_root, 0);
    seed_execution_proof_bookkeeping(&mut missing, missing_root);
    let missing_bookkeeping = execution_proof_bookkeeping(&missing);
    let missing_context_envelope = context_signed_envelope(missing_root);
    let missing_prechecked = context_prechecked(&missing, &missing_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&missing, &missing_prechecked),
        ExecutionProofContextLoad::Ignore("execution proof's validated post-state is unavailable")
    ));
    assert_eq!(*storage.requested_roots.lock(), [missing_root]);
    assert!(
        missing
            .state_cache
            .before_or_at_slot_in_cache_only(missing_root, 0)
            .is_none()
    );
    assert_execution_proof_bookkeeping_unchanged(&missing, &missing_bookkeeping);

    let failed_storage = Arc::new(ContextStorage {
        fail_reads: true,
        ..ContextStorage::default()
    });
    let (mut failed, _, failed_root) = gloas_context_store(failed_storage.clone_arc(), 5);
    failed
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = None;
    cache_accepted_test_payload(&mut failed, failed_root, 0);
    seed_execution_proof_bookkeeping(&mut failed, failed_root);
    let failed_bookkeeping = execution_proof_bookkeeping(&failed);
    let failed_context_envelope = context_signed_envelope(failed_root);
    let failed_prechecked = context_prechecked(&failed, &failed_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&failed, &failed_prechecked),
        ExecutionProofContextLoad::Ignore("execution proof's validated post-state is unavailable")
    ));
    assert_eq!(*failed_storage.requested_roots.lock(), [failed_root]);
    assert!(
        failed
            .state_cache
            .before_or_at_slot_in_cache_only(failed_root, 0)
            .is_none()
    );
    assert_execution_proof_bookkeeping_unchanged(&failed, &failed_bookkeeping);
}

#[test]
fn execution_proof_context_uses_exact_block_not_same_slot_or_next_slot_state() {
    use crate::prepared_execution_proof::{
        ExecutionProofContextLoad, load_execution_proof_context,
    };

    let storage = Arc::new(ContextStorage::default());
    let (mut store, _, block_root) = gloas_context_store(storage.clone_arc(), 6);
    store
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = None;
    cache_accepted_test_payload(&mut store, block_root, 0);

    let (other_store, other_state, other_root) =
        gloas_context_store(Arc::new(ContextStorage::default()), 7);
    assert_ne!(block_root, other_root);
    assert_eq!(
        other_state.slot(),
        store
            .chain_link(block_root)
            .expect("fixture target block must remain in Store")
            .slot()
    );

    seed_execution_proof_bookkeeping(&mut store, block_root);
    let bookkeeping = execution_proof_bookkeeping(&store);
    let block_context_envelope = context_signed_envelope(block_root);
    let block_prechecked = context_prechecked(&store, &block_context_envelope);

    // Model another valid same-slot root as the latest stored link. This is a
    // root-selection fixture, not a fork-choice head or imported competing block.
    let other_link = other_store.finalized[0].clone();
    store.finalized.push_back(other_link);
    store.finalized_indices.insert(other_root, 1);
    storage
        .states
        .lock()
        .insert(other_root, other_state.clone_arc());
    assert_eq!(
        store
            .finalized
            .back()
            .expect("same-slot fixture link must be appended")
            .block_root,
        other_root
    );

    // TODO delete
    //         seed_execution_proof_bookkeeping(&mut store, block_root);
    //         let bookkeeping = execution_proof_bookkeeping(&store);
    //         let block_context_envelope = context_signed_envelope(block_root);
    //         let block_prechecked = context_prechecked(&store, &block_context_envelope
    // );
    assert!(matches!(
        load_execution_proof_context(&store, &block_prechecked),
        ExecutionProofContextLoad::Ignore("execution proof's validated post-state is unavailable")
    ));
    assert_eq!(*storage.requested_roots.lock(), [block_root]);
    assert!(
        store
            .state_cache
            .before_or_at_slot_in_cache_only(block_root, 0)
            .is_none()
    );
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);

    let next_storage = Arc::new(ContextStorage::default());
    let (mut next_only, _, next_root) = gloas_context_store(next_storage.clone_arc(), 8);
    next_only
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = None;
    cache_accepted_test_payload(&mut next_only, next_root, 0);
    let next_gloas_state = GloasBeaconState::<Minimal> {
        slot: 1,
        ..Default::default()
    };
    let next_state = Arc::new(BeaconState::from(next_gloas_state));
    next_only
        .state_cache
        .get_or_insert_with(next_root, next_state.slot(), true, || {
            Ok((next_state.clone_arc(), None))
        })
        .expect("adding a next-slot-only cached state should succeed");
    seed_execution_proof_bookkeeping(&mut next_only, next_root);
    let next_bookkeeping = execution_proof_bookkeeping(&next_only);
    let next_context_envelope = context_signed_envelope(next_root);
    let next_prechecked = context_prechecked(&next_only, &next_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&next_only, &next_prechecked),
        ExecutionProofContextLoad::Ignore("execution proof's validated post-state is unavailable")
    ));
    assert_eq!(*next_storage.requested_roots.lock(), [next_root]);
    assert!(
        next_only
            .state_cache
            .before_or_at_slot_in_cache_only(next_root, 0)
            .is_none()
    );
    assert_execution_proof_bookkeeping_unchanged(&next_only, &next_bookkeeping);
}

#[test]
fn execution_proof_context_rejects_inconsistent_state_or_payload_slot_association() {
    use crate::prepared_execution_proof::{
        ExecutionProofContextLoad, load_execution_proof_context,
    };

    let root_mismatch_storage = Arc::new(ContextStorage::default());
    let (mut root_mismatch, _, root) = gloas_context_store(root_mismatch_storage, 9);
    cache_accepted_test_payload(&mut root_mismatch, root, 0);
    let mut altered_gloas_state = GloasBeaconState::<Minimal> {
        genesis_time: 1,
        ..Default::default()
    };
    altered_gloas_state.latest_block_header.body_root =
        GloasBeaconBlockBody::<Minimal>::default().hash_tree_root();
    root_mismatch
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = Some(Arc::new(BeaconState::from(altered_gloas_state)));
    seed_execution_proof_bookkeeping(&mut root_mismatch, root);
    let root_bookkeeping = execution_proof_bookkeeping(&root_mismatch);
    let root_context_envelope = context_signed_envelope(root);
    let root_prechecked = context_prechecked(&root_mismatch, &root_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&root_mismatch, &root_prechecked),
        ExecutionProofContextLoad::Ignore("execution proof's validated post-state is unavailable")
    ));
    assert_execution_proof_bookkeeping_unchanged(&root_mismatch, &root_bookkeeping);

    let slot_storage = Arc::new(ContextStorage::default());
    let (mut slot_mismatch, _, slot_root) = gloas_context_store(slot_storage, 10);
    cache_accepted_test_payload(&mut slot_mismatch, slot_root, 0);
    let wrong_slot_state = Arc::new(BeaconState::from(GloasBeaconState::<Minimal> {
        slot: 1,
        ..Default::default()
    }));
    slot_mismatch
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = Some(wrong_slot_state);
    seed_execution_proof_bookkeeping(&mut slot_mismatch, slot_root);
    let slot_bookkeeping = execution_proof_bookkeeping(&slot_mismatch);
    let slot_context_envelope = context_signed_envelope(slot_root);
    let slot_prechecked = context_prechecked(&slot_mismatch, &slot_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&slot_mismatch, &slot_prechecked),
        ExecutionProofContextLoad::Ignore("execution proof's validated post-state is unavailable")
    ));
    assert_execution_proof_bookkeeping_unchanged(&slot_mismatch, &slot_bookkeeping);

    let payload_storage = Arc::new(ContextStorage::default());
    let (mut payload_mismatch, _, payload_root) = gloas_context_store(payload_storage, 11);
    cache_accepted_test_payload(&mut payload_mismatch, payload_root, 1);
    seed_execution_proof_bookkeeping(&mut payload_mismatch, payload_root);
    let payload_bookkeeping = execution_proof_bookkeeping(&payload_mismatch);
    let payload_context_envelope = context_signed_envelope(payload_root);
    let payload_prechecked = context_prechecked(&payload_mismatch, &payload_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&payload_mismatch, &payload_prechecked),
        ExecutionProofContextLoad::Ignore(
            "execution proof's accepted payload envelope does not match its beacon block"
        )
    ));
    assert_execution_proof_bookkeeping_unchanged(&payload_mismatch, &payload_bookkeeping);
}

#[test]
fn execution_proof_context_rejects_inconsistent_exact_cache_hit() {
    use crate::prepared_execution_proof::{
        ExecutionProofContextLoad, load_execution_proof_context,
    };

    let storage = Arc::new(ContextStorage::default());
    let (mut store, state, block_root) = gloas_context_store(storage, 12);
    let block_slot = store
        .chain_link(block_root)
        .expect("fixture target block must remain in Store")
        .slot();
    let declared_state_root = store
        .chain_link(block_root)
        .expect("fixture target block must remain in Store")
        .block
        .message()
        .state_root();
    store
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = None;
    cache_accepted_test_payload(&mut store, block_root, block_slot);

    // Match the cache key, slot, and even Hc's declared-root cache while changing a
    // consensus field. The Store association check must recompute the clone's SSZ root.
    let mut inconsistent_state = state.as_ref().clone();
    *inconsistent_state.genesis_time_mut() = state.genesis_time().saturating_add(1);
    let BeaconState::Gloas(state_hc) = &inconsistent_state else {
        panic!("Gloas context fixture should contain a Gloas state");
    };
    state_hc.set_cached_root(declared_state_root);
    assert_eq!(inconsistent_state.slot(), block_slot);
    assert_eq!(inconsistent_state.hash_tree_root(), declared_state_root);
    store
        .state_cache
        .get_or_insert_with(block_root, block_slot, true, || {
            Ok((Arc::new(inconsistent_state), None))
        })
        .expect("installing the synthetic exact cache hit should succeed");
    seed_execution_proof_bookkeeping(&mut store, block_root);
    let bookkeeping = execution_proof_bookkeeping(&store);

    let block_context_envelope = context_signed_envelope(block_root);
    let block_prechecked = context_prechecked(&store, &block_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&store, &block_prechecked),
        ExecutionProofContextLoad::Ignore("execution proof's validated post-state is unavailable")
    ));
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);
}

#[test]
#[should_panic(expected = "legacy state loading requires replaying at least one block")]
fn execution_proof_legacy_state_replay_still_requires_a_block() {
    let store = genesis_store();
    store.load_beacon_state_by_state_transition(store.head().block_root);
}

type GloasBlockFixture = (
    Arc<ChainConfig>,
    BeaconState<Minimal>,
    Vec<SignedBeaconBlock<Minimal>>,
    Option<BeaconState<Minimal>>,
);

fn load_gloas_block_fixture(case_path: &'static str) -> GloasBlockFixture {
    let case = Case::from(case_path);
    let config = Arc::new(Minimal::default_config().start_and_stay_in(Phase::Gloas));
    let pre_state: BeaconState<Minimal> = case.ssz(config.as_ref(), "pre");
    let blocks: Vec<SignedBeaconBlock<Minimal>> = case
        .numbered(config.as_ref(), "blocks", 0..case.meta().blocks_count)
        .collect();
    let post_state: Option<BeaconState<Minimal>> = case.try_ssz(config.as_ref(), "post");

    (config, pre_state, blocks, post_state)
}

fn fixture_chain_store(
    config: Arc<ChainConfig>,
    pre_state: BeaconState<Minimal>,
    blocks: Vec<SignedBeaconBlock<Minimal>>,
    storage: Arc<ContextStorage>,
) -> (Store<Minimal, ContextStorage>, H256, Vec<H256>) {
    assert!(!blocks.is_empty(), "fixture must contain a target block");

    let pre_state = Arc::new(pre_state);
    let anchor_root = blocks[0].message().parent_root();
    assert_eq!(
        accessors::latest_block_root(&pre_state),
        anchor_root,
        "fixture pre-state must identify the first block's parent"
    );
    storage
        .states
        .lock()
        .insert(anchor_root, pre_state.clone_arc());

    // The fixtures omit their parent block. This local anchor and direct link insertion build
    // ancestry only; they do not claim fork-choice import or EL validation. The replayed SSZ
    // fixture blocks are checked against their independent `post` state in the success test.
    let (mut store, _, _) = gloas_context_store(storage, 0);
    store.chain_config = config;
    store.tick = Tick::start_of_slot(pre_state.slot());

    let anchor_header = pre_state.latest_block_header();
    let anchor_block = Arc::new(SignedBeaconBlock::<Minimal>::from(
        GloasSignedBeaconBlock::<Minimal> {
            message: Hc::from(GloasBeaconBlock::<Minimal> {
                slot: pre_state.slot(),
                proposer_index: anchor_header.proposer_index,
                parent_root: anchor_header.parent_root,
                state_root: pre_state.hash_tree_root(),
                ..Default::default()
            }),
            signature: <_>::default(),
        },
    ));
    let checkpoint = Checkpoint {
        epoch: accessors::get_current_epoch(&pre_state),
        root: anchor_root,
    };
    let anchor = store
        .finalized
        .iter_mut()
        .next()
        .expect("test store should have an anchor");
    anchor.block_root = anchor_root;
    anchor.block = anchor_block;
    anchor.state = None;
    anchor.current_justified_checkpoint = checkpoint;
    anchor.finalized_checkpoint = checkpoint;
    anchor.unrealized_justified_checkpoint = checkpoint;
    anchor.unrealized_finalized_checkpoint = checkpoint;

    store.finalized_indices = HashMap::unit(anchor_root, 0);
    store.checkpoint_states = HashMap::unit(checkpoint, pre_state);
    store.justified_checkpoint = checkpoint;
    store.finalized_checkpoint = checkpoint;
    store.unrealized_justified_checkpoint = checkpoint;
    store.unrealized_finalized_checkpoint = checkpoint;

    let mut block_roots = Vec::with_capacity(blocks.len());
    for block in blocks {
        let block_root = block.message().hash_tree_root();
        store
            .insert_block(ChainLink {
                block_root,
                block: Arc::new(block),
                state: None,
                current_justified_checkpoint: checkpoint,
                finalized_checkpoint: checkpoint,
                unrealized_justified_checkpoint: checkpoint,
                unrealized_finalized_checkpoint: checkpoint,
                payload_status: PayloadStatus::Optimistic,
                parent_payload_presence: PayloadPresence::default(),
            })
            .expect("fixture block should link to its stored parent");
        block_roots.push(block_root);
    }

    (store, anchor_root, block_roots)
}

// Decode after replay so tests inspect SSZ contents rather than a trusted Hc cached root.
fn decode_fixture_state(
    config: &ChainConfig,
    state: &BeaconState<Minimal>,
) -> BeaconState<Minimal> {
    BeaconState::<Minimal>::from_ssz(
        config,
        state.to_ssz().expect("fixture state should encode to SSZ"),
    )
    .expect("fixture state should decode from SSZ")
}

fn assert_legacy_fixture_replay_matches_post_state(
    store: &Store<Minimal, ContextStorage>,
    config: &ChainConfig,
    target_root: H256,
    expected_post: &BeaconState<Minimal>,
) {
    let legacy_state = store.load_beacon_state_by_state_transition(target_root);
    let actual_post = decode_fixture_state(config, &legacy_state);
    assert_eq!(&actual_post, expected_post);
}

// The withdrawal fixture's bid and parent block hashes are both zero, violating Gloas bid rules.
const APPLIED_PARENT_PAYLOAD_TWO_BLOCKS: &str = "consensus-spec-tests/tests/minimal/gloas/sanity/blocks/pyspec_tests/attestations_after_missed_slot_use_applied_parent_payload_availability";
const INVALID_SAME_SLOT_BLOCK_TRANSITION: &str = "consensus-spec-tests/tests/minimal/gloas/sanity/blocks/pyspec_tests/invalid_same_slot_block_transition";

#[test]
fn execution_proof_context_replays_two_fixture_blocks_in_chronological_order() {
    use crate::prepared_execution_proof::{
        ExecutionProofContextLoad, load_execution_proof_context,
    };

    let (config, pre_state, blocks, post_state) =
        load_gloas_block_fixture(APPLIED_PARENT_PAYLOAD_TWO_BLOCKS);
    assert_eq!(blocks.len(), 2, "fixture must contain both replay blocks");
    let post_state = post_state.expect("successful transition fixture must include post state");
    let target_root_hint = blocks[1].message().hash_tree_root();
    // The target disk read fails, while the persisted pre-state remains a usable seed.
    let storage = Arc::new(ContextStorage {
        fail_root: Some(target_root_hint),
        ..ContextStorage::default()
    });
    let (mut store, anchor_root, block_roots) =
        fixture_chain_store(config.clone_arc(), pre_state, blocks, storage.clone_arc());
    let intermediate_root = block_roots[0];
    let target_root = block_roots[1];
    assert_eq!(target_root, target_root_hint);
    let intermediate_link = store
        .chain_link(intermediate_root)
        .expect("fixture intermediate block must remain in Store");
    let target_link = store
        .chain_link(target_root)
        .expect("fixture target block must remain in Store");
    let intermediate_slot = intermediate_link.slot();
    let target_slot = target_link.slot();
    let target_declared_state_root = target_link.block.message().state_root();

    assert_eq!(
        store
            .chain_ending_with(target_root)
            .map(|chain_link| chain_link.block_root)
            .collect::<Vec<_>>(),
        [target_root, intermediate_root, anchor_root],
        "stored ancestry must include both fixture blocks above the pre-state anchor"
    );
    assert!(intermediate_link.state.is_none());
    assert!(target_link.state.is_none());
    assert!(target_slot > intermediate_slot);
    cache_accepted_test_payload(&mut store, target_root, target_slot);
    seed_execution_proof_bookkeeping(&mut store, target_root);
    let bookkeeping = execution_proof_bookkeeping(&store);

    // The old replay-only entrypoint remains usable on a cold cache and produces the same
    // fixture post-state. This call does not publish into StateCache.
    assert_legacy_fixture_replay_matches_post_state(&store, &config, target_root, &post_state);
    assert_eq!(
        storage.requested_roots.lock().as_slice(),
        &[target_root, intermediate_root, anchor_root]
    );
    storage.requested_roots.lock().clear();

    let cache_observer = store.clone();
    assert!(
        cache_observer
            .state_cache
            .before_or_at_slot_in_cache_only(target_root, target_slot)
            .is_none()
    );
    let target_context_envelope = context_signed_envelope(target_root);
    let target_prechecked = context_prechecked(&store, &target_context_envelope);
    let loaded_state = match load_execution_proof_context(&store, &target_prechecked) {
        ExecutionProofContextLoad::Continue {
            state,
            payload_envelope: _,
        } => {
            assert_eq!(state.slot(), target_slot);

            // Round-trip before hashing so the assertion is over fixture state contents,
            // not the root installed by trusted replay's Hc cache.
            let actual_post = decode_fixture_state(config.as_ref(), &state);
            assert_eq!(actual_post, post_state);
            assert_eq!(actual_post.hash_tree_root(), target_declared_state_root);
            assert_eq!(accessors::latest_block_root(&actual_post), target_root);
            assert_ne!(actual_post.slot(), intermediate_slot);
            state
        }
        ExecutionProofContextLoad::Ignore(reason) => {
            panic!("coherent two-block fixture should load: {reason}")
        }
    };
    let reads_after_fill = [target_root, intermediate_root, anchor_root];
    assert_eq!(
        storage.requested_roots.lock().as_slice(),
        &reads_after_fill[..]
    );
    let cached_state = cache_observer
        .state_cache
        .before_or_at_slot_in_cache_only(target_root, target_slot)
        .expect("successful validated replay should be published to the shared cache");
    assert!(Arc::ptr_eq(&loaded_state, &cached_state));
    let cached_post = decode_fixture_state(config.as_ref(), &cached_state);
    assert_eq!(cached_post, post_state);

    assert!(matches!(
        load_execution_proof_context(&store, &target_prechecked),
        ExecutionProofContextLoad::Continue { .. }
    ));
    assert_eq!(
        storage.requested_roots.lock().as_slice(),
        reads_after_fill,
        "an exact validated cache hit should not reread persisted ancestors"
    );
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);
}

#[test]
fn execution_proof_context_does_not_cache_replayed_wrong_target_root() {
    use crate::prepared_execution_proof::{
        ExecutionProofContextLoad, load_execution_proof_context,
    };

    let (config, pre_state, mut blocks, post_state) =
        load_gloas_block_fixture(APPLIED_PARENT_PAYLOAD_TWO_BLOCKS);
    assert_eq!(blocks.len(), 2);
    let post_state = post_state.expect("successful transition fixture must include post state");
    let wrong_declared_state_root = H256::repeat_byte(0xfe);
    assert_ne!(post_state.hash_tree_root(), wrong_declared_state_root);
    let SignedBeaconBlock::Gloas(target_block) = &mut blocks[1] else {
        panic!("Gloas fixture should decode to a Gloas block");
    };
    target_block.message.state_root = wrong_declared_state_root;

    let storage = Arc::new(ContextStorage::default());
    let (mut store, _anchor_root, block_roots) =
        fixture_chain_store(config.clone_arc(), pre_state, blocks, storage);
    let target_root = block_roots[1];
    let target_slot = store
        .chain_link(target_root)
        .expect("fixture target block must remain in Store")
        .slot();
    cache_accepted_test_payload(&mut store, target_root, target_slot);
    seed_execution_proof_bookkeeping(&mut store, target_root);
    let bookkeeping = execution_proof_bookkeeping(&store);

    // Prove that seed validation and the trusted transitions themselves succeed. The
    // independently decoded content root then isolates the bad target declaration.
    let (replayed_state, replayed) = store
        .try_load_beacon_state_by_state_transition(target_root, true)
        .expect("valid seed and trusted ancestry transitions should complete");
    assert!(replayed);
    let actual_post = decode_fixture_state(config.as_ref(), &replayed_state);
    assert_eq!(actual_post, post_state);
    assert_ne!(
        actual_post.hash_tree_root(),
        store
            .chain_link(target_root)
            .expect("fixture target block must remain in Store")
            .block
            .message()
            .state_root(),
        "trusted replay must not make the wrong declared target root true"
    );
    assert!(
        store
            .state_cache
            .before_or_at_slot_in_cache_only(target_root, target_slot)
            .is_none(),
        "direct ancestry replay does not publish into StateCache"
    );

    let cache_observer = store.clone();
    let target_context_envelope = context_signed_envelope(target_root);
    let target_prechecked = context_prechecked(&store, &target_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&store, &target_prechecked),
        ExecutionProofContextLoad::Ignore("execution proof's validated post-state is unavailable")
    ));
    assert!(
        cache_observer
            .state_cache
            .before_or_at_slot_in_cache_only(target_root, target_slot)
            .is_none(),
        "a rejected target must not be published through the cache fill closure"
    );
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);
}

#[test]
fn execution_proof_context_rejects_corrupt_persisted_seed_before_trusted_replay() {
    use crate::prepared_execution_proof::{
        ExecutionProofContextLoad, load_execution_proof_context,
    };

    let (config, pre_state, blocks, _) =
        load_gloas_block_fixture(APPLIED_PARENT_PAYLOAD_TWO_BLOCKS);
    let original_root = pre_state.hash_tree_root();
    let original_header = pre_state.latest_block_header();
    let original_slot = pre_state.slot();

    // This is synthetic local persisted-state corruption, not a protocol-reachability or
    // exploit claim. Prime and then ordinarily invalidate Hc via a non-header consensus field.
    let mut corrupted_state = pre_state.clone();
    let _ = corrupted_state.hash_tree_root();
    *corrupted_state.genesis_time_mut() = pre_state.genesis_time().saturating_add(1);
    let mutated_root = corrupted_state.hash_tree_root();
    assert_ne!(mutated_root, original_root);
    assert_eq!(corrupted_state.slot(), original_slot);
    assert_eq!(corrupted_state.latest_block_header(), original_header);

    // Model the persisted SSZ decode path: Hc's root cache is not part of SSZ and decode
    // produces a fresh cell, so this hash is derived from the altered state contents.
    let corrupted_persisted = BeaconState::<Minimal>::from_ssz(
        config.as_ref(),
        corrupted_state
            .to_ssz()
            .expect("corrupted seed should encode to SSZ"),
    )
    .expect("corrupted persisted seed should decode from SSZ");
    assert_eq!(corrupted_persisted.hash_tree_root(), mutated_root);

    let storage = Arc::new(ContextStorage::default());
    let (mut store, anchor_root, block_roots) =
        fixture_chain_store(config, pre_state, blocks, storage.clone_arc());
    storage
        .states
        .lock()
        .insert(anchor_root, Arc::new(corrupted_persisted));
    assert_eq!(anchor_root, store.finalized[0].block_root);
    let target_root = block_roots[1];
    let intermediate_root = block_roots[0];
    assert_ne!(
        storage.states.lock()[&anchor_root].hash_tree_root(),
        store.finalized[0].block.message().state_root(),
        "corrupted seed must disagree with its persisted block's declared state root"
    );
    let target_link = store
        .chain_link(target_root)
        .expect("fixture target block must remain in Store");
    let intermediate_link = store
        .chain_link(intermediate_root)
        .expect("fixture intermediate block must remain in Store");
    assert!(target_link.state.is_none());
    assert!(intermediate_link.state.is_none());
    let target_slot = target_link.slot();
    cache_accepted_test_payload(&mut store, target_root, target_slot);
    assert!(store.is_payload_verified(target_root));
    let accepted_payload = store
        .cached_execution_payload_envelope_by_root(target_root)
        .expect("target's accepted payload envelope should be cached");
    assert_eq!(accepted_payload.block_root(), target_root);
    assert_eq!(accepted_payload.slot(), target_slot);
    seed_execution_proof_bookkeeping(&mut store, target_root);
    let bookkeeping = execution_proof_bookkeeping(&store);

    let error = store
        .try_load_beacon_state_by_state_transition(target_root, true)
        .expect_err("corrupt persisted seed must fail before trusted replay");
    assert!(
        format!("{error:#}").contains(
            "selected ancestry seed is inconsistent: reconstructed state root does not match its block's declared state root"
        ),
        "unexpected integrity failure: {error:#}"
    );
    assert_eq!(
        storage.requested_roots.lock().as_slice(),
        &[target_root, intermediate_root, anchor_root],
        "the exact corrupt ancestor must be the selected seed after absent descendants"
    );

    let cache_observer = store.clone();
    assert!(
        cache_observer
            .state_cache
            .before_or_at_slot_in_cache_only(target_root, target_slot)
            .is_none(),
        "failed seed association must not publish a target state"
    );
    storage.requested_roots.lock().clear();
    let target_context_envelope = context_signed_envelope(target_root);
    let target_prechecked = context_prechecked(&store, &target_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&store, &target_prechecked),
        ExecutionProofContextLoad::Ignore("execution proof's validated post-state is unavailable")
    ));
    assert!(
        cache_observer
            .state_cache
            .before_or_at_slot_in_cache_only(target_root, target_slot)
            .is_none(),
        "failed context loading must leave no target state cache entry"
    );
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);
}

#[test]
fn execution_proof_context_ignores_same_slot_fixture_transition_error() {
    use crate::prepared_execution_proof::{
        ExecutionProofContextLoad, load_execution_proof_context,
    };

    let (config, pre_state, blocks, _) =
        load_gloas_block_fixture(INVALID_SAME_SLOT_BLOCK_TRANSITION);
    assert_eq!(
        blocks.len(),
        1,
        "same-slot fixture has one corrupted target block"
    );
    let storage = Arc::new(ContextStorage::default());
    let (mut store, anchor_root, block_roots) =
        fixture_chain_store(config, pre_state, blocks, storage.clone_arc());
    let target_root = block_roots[0];
    let target_slot = store
        .chain_link(target_root)
        .expect("fixture target block must remain in Store")
        .slot();
    assert_eq!(
        target_slot,
        store
            .chain_link(anchor_root)
            .expect("fixture anchor block must remain in Store")
            .slot()
    );
    assert!(
        store
            .chain_link(target_root)
            .expect("fixture target block must remain in Store")
            .state
            .is_none()
    );
    cache_accepted_test_payload(&mut store, target_root, target_slot);
    assert!(store.is_payload_verified(target_root));
    let accepted_payload = store
        .cached_execution_payload_envelope_by_root(target_root)
        .expect("target's accepted payload envelope should be cached");
    assert_eq!(accepted_payload.block_root(), target_root);
    assert_eq!(accepted_payload.slot(), target_slot);
    seed_execution_proof_bookkeeping(&mut store, target_root);
    let bookkeeping = execution_proof_bookkeeping(&store);

    // The fixture is deliberately inserted as a synthetic stored target to exercise a local
    // transition failure; this is not a claim that it passed block validation/import.
    let error = store
        .try_load_beacon_state_by_state_transition(target_root, true)
        .expect_err("same-slot target must fail its trusted state transition");
    let diagnostic = format!("{error:#}");
    assert!(
        diagnostic.contains("is not later than current slot"),
        "expected deterministic SlotNotLater transition error, got: {diagnostic}"
    );
    assert!(diagnostic.contains(&target_slot.to_string()));
    assert_eq!(
        storage.requested_roots.lock().as_slice(),
        &[target_root, anchor_root],
        "the correct persisted ancestor must be selected before the transition error"
    );

    storage.requested_roots.lock().clear();
    let target_context_envelope = context_signed_envelope(target_root);
    let target_prechecked = context_prechecked(&store, &target_context_envelope);
    assert!(matches!(
        load_execution_proof_context(&store, &target_prechecked),
        ExecutionProofContextLoad::Ignore("execution proof's validated post-state is unavailable")
    ));
    assert!(
        store
            .state_cache
            .before_or_at_slot_in_cache_only(target_root, target_slot)
            .is_none(),
        "a failed trusted transition must not publish a target state"
    );
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);
}

#[test]
fn execution_proof_preparation_authenticates_and_binds_exact_accepted_context() {
    let (store, state, signed_proof) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let block_root = signed_proof.message.beacon_block_root;
    let accepted_payload = store
        .cached_execution_payload_envelope_by_root(block_root)
        .expect("fixture accepted payload should be cached");
    assert_eq!(accepted_payload.block_root(), block_root);
    assert_eq!(
        accepted_payload.slot(),
        store
            .chain_link(block_root)
            .expect("fixture target block should remain in Store")
            .slot()
    );
    let expected = store
        .get_execution_proof(
            &state,
            signed_proof.message.as_ref(),
            &accepted_payload.message,
        )
        .expect("fixture Gloas context should reconstruct the statement");
    let bookkeeping = execution_proof_bookkeeping(&store);

    match crate::prepare_execution_proof(&store, &signed_proof) {
        Ok(crate::ExecutionProofPreparation::Prepared(prepared)) => {
            assert_eq!(prepared.signed_message(), signed_proof.message.as_ref());
            assert_eq!(prepared.validator_index(), 0);
            assert_eq!(prepared.execution_proof(), &expected);
            assert_eq!(prepared.signed_message().beacon_block_root, block_root);
            assert_eq!(prepared.signed_message().proof_type, 1);
            assert_eq!(prepared.signed_message().proof_data, expected.proof_data);
            assert_eq!(
                prepared.envelope_root(),
                signed_proof.message.as_ref().hash_tree_root(),
                "prepared carrier preserves the bare envelope root from ordered precheck"
            );
            assert_eq!(prepared.context_identity().beacon_block_root(), block_root);
            assert_eq!(
                prepared.context_identity().public_input(),
                &expected.public_input,
                "context identity retains the complete reconstructed public input"
            );
            assert!(
                prepared
                    .execution_proof()
                    .public_input
                    .successful_validation
            );
            assert_eq!(
                prepared.execution_proof().public_input.chain_id,
                store.chain_config().deposit_chain_id
            );
            assert_eq!(
                prepared.execution_proof().public_input.schema_id,
                STATELESS_INPUT_SCHEMA_ID
            );
        }
        Ok(crate::ExecutionProofPreparation::Ignore(reason)) => {
            panic!("coherent authenticated fixture should prepare: {reason}")
        }
        Err(error) => panic!("coherent authenticated fixture failed: {error:#}"),
    }
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);
}

#[test]
fn execution_proof_preparation_rejects_authentication_failures_without_bookkeeping() {
    let (store, _, mut invalid_index) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    invalid_index.validator_index = 1;
    let bookkeeping = execution_proof_bookkeeping(&store);
    assert_preparation_rejected(&store, &invalid_index, |error| {
        matches!(
            error,
            Error::ExecutionProofEnvelopeInvalidValidatorIndex { .. }
        )
    });
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);

    let (inactive_store, _, inactive) = proof_preparation_fixture(0, true);
    let bookkeeping = execution_proof_bookkeeping(&inactive_store);
    assert_preparation_rejected(&inactive_store, &inactive, |error| {
        matches!(error, Error::ExecutionProofEnvelopeInactiveValidator { .. })
    });
    assert_execution_proof_bookkeeping_unchanged(&inactive_store, &bookkeeping);

    let (bad_signature_store, _, mut bad_signature) =
        proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    // Tamper only after the fixture has signed the correct target and state.
    bad_signature.signature = SignedExecutionProofEnvelope::default().signature;
    let bookkeeping = execution_proof_bookkeeping(&bad_signature_store);
    assert_preparation_rejected(&bad_signature_store, &bad_signature, |error| {
        matches!(error, Error::ExecutionProofEnvelopeInvalidSignature { .. })
    });
    assert_execution_proof_bookkeeping_unchanged(&bad_signature_store, &bookkeeping);
}

#[test]
fn execution_proof_preparation_ignores_unavailable_context_before_authentication() {
    let (no_payload, _, mut signed_proof) = proof_preparation_fixture(FAR_FUTURE_EPOCH, false);
    signed_proof.signature = SignedExecutionProofEnvelope::default().signature;
    let bookkeeping = execution_proof_bookkeeping(&no_payload);
    assert!(matches!(
        crate::prepare_execution_proof(&no_payload, &signed_proof),
        Ok(crate::ExecutionProofPreparation::Ignore(
            "execution proof's payload has not been accepted"
        ))
    ));
    assert_execution_proof_bookkeeping_unchanged(&no_payload, &bookkeeping);

    let (mut marker_only, _, mut signed_proof) = proof_preparation_fixture(FAR_FUTURE_EPOCH, false);
    marker_only
        .payloads
        .insert(signed_proof.message.beacon_block_root);
    signed_proof.signature = SignedExecutionProofEnvelope::default().signature;
    let bookkeeping = execution_proof_bookkeeping(&marker_only);
    assert!(matches!(
        crate::prepare_execution_proof(&marker_only, &signed_proof),
        Ok(crate::ExecutionProofPreparation::Ignore(
            "execution proof's accepted payload envelope is unavailable"
        ))
    ));
    assert_execution_proof_bookkeeping_unchanged(&marker_only, &bookkeeping);

    let (mut missing_state, _, mut signed_proof) =
        proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    missing_state
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = None;
    signed_proof.signature = SignedExecutionProofEnvelope::default().signature;
    let bookkeeping = execution_proof_bookkeeping(&missing_state);
    assert!(matches!(
        crate::prepare_execution_proof(&missing_state, &signed_proof),
        Ok(crate::ExecutionProofPreparation::Ignore(
            "execution proof's validated post-state is unavailable"
        ))
    ));
    assert_execution_proof_bookkeeping_unchanged(&missing_state, &bookkeeping);
}

#[test]
fn execution_proof_preparation_preserves_spec_precheck_precedence() {
    let (mut store, _, signed_proof) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let block_root = signed_proof.message.beacon_block_root;
    let unknown_root = H256::repeat_byte(0xee);

    let mut empty_unknown = signed_proof.clone();
    empty_unknown.message.proof_data = ProofData::default();
    empty_unknown.message.beacon_block_root = unknown_root;
    let bookkeeping = execution_proof_bookkeeping(&store);
    assert_preparation_rejected(&store, &empty_unknown, |error| {
        matches!(error, Error::ExecutionProofEnvelopeEmptyProof)
    });
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);

    let mut unsupported_unknown = signed_proof.clone();
    unsupported_unknown.message.proof_type = 0;
    unsupported_unknown.message.beacon_block_root = unknown_root;
    let bookkeeping = execution_proof_bookkeeping(&store);
    assert_preparation_rejected(&store, &unsupported_unknown, |error| {
        matches!(
            error,
            Error::ExecutionProofEnvelopeUnsupportedProofType { proof_type: 0 }
        )
    });
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);

    let mut unknown = signed_proof.clone();
    unknown.message.beacon_block_root = unknown_root;
    let bookkeeping = execution_proof_bookkeeping(&store);
    assert!(matches!(
        crate::prepare_execution_proof(&store, &unknown),
        Ok(crate::ExecutionProofPreparation::Ignore(
            "execution proof's beacon block has not been seen"
        ))
    ));
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);

    store
        .execution_proofs
        .entry(block_root)
        .or_default()
        .insert(1, signed_proof.message.as_ref().clone());
    store
        .execution_proof_roots
        .entry(block_root)
        .or_default()
        .insert(signed_proof.message.hash_tree_root());
    store.execution_proof_provers.insert((block_root, 1, 0));
    let bookkeeping = execution_proof_bookkeeping(&store);
    assert!(matches!(
        crate::prepare_execution_proof(&store, &signed_proof),
        Ok(crate::ExecutionProofPreparation::Ignore(
            "verified proof already known for this beacon block and proof type"
        ))
    ));
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);

    store.execution_proofs.remove(&block_root);
    let bookkeeping = execution_proof_bookkeeping(&store);
    assert!(matches!(
        crate::prepare_execution_proof(&store, &signed_proof),
        Ok(crate::ExecutionProofPreparation::Ignore(
            "execution proof has already been processed"
        ))
    ));
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);

    store.execution_proof_roots.remove(&block_root);
    let bookkeeping = execution_proof_bookkeeping(&store);
    assert!(matches!(
        crate::prepare_execution_proof(&store, &signed_proof),
        Ok(crate::ExecutionProofPreparation::Ignore(
            "proof already seen from this prover for this beacon block and proof type"
        ))
    ));
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);
}

#[test]
fn execution_proof_preparation_propagates_binding_failures_as_local_errors() {
    let (store, state, signed_proof) = pre_gloas_proof_preparation_fixture();
    store
        .verify_execution_proof_envelope(&state, &signed_proof)
        .expect("the binding-failure fixture must authenticate successfully first");
    let bookkeeping = execution_proof_bookkeeping(&store);
    let Err(error) = crate::prepare_execution_proof(&store, &signed_proof) else {
        panic!("pre-Gloas trusted context cannot reconstruct an execution proof");
    };
    assert!(
        error
            .to_string()
            .contains("execution proof binding requires a Gloas state"),
        "binding failure should remain diagnosable as a local error: {error:#}"
    );
    assert!(
        error.downcast_ref::<Error<Minimal>>().is_none(),
        "binding failure must not be turned into a peer-invalid Store rejection"
    );
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);
}
