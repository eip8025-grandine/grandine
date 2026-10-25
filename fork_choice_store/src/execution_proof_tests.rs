use std::collections::HashMap as StdHashMap;

use super::*;
use bls::{SecretKey, SecretKeyBytes, traits::SecretKey as _};
use eth2_libp2p::GossipId;
use spec_test_utils::Case;
use ssz::{Hc, ProgressiveList, SszRead as _, SszWrite as _};
use types::{
    eip8025::containers::ProofData,
    gloas::{
        beacon_state::BeaconState as GloasBeaconState,
        containers::{
            BeaconBlock as GloasBeaconBlock, BeaconBlockBody as GloasBeaconBlockBody,
            ExecutionPayload as GloasExecutionPayload, ExecutionPayloadBid, ExecutionRequests,
            SignedBeaconBlock as GloasSignedBeaconBlock, SignedExecutionPayloadBid,
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

type PayloadValidationFixture<S> = (
    Store<Minimal, S>,
    Arc<BeaconState<Minimal>>,
    Arc<SignedExecutionPayloadEnvelope<Minimal>>,
);

type RetainedUnfinalizedPayloadFixture = (
    Store<Minimal, NoopStorage>,
    Arc<BeaconState<Minimal>>,
    Arc<SignedExecutionPayloadEnvelope<Minimal>>,
    H256,
    H256,
    SecretKey,
);

#[derive(Clone)]
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

struct RecordedPayloadSubmission {
    block_root: H256,
    payload: types::combined::ExecutionPayload<Minimal>,
    params: Option<ExecutionPayloadParams<Minimal>>,
}

struct RecordingPayloadEngine {
    requests: Arc<Mutex<Vec<RecordedPayloadSubmission>>>,
    trace: Arc<Mutex<Vec<&'static str>>>,
    fail_notification: bool,
}

impl ExecutionEngine<Minimal> for RecordingPayloadEngine {
    const IS_NULL: bool = false;

    fn allow_optimistic_merge_block_validation(&self) -> bool {
        false
    }

    fn exchange_capabilities(&self) {}

    fn get_blobs(&self, _params: execution_engine::EngineGetBlobsParams<Minimal>) {}

    fn get_payload_bodies_by_hash(
        &self,
        _block_hashes: Vec<ExecutionBlockHash>,
        _sender: futures::channel::oneshot::Sender<
            Result<Vec<Option<types::nonstandard::ExecutionPayloadBody<Minimal>>>>,
        >,
    ) {
    }

    fn notify_forkchoice_updated(
        &self,
        _head_eth1_block_hash: ExecutionBlockHash,
        _safe_eth1_block_hash: ExecutionBlockHash,
        _finalized_eth1_block_hash: ExecutionBlockHash,
        _payload_attributes: Either<Phase, execution_engine::PayloadAttributes<Minimal>>,
        _sender: Option<futures::channel::oneshot::Sender<Option<execution_engine::PayloadId>>>,
    ) {
    }

    fn notify_new_payload(
        &self,
        block_root: H256,
        payload: types::combined::ExecutionPayload<Minimal>,
        params: Option<ExecutionPayloadParams<Minimal>>,
        _sender: Option<
            futures::channel::oneshot::Sender<Result<execution_engine::PayloadStatusV1>>,
        >,
    ) -> Result<()> {
        self.trace.lock().push("notify");
        self.requests.lock().push(RecordedPayloadSubmission {
            block_root,
            payload,
            params,
        });

        if self.fail_notification {
            anyhow::bail!("test-only execution submission failure");
        }
        Ok(())
    }

    fn pow_block(
        &self,
        _block_hash: ExecutionBlockHash,
    ) -> Option<types::nonstandard::TimedPowBlock> {
        None
    }

    fn stop(&self) {}
}

fn payload_validation_fixture() -> PayloadValidationFixture<NoopStorage> {
    payload_validation_fixture_with_state_bid_commitments(Arc::new(NoopStorage), None, None, None)
}

#[expect(
    clippy::too_many_lines,
    reason = "the state, bid, and envelope share roots best shown in one fixture"
)]
fn payload_validation_fixture_with_state_bid_commitments<S: Storage<Minimal>>(
    storage: Arc<S>,
    block_bid_commitments: Option<Vec<KzgCommitment>>,
    state_bid_commitments: Option<Vec<KzgCommitment>>,
    validator: Option<Validator>,
) -> PayloadValidationFixture<S> {
    let chain_config = Arc::new(ChainConfig::default());
    let parent_beacon_block_root = H256::repeat_byte(0x33);
    let execution_requests = ExecutionRequests::<Minimal> {
        deposits: ProgressiveList::try_from(vec![types::electra::containers::DepositRequest {
            withdrawal_credentials: H256::repeat_byte(0x91),
            amount: 32,
            index: 7,
            ..Default::default()
        }])
        .expect("one execution deposit request fits its bound"),
        ..Default::default()
    };
    let mut bid = ExecutionPayloadBid::<Minimal> {
        block_hash: ExecutionBlockHash::repeat_byte(0x44),
        prev_randao: H256::repeat_byte(0x55),
        gas_limit: 30_000_000,
        builder_index: BUILDER_INDEX_SELF_BUILD,
        execution_requests_root: execution_requests.hash_tree_root(),
        ..Default::default()
    };
    bid.blob_kzg_commitments =
        ProgressiveList::try_from(block_bid_commitments.unwrap_or_else(|| {
            vec![
                KzgCommitment::repeat_byte(0x66),
                KzgCommitment::repeat_byte(0x77),
            ]
        }))
        .expect("fixture block commitments fit the progressive-list bound");
    let body = GloasBeaconBlockBody::<Minimal> {
        signed_execution_payload_bid: SignedExecutionPayloadBid {
            message: bid.clone(),
            signature: <_>::default(),
        },
        ..Default::default()
    };
    let mut state_bid = bid.clone();
    if let Some(commitments) = state_bid_commitments {
        state_bid.blob_kzg_commitments = ProgressiveList::try_from(commitments)
            .expect("fixture state commitments fit the progressive-list bound");
    }
    let state = Arc::new(BeaconState::from(GloasBeaconState::<Minimal> {
        validators: validator.into_iter().collect(),
        latest_block_header: BeaconBlockHeader {
            parent_root: parent_beacon_block_root,
            body_root: body.hash_tree_root(),
            ..Default::default()
        },
        latest_execution_payload_bid: state_bid,
        ..Default::default()
    }));
    let block = GloasSignedBeaconBlock {
        message: Hc::from(GloasBeaconBlock {
            parent_root: parent_beacon_block_root,
            state_root: state.hash_tree_root(),
            body,
            ..Default::default()
        }),
        signature: <_>::default(),
    };
    let block_root = block.message.hash_tree_root();
    assert_eq!(accessors::latest_block_root(&state), block_root);
    let timestamp = misc::compute_timestamp_at_slot(&chain_config, &state, state.slot())
        .expect("fixture Gloas timestamp should be computable");
    let payload_envelope = Arc::new(SignedExecutionPayloadEnvelope {
        message: ExecutionPayloadEnvelope {
            payload: GloasExecutionPayload {
                parent_hash: state
                    .post_gloas()
                    .expect("fixture state is Gloas")
                    .latest_block_hash(),
                prev_randao: bid.prev_randao,
                gas_limit: bid.gas_limit,
                gas_used: 21_000,
                block_number: 12,
                timestamp,
                fee_recipient: types::phase0::primitives::ExecutionAddress::repeat_byte(0x88),
                block_hash: bid.block_hash,
                extra_data: Arc::new(
                    ssz::ByteList::try_from(vec![0x10, 0x20, 0x30])
                        .expect("fixture extra data fits its bound"),
                ),
                transactions: Arc::new(
                    ProgressiveList::try_from(vec![
                        types::gloas::primitives::Transaction::<Minimal>::try_from(vec![
                            0x02, 0x03, 0x04,
                        ])
                        .expect("fixture transaction fits its bound"),
                    ])
                    .expect("one fixture transaction fits its bound"),
                ),
                slot_number: state.slot(),
                ..Default::default()
            },
            execution_requests,
            builder_index: bid.builder_index,
            beacon_block_root: block_root,
            parent_beacon_block_root,
        },
        ..Default::default()
    });
    let store = Store::new(
        chain_config,
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

    (store, state, payload_envelope)
}

fn recording_payload_engine<S: Storage<Minimal>>(
    store: &Store<Minimal, S>,
    fail_notification: bool,
) -> RecordingPayloadEngine {
    RecordingPayloadEngine {
        requests: Arc::default(),
        trace: store.execution_proof_context_capture_trace.clone_arc(),
        fail_notification,
    }
}

fn recorded_payload_request(
    engine: &RecordingPayloadEngine,
    index: usize,
) -> (H256, NewPayloadRequest<Minimal>) {
    let submissions = engine.requests.lock();
    let submission = &submissions[index];
    (
        submission.block_root,
        NewPayloadRequest::new(
            &submission.payload,
            submission
                .params
                .as_ref()
                .expect("ordinary Gloas submission has request params"),
        )
        .expect("healthy submitted request should satisfy constructor bounds"),
    )
}

fn payload_carrier_from_snapshot<S: Storage<Minimal> + Clone>(
    store: &Store<Minimal, S>,
    envelope: &Arc<SignedExecutionPayloadEnvelope<Minimal>>,
    fail_capture: bool,
) -> AcceptedExecutionPayloadEnvelope<Minimal> {
    let mut validation_snapshot = store.clone();
    validation_snapshot.fail_execution_proof_context_capture = fail_capture;
    let engine = recording_payload_engine(&validation_snapshot, false);
    accepted_payload_carrier(&validation_snapshot, envelope, &engine)
}

fn accepted_payload_carrier<S: Storage<Minimal>>(
    store: &Store<Minimal, S>,
    envelope: &Arc<SignedExecutionPayloadEnvelope<Minimal>>,
    engine: &RecordingPayloadEngine,
) -> AcceptedExecutionPayloadEnvelope<Minimal> {
    match store
        .validate_execution_payload_envelope(
            envelope,
            &ExecutionPayloadEnvelopeOrigin::Own,
            engine,
            NullVerifier,
        )
        .expect("ordinary payload validation should return an action")
    {
        ExecutionPayloadEnvelopeValidationAction::Accept(accepted) => accepted,
        _ => panic!("fixture payload should be accepted by ordinary validation"),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the target, descendants, and checkpoint boundary form one topology fixture"
)]
fn retained_unfinalized_payload_fixture() -> RetainedUnfinalizedPayloadFixture {
    let key = proof_signing_key();
    let validator = Validator {
        pubkey: key.to_public_key().into(),
        activation_epoch: 0,
        exit_epoch: FAR_FUTURE_EPOCH,
        ..Default::default()
    };
    let (mut store, _, _) = payload_validation_fixture_with_state_bid_commitments(
        Arc::new(NoopStorage),
        None,
        None,
        Some(validator),
    );
    // These synthetic links use Gloas fork-choice semantics, including head selection
    // during finalization; the default fork schedule does not activate Gloas at slot zero.
    store.chain_config = Arc::new(ChainConfig::default().start_and_stay_in(Phase::Gloas));
    assert_eq!(store.phase(), Phase::Gloas);
    let parent_root = store.last_finalized().block_root;
    let slot = 1;
    let execution_requests = ExecutionRequests::<Minimal>::default();
    let bid = ExecutionPayloadBid::<Minimal> {
        block_hash: ExecutionBlockHash::repeat_byte(0x61),
        prev_randao: H256::repeat_byte(0x62),
        gas_limit: 30_000_000,
        builder_index: BUILDER_INDEX_SELF_BUILD,
        execution_requests_root: execution_requests.hash_tree_root(),
        ..Default::default()
    };
    let body = GloasBeaconBlockBody::<Minimal> {
        signed_execution_payload_bid: SignedExecutionPayloadBid {
            message: bid.clone(),
            signature: <_>::default(),
        },
        ..Default::default()
    };
    let target_state = Arc::new(BeaconState::from(GloasBeaconState::<Minimal> {
        validators: core::iter::once(Validator {
            pubkey: key.to_public_key().into(),
            activation_epoch: 0,
            exit_epoch: FAR_FUTURE_EPOCH,
            ..Default::default()
        })
        .collect(),
        slot,
        latest_block_header: BeaconBlockHeader {
            slot,
            proposer_index: 0,
            parent_root,
            body_root: body.hash_tree_root(),
            ..Default::default()
        },
        latest_execution_payload_bid: bid.clone(),
        ..Default::default()
    }));
    let target_block = GloasSignedBeaconBlock {
        message: Hc::from(GloasBeaconBlock {
            slot,
            proposer_index: 0,
            parent_root,
            state_root: target_state.hash_tree_root(),
            body,
        }),
        signature: <_>::default(),
    };
    let target_root = target_block.message.hash_tree_root();
    assert_eq!(target_block.message.slot, slot);
    assert_eq!(target_block.message.proposer_index, 0);
    assert_eq!(target_block.message.parent_root, parent_root);
    assert_eq!(
        target_block
            .message
            .body
            .signed_execution_payload_bid
            .message,
        bid
    );
    assert_eq!(target_state.latest_block_header().slot, slot);
    assert_eq!(target_state.latest_block_header().proposer_index, 0);
    assert_eq!(target_state.latest_block_header().parent_root, parent_root);
    assert_eq!(
        target_state.latest_block_header().body_root,
        target_block.message.body.hash_tree_root()
    );
    assert_eq!(
        target_state
            .post_gloas()
            .expect("target state is Gloas")
            .latest_execution_payload_bid(),
        &bid
    );
    let validators = target_state.validators();
    assert_eq!(validators.len_u64(), 1);
    assert_eq!(
        validators
            .get(0)
            .expect("target state has validator 0")
            .pubkey,
        key.to_public_key().into()
    );
    assert_eq!(accessors::latest_block_root(&target_state), target_root);

    let checkpoint = store.finalized_checkpoint;
    store
        .insert_block(ChainLink {
            block_root: target_root,
            block: Arc::new(SignedBeaconBlock::<Minimal>::from(target_block)),
            state: Some(target_state.clone_arc()),
            current_justified_checkpoint: checkpoint,
            finalized_checkpoint: checkpoint,
            unrealized_justified_checkpoint: checkpoint,
            unrealized_finalized_checkpoint: checkpoint,
            payload_status: PayloadStatus::Optimistic,
            parent_payload_presence: PayloadPresence::default(),
        })
        .expect("target should be inserted below the current finalized anchor");
    assert!(store.unfinalized_locations.contains_key(&target_root));

    // This child supplies a retained finalization target only; no child state is replayed.
    let descendant_block = GloasSignedBeaconBlock {
        message: Hc::from(GloasBeaconBlock {
            slot: slot + 1,
            proposer_index: 0,
            parent_root: target_root,
            state_root: H256::repeat_byte(0x63),
            body: GloasBeaconBlockBody::default(),
        }),
        signature: <_>::default(),
    };
    let descendant_root = descendant_block.message.hash_tree_root();
    assert_eq!(descendant_block.message.slot, slot + 1);
    assert_eq!(descendant_block.message.parent_root, target_root);
    store
        .insert_block(ChainLink {
            block_root: descendant_root,
            block: Arc::new(SignedBeaconBlock::<Minimal>::from(descendant_block)),
            state: None,
            current_justified_checkpoint: checkpoint,
            finalized_checkpoint: checkpoint,
            unrealized_justified_checkpoint: checkpoint,
            unrealized_finalized_checkpoint: checkpoint,
            payload_status: PayloadStatus::Optimistic,
            parent_payload_presence: PayloadPresence::default(),
        })
        .expect("descendant should extend the retained target");
    assert!(store.unfinalized_locations.contains_key(&descendant_root));
    let retained_descendant = store
        .chain_link(descendant_root)
        .expect("inserted descendant remains addressable");
    assert_eq!(retained_descendant.parent_root(), target_root);
    assert_eq!(retained_descendant.slot(), slot + 1);
    assert_eq!(retained_descendant.block_root, descendant_root);
    assert!(retained_descendant.state.is_none());

    // Keep one child beyond the checkpoint: Segment::finalize_up_to must retain a nonempty
    // suffix when the target and checkpoint are finalized through their ordinary Store path.
    let post_checkpoint_block = GloasSignedBeaconBlock {
        message: Hc::from(GloasBeaconBlock {
            slot: slot + 2,
            proposer_index: 0,
            parent_root: descendant_root,
            state_root: H256::repeat_byte(0x64),
            body: GloasBeaconBlockBody::default(),
        }),
        signature: <_>::default(),
    };
    let post_checkpoint_root = post_checkpoint_block.message.hash_tree_root();
    store
        .insert_block(ChainLink {
            block_root: post_checkpoint_root,
            block: Arc::new(SignedBeaconBlock::<Minimal>::from(post_checkpoint_block)),
            state: None,
            current_justified_checkpoint: checkpoint,
            finalized_checkpoint: checkpoint,
            unrealized_justified_checkpoint: checkpoint,
            unrealized_finalized_checkpoint: checkpoint,
            payload_status: PayloadStatus::Optimistic,
            parent_payload_presence: PayloadPresence::default(),
        })
        .expect("post-checkpoint child should extend the finalization target");
    assert!(
        store
            .unfinalized_locations
            .contains_key(&post_checkpoint_root)
    );
    let retained_post_checkpoint = store
        .chain_link(post_checkpoint_root)
        .expect("post-checkpoint child remains addressable");
    assert_eq!(retained_post_checkpoint.parent_root(), descendant_root);
    assert_eq!(retained_post_checkpoint.slot(), slot + 2);
    assert_eq!(retained_post_checkpoint.block_root, post_checkpoint_root);
    assert!(retained_post_checkpoint.state.is_none());

    let chain_config = store.chain_config.clone_arc();
    let timestamp = misc::compute_timestamp_at_slot(&chain_config, &target_state, slot)
        .expect("fixture target timestamp should be computable");
    let payload_envelope = Arc::new(SignedExecutionPayloadEnvelope {
        message: ExecutionPayloadEnvelope {
            payload: GloasExecutionPayload {
                parent_hash: target_state
                    .post_gloas()
                    .expect("target state is Gloas")
                    .latest_block_hash(),
                prev_randao: bid.prev_randao,
                gas_limit: bid.gas_limit,
                timestamp,
                block_hash: bid.block_hash,
                slot_number: slot,
                ..Default::default()
            },
            execution_requests,
            builder_index: bid.builder_index,
            beacon_block_root: target_root,
            parent_beacon_block_root: parent_root,
        },
        ..Default::default()
    });

    (
        store,
        target_state,
        payload_envelope,
        descendant_root,
        post_checkpoint_root,
        key,
    )
}

fn payload_with_gas_used(
    envelope: &Arc<SignedExecutionPayloadEnvelope<Minimal>>,
    gas_used: u64,
) -> Arc<SignedExecutionPayloadEnvelope<Minimal>> {
    let mut replacement = envelope.as_ref().clone();
    replacement.message.payload.gas_used = gas_used;
    Arc::new(replacement)
}

fn assert_selected_payload_application<S: Storage<Minimal>>(
    store: &Store<Minimal, S>,
    envelope: &Arc<SignedExecutionPayloadEnvelope<Minimal>>,
    proof_public_input: Option<PublicInput>,
    is_timely: bool,
) {
    let block_root = envelope.block_root();
    assert!(store.payloads.contains(&block_root));
    assert_eq!(
        store.timely_payloads.contains(&block_root),
        is_timely,
        "timely marker should follow ordinary deadline handling"
    );
    assert!(store.accepted_execution_payload_envelopes.contains(&(
        envelope.slot(),
        block_root,
        envelope.builder_index(),
    )));
    assert_eq!(
        store
            .cached_execution_payload_envelope_by_root(block_root)
            .expect("ordinary application should select the envelope")
            .as_ref(),
        envelope.as_ref(),
        "the full selected envelope must remain paired with its evidence"
    );
    assert_eq!(
        store.execution_proof_contexts.get(&block_root).copied(),
        proof_public_input,
        "proof authority must match the currently selected envelope"
    );
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

fn cache_accepted_test_payload<S: Storage<Minimal>>(
    store: &mut Store<Minimal, S>,
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

fn seed_execution_proof_context_for_test<S: Storage<Minimal>>(
    store: &mut Store<Minimal, S>,
    state: &BeaconState<Minimal>,
    payload_envelope: &ExecutionPayloadEnvelope<Minimal>,
) {
    // Successful-preparation fixtures model the paired Store apply result explicitly. Context
    // loader/replay fixtures intentionally use marker/cache only and do not seed this identity.
    let post_gloas_state = state
        .post_gloas()
        .expect("proof-preparation fixture must use a Gloas state");
    let public_input = store
        .execution_proof_public_input_from_parts(
            payload_envelope,
            post_gloas_state
                .latest_execution_payload_bid()
                .blob_kzg_commitments
                .iter()
                .copied()
                .map(misc::kzg_commitment_to_versioned_hash),
        )
        .expect("fixture state and payload should have bindable Gloas context");
    store
        .execution_proof_contexts
        .insert(payload_envelope.beacon_block_root, public_input);
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
    HashMap<H256, HashMap<ProofType, Arc<ExecutionProofEnvelope>>>,
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
        "verified proofs must remain unchanged"
    );
    assert_eq!(
        store.execution_proof_roots, before.1,
        "Seen envelope roots must remain unchanged"
    );
    assert_eq!(
        store.execution_proof_provers, before.2,
        "Seen provers must remain unchanged"
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
        .insert(2, Arc::new(envelope.message.as_ref().clone()));
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
    execution_proofs: &HashMap<H256, HashMap<ProofType, Arc<ExecutionProofEnvelope>>>,
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
        .insert(1, Arc::new(duplicate.message.as_ref().clone()));
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
        .insert(1, Arc::new(verified_type_one.message.as_ref().clone()));
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
        .insert(1, Arc::new(first_attempt.message.as_ref().clone()));
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
        .insert(1, Arc::new(candidate.message.as_ref().clone()));
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
        .insert(1, Arc::new(envelope.message.as_ref().clone()));
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

fn second_proof_signing_key() -> SecretKey {
    let mut bytes = SecretKeyBytes::default();
    bytes.as_mut()[31] = 2; // Deterministic scalar-two test key.
    bytes.try_into().expect("scalar two is a valid secret key")
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
    let key = proof_signing_key();
    proof_preparation_fixture_with_keys(validator_exit_epoch, accepted_payload, &[key])
}

fn proof_preparation_fixture_with_keys(
    validator_exit_epoch: Epoch,
    accepted_payload: bool,
    keys: &[SecretKey],
) -> (
    Store<Minimal, ContextStorage>,
    Arc<BeaconState<Minimal>>,
    SignedExecutionProofEnvelope,
) {
    let storage = Arc::new(ContextStorage::default());
    let signing_key = keys
        .first()
        .expect("proof preparation fixture requires at least one signing key");
    let body = GloasBeaconBlockBody::<Minimal>::default();
    let state = Arc::new(BeaconState::from(GloasBeaconState::<Minimal> {
        validators: keys
            .iter()
            .map(|key| Validator {
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
        let payload_envelope = cache_accepted_test_payload(&mut store, block_root, state.slot());
        seed_execution_proof_context_for_test(&mut store, &state, &payload_envelope.message);
    }

    let envelope = ExecutionProofEnvelope {
        proof_data: ProofData::try_from(vec![0x42])
            .expect("one byte is within the proof-data bound"),
        proof_type: 1,
        beacon_block_root: block_root,
    };
    // Sign only after the trusted state and its block root are fixed.
    let signature = envelope
        .sign(&store.chain_config, &state, state.slot(), signing_key)
        .into();
    let signed_proof = SignedExecutionProofEnvelope {
        message: Hc::from(envelope),
        validator_index: 0,
        signature,
    };

    (store, state, signed_proof)
}

fn signed_execution_proof_for_test<S: Storage<Minimal>>(
    store: &Store<Minimal, S>,
    state: &BeaconState<Minimal>,
    proof_data: &[u8],
    proof_type: ProofType,
    validator_index: ValidatorIndex,
    key: &SecretKey,
) -> SignedExecutionProofEnvelope {
    let envelope = ExecutionProofEnvelope {
        proof_data: ProofData::try_from(proof_data.to_vec())
            .expect("test proof bytes are within the proof-data bound"),
        proof_type,
        beacon_block_root: accessors::latest_block_root(state),
    };
    let signature = envelope
        .sign(&store.chain_config, state, state.slot(), key)
        .into();

    SignedExecutionProofEnvelope {
        message: Hc::from(envelope),
        validator_index,
        signature,
    }
}

fn prepared_execution_proof_for_test<S: Storage<Minimal>>(
    store: &Store<Minimal, S>,
    signed_envelope: &SignedExecutionProofEnvelope,
) -> Box<PreparedExecutionProof> {
    match crate::prepare_execution_proof(store, signed_envelope) {
        Ok(crate::ExecutionProofPreparation::Prepared(prepared)) => prepared,
        Ok(crate::ExecutionProofPreparation::Ignore(reason)) => {
            panic!("authenticated proof fixture should prepare: {reason}")
        }
        Err(error) => panic!("authenticated proof fixture failed to prepare: {error:#}"),
    }
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

fn assert_admitted_callback_result(expected_outcome: ExecutionProofVerificationOutcome) {
    let (store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);

    let expected_input = prepared.execution_proof().clone();
    let expected_message = prepared.signed_message().clone();
    let expected_context_identity = *prepared.context_identity();
    let expected_envelope_root = prepared.envelope_root();
    let expected_validator_index = prepared.validator_index();
    // Pointer checks cover the handoff only, not preparation or persistent-map copies.
    let input_data_pointer = prepared.execution_proof().proof_data.as_bytes().as_ptr();
    let message_data_pointer = prepared.signed_message().proof_data.as_bytes().as_ptr();
    assert!(!expected_input.proof_data.as_bytes().is_empty());
    assert!(!expected_message.proof_data.as_bytes().is_empty());

    let bookkeeping = execution_proof_bookkeeping(&store);
    let proof_contexts = store.execution_proof_contexts.clone();
    // Synthetic admission: authentication is real, but live Seen checks are not exercised.
    let admitted = AdmittedExecutionProof { prepared };
    let mut callback_calls = 0_usize;
    let completion = admitted.verify_with(|input| {
        callback_calls = callback_calls
            .checked_add(1)
            .expect("a FnOnce callback can run at most once");
        assert_eq!(
            input.proof_data.as_bytes(),
            expected_input.proof_data.as_bytes()
        );
        assert_eq!(input.proof_type, expected_input.proof_type);
        assert_eq!(input.public_input, expected_input.public_input);
        assert_eq!(input.proof_data.as_bytes().as_ptr(), input_data_pointer);
        expected_outcome
    });

    assert_eq!(callback_calls, 1, "the callback runs once on normal return");
    assert_eq!(completion.envelope(), &expected_message);
    assert_eq!(
        completion.signed_envelope.signature,
        signed_envelope.signature
    );
    assert_eq!(
        completion.envelope().proof_data.as_bytes(),
        expected_message.proof_data.as_bytes()
    );
    assert_eq!(
        completion.envelope().proof_type,
        expected_message.proof_type
    );
    assert_eq!(
        completion.envelope().beacon_block_root,
        expected_context_identity.beacon_block_root()
    );
    assert_eq!(
        completion.envelope().proof_data.as_bytes().as_ptr(),
        message_data_pointer,
        "the associated message retains its original proof-byte allocation"
    );
    assert_eq!(completion.validator_index(), expected_validator_index);
    assert_eq!(completion.context_identity(), &expected_context_identity);
    assert_eq!(
        completion.context_identity().public_input(),
        &expected_input.public_input,
        "the completion retains all fields of Q"
    );
    assert_eq!(completion.envelope_root(), expected_envelope_root);
    assert_eq!(completion.verification_outcome(), expected_outcome);
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);
    assert_eq!(store.execution_proof_contexts, proof_contexts);
}

#[test]
fn admitted_execution_proof_verify_with_preserves_valid_result_and_owned_input() {
    assert_admitted_callback_result(ExecutionProofVerificationOutcome::Valid);
}

#[test]
fn admitted_execution_proof_verify_with_preserves_invalid_result_and_owned_input() {
    assert_admitted_callback_result(ExecutionProofVerificationOutcome::Invalid);
}

#[test]
fn admitted_execution_proof_local_fault_preserves_association_without_store_mutation() {
    let (store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
    let expected_message = prepared.signed_message().clone();
    let expected_context_identity = *prepared.context_identity();
    let expected_envelope_root = prepared.envelope_root();
    let expected_validator_index = prepared.validator_index();
    let message_data_pointer = prepared.signed_message().proof_data.as_bytes().as_ptr();
    let bookkeeping = execution_proof_bookkeeping(&store);
    let proof_contexts = store.execution_proof_contexts.clone();
    // Synthetic admission, as in the callback tests above.
    let admitted = AdmittedExecutionProof { prepared };

    let completion = admitted.into_local_fault();

    assert_eq!(completion.envelope(), &expected_message);
    assert_eq!(
        completion.signed_envelope.signature,
        signed_envelope.signature
    );
    assert_eq!(
        completion.envelope().proof_data.as_bytes().as_ptr(),
        message_data_pointer
    );
    assert_eq!(completion.validator_index(), expected_validator_index);
    assert_eq!(completion.context_identity(), &expected_context_identity);
    assert_eq!(completion.envelope_root(), expected_envelope_root);
    assert_eq!(
        completion.verification_outcome(),
        ExecutionProofVerificationOutcome::LocalFault
    );
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);
    assert_eq!(store.execution_proof_contexts, proof_contexts);
}

fn assert_execution_proof_admission_declined_without_writes<S: Storage<Minimal>>(
    store: &mut Store<Minimal, S>,
    prepared: Box<PreparedExecutionProof>,
    expected: ExecutionProofAdmissionDecline,
) {
    let bookkeeping = execution_proof_bookkeeping(store);
    let proof_contexts = store.execution_proof_contexts.clone();
    let payloads = store.payloads.clone();

    let admission = store.admit_execution_proof(prepared);

    assert!(matches!(
        admission,
        ExecutionProofAdmission::Declined(actual) if actual == expected
    ));
    assert_execution_proof_bookkeeping_unchanged(store, &bookkeeping);
    assert_eq!(store.execution_proof_contexts, proof_contexts);
    assert_eq!(store.payloads, payloads);
}

#[expect(
    clippy::too_many_lines,
    reason = "ownership and unchanged-state assertions share one admission fixture"
)]
#[test]
fn execution_proof_admission_adds_both_seen_keys_and_preserves_prepared_ownership() {
    let (mut store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
    let block_root = prepared.context_identity().beacon_block_root();
    let proof_type = prepared.signed_message().proof_type;
    let validator_index = prepared.validator_index();
    let envelope_root = prepared.envelope_root();
    let expected_input = prepared.execution_proof().clone();
    let expected_message = prepared.signed_message().clone();
    let expected_context_identity = *prepared.context_identity();
    let prepared_pointer = core::ptr::from_ref(prepared.as_ref());
    let input_data_pointer = prepared.execution_proof().proof_data.as_bytes().as_ptr();
    let message_data_pointer = prepared.signed_message().proof_data.as_bytes().as_ptr();
    let bookkeeping = execution_proof_bookkeeping(&store);
    let mut expected_roots = bookkeeping.1.clone();
    expected_roots
        .entry(block_root)
        .or_default()
        .insert(envelope_root);
    let mut expected_provers = bookkeeping.2.clone();
    expected_provers.insert((block_root, proof_type, validator_index));
    let proof_contexts = store.execution_proof_contexts.clone();
    let payloads = store.payloads.clone();
    let tick = store.tick();
    let justified_checkpoint = store.justified_checkpoint();
    let finalized_checkpoint = store.finalized_checkpoint();
    let last_finalized_root = store.last_finalized().block_root;
    let head_root = store.head().block_root;
    let head_payload_status = store.head_node_payload_status();
    let cached_payload_pointer = Arc::as_ptr(
        store
            .cached_execution_payload_envelope_by_root(block_root)
            .expect("prepared proof fixture must retain its accepted payload"),
    );
    let trusted_state_pointer = store
        .chain_link(block_root)
        .expect("prepared proof fixture must retain its target link")
        .state
        .as_ref()
        .map(Arc::as_ptr);

    let admission = store.admit_execution_proof(prepared);
    let admitted = match admission {
        ExecutionProofAdmission::Admitted(admitted) => admitted,
        ExecutionProofAdmission::Declined(_) => {
            panic!("fresh authentic proof should be admitted")
        }
    };

    assert_eq!(
        core::ptr::from_ref(admitted.prepared.as_ref()),
        prepared_pointer
    );
    assert_eq!(admitted.prepared.execution_proof(), &expected_input);
    assert_eq!(
        admitted
            .prepared
            .execution_proof()
            .proof_data
            .as_bytes()
            .as_ptr(),
        input_data_pointer
    );
    assert_eq!(admitted.prepared.signed_message(), &expected_message);
    assert_eq!(
        admitted
            .prepared
            .signed_message()
            .proof_data
            .as_bytes()
            .as_ptr(),
        message_data_pointer
    );
    assert_eq!(
        admitted.prepared.context_identity(),
        &expected_context_identity
    );
    assert_eq!(admitted.prepared.envelope_root(), envelope_root);
    assert_eq!(store.execution_proofs, bookkeeping.0);
    assert_eq!(store.execution_proof_roots, expected_roots);
    assert_eq!(store.execution_proof_provers, expected_provers);
    assert_eq!(store.execution_proof_contexts, proof_contexts);
    assert_eq!(store.payloads, payloads);
    assert_eq!(store.tick(), tick);
    assert_eq!(store.justified_checkpoint(), justified_checkpoint);
    assert_eq!(store.finalized_checkpoint(), finalized_checkpoint);
    assert_eq!(store.last_finalized().block_root, last_finalized_root);
    assert_eq!(store.head().block_root, head_root);
    assert_eq!(store.head_node_payload_status(), head_payload_status);
    assert_eq!(
        Arc::as_ptr(
            store
                .cached_execution_payload_envelope_by_root(block_root)
                .expect("admission must not evict its accepted payload")
        ),
        cached_payload_pointer
    );
    assert_eq!(
        store
            .chain_link(block_root)
            .expect("admission must not remove its target link")
            .state
            .as_ref()
            .map(Arc::as_ptr),
        trusted_state_pointer
    );
}

#[test]
fn execution_proof_admission_declines_in_specified_precedence() {
    for expected in [
        ExecutionProofAdmissionDecline::Retired,
        ExecutionProofAdmissionDecline::ContextInapplicable,
        ExecutionProofAdmissionDecline::AlreadyVerified,
        ExecutionProofAdmissionDecline::SeenRoot,
        ExecutionProofAdmissionDecline::SeenProver,
    ] {
        let (mut store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
        let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
        let block_root = prepared.context_identity().beacon_block_root();
        let proof_type = prepared.signed_message().proof_type;
        let validator_index = prepared.validator_index();
        let envelope_root = prepared.envelope_root();
        let stored_envelope = Arc::new(prepared.signed_message().clone());

        match expected {
            ExecutionProofAdmissionDecline::Retired => {
                let (other_store, _, other_root) =
                    gloas_context_store(Arc::new(ContextStorage::default()), 7);
                assert_ne!(block_root, other_root);
                store.finalized.push_back(other_store.finalized[0].clone());
                store.finalized_indices.insert(other_root, 1);
                store.payloads.remove(&block_root);
                store
                    .execution_proofs
                    .entry(block_root)
                    .or_default()
                    .insert(proof_type, stored_envelope);
                store
                    .execution_proof_roots
                    .entry(block_root)
                    .or_default()
                    .insert(envelope_root);
                store
                    .execution_proof_provers
                    .insert((block_root, proof_type, validator_index));
            }
            ExecutionProofAdmissionDecline::ContextInapplicable => {
                store.payloads.remove(&block_root);
                store
                    .execution_proofs
                    .entry(block_root)
                    .or_default()
                    .insert(proof_type, stored_envelope);
                store
                    .execution_proof_roots
                    .entry(block_root)
                    .or_default()
                    .insert(envelope_root);
                store
                    .execution_proof_provers
                    .insert((block_root, proof_type, validator_index));
            }
            ExecutionProofAdmissionDecline::AlreadyVerified => {
                store
                    .execution_proofs
                    .entry(block_root)
                    .or_default()
                    .insert(proof_type, stored_envelope);
                store
                    .execution_proof_roots
                    .entry(block_root)
                    .or_default()
                    .insert(envelope_root);
                store
                    .execution_proof_provers
                    .insert((block_root, proof_type, validator_index));
            }
            ExecutionProofAdmissionDecline::SeenRoot => {
                store
                    .execution_proof_roots
                    .entry(block_root)
                    .or_default()
                    .insert(envelope_root);
                store
                    .execution_proof_provers
                    .insert((block_root, proof_type, validator_index));
            }
            ExecutionProofAdmissionDecline::SeenProver => {
                store
                    .execution_proof_provers
                    .insert((block_root, proof_type, validator_index));
            }
        }

        assert_execution_proof_admission_declined_without_writes(&mut store, prepared, expected);
    }
}

#[test]
fn execution_proof_admission_checks_seen_keys_independently() {
    let (mut root_store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let prepared = prepared_execution_proof_for_test(&root_store, &signed_envelope);
    let block_root = prepared.context_identity().beacon_block_root();
    root_store
        .execution_proof_roots
        .entry(block_root)
        .or_default()
        .insert(prepared.envelope_root());
    assert_execution_proof_admission_declined_without_writes(
        &mut root_store,
        prepared,
        ExecutionProofAdmissionDecline::SeenRoot,
    );

    let (mut prover_store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let prepared = prepared_execution_proof_for_test(&prover_store, &signed_envelope);
    let prover_key = (
        prepared.context_identity().beacon_block_root(),
        prepared.signed_message().proof_type,
        prepared.validator_index(),
    );
    prover_store.execution_proof_provers.insert(prover_key);
    assert_execution_proof_admission_declined_without_writes(
        &mut prover_store,
        prepared,
        ExecutionProofAdmissionDecline::SeenProver,
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "four competing cases share one old-snapshot fixture and full state assertions"
)]
#[test]
fn execution_proof_admission_competing_prepared_attempts_use_live_seen_keys() {
    let keys = [proof_signing_key(), second_proof_signing_key()];
    let (base_store, state, first_signed) =
        proof_preparation_fixture_with_keys(FAR_FUTURE_EPOCH, true, &keys);
    let block_root = first_signed.message.beacon_block_root;
    let cases: [(&str, &[u8], ValidatorIndex, bool, bool); 4] = [
        ("same R, different V", &[0x42], 1, true, false),
        ("different R, same K", &[0x43], 0, false, true),
        ("identical R and K", &[0x42], 0, true, true),
        ("different R and V", &[0x43], 1, false, false),
    ];

    for (
        case,
        second_proof_data,
        second_validator_index,
        roots_should_match,
        prover_keys_should_match,
    ) in cases
    {
        let mut live_store = base_store.clone();
        seed_execution_proof_bookkeeping(&mut live_store, block_root);
        let old_snapshot = live_store.clone();
        let old_bookkeeping = execution_proof_bookkeeping(&old_snapshot);
        assert!(old_bookkeeping.0[&block_root].contains_key(&2));
        assert!(old_bookkeeping.1[&block_root].contains(&H256::repeat_byte(0x92)));
        assert!(old_bookkeeping.2.contains(&(block_root, 2, 7)));
        assert!(!old_bookkeeping.0[&block_root].contains_key(&1));
        assert!(!old_bookkeeping.2.contains(&(block_root, 1, 0)));

        let signer_index =
            usize::try_from(second_validator_index).expect("fixture validator index fits in usize");
        let second_signed = signed_execution_proof_for_test(
            &old_snapshot,
            &state,
            second_proof_data,
            1,
            second_validator_index,
            &keys[signer_index],
        );
        let first_prepared = prepared_execution_proof_for_test(&old_snapshot, &first_signed);
        let second_prepared = prepared_execution_proof_for_test(&old_snapshot, &second_signed);

        assert_eq!(
            first_prepared.context_identity().beacon_block_root(),
            block_root
        );
        assert_eq!(
            second_prepared.context_identity().beacon_block_root(),
            block_root
        );
        assert_eq!(first_prepared.signed_message().proof_type, 1);
        assert_eq!(second_prepared.signed_message().proof_type, 1);
        assert_eq!(first_prepared.validator_index(), 0);
        assert_eq!(second_prepared.validator_index(), second_validator_index);
        assert_eq!(
            first_prepared.context_identity(),
            second_prepared.context_identity(),
            "competing attempts share the same trusted context"
        );
        assert_eq!(
            first_prepared.envelope_root() == second_prepared.envelope_root(),
            roots_should_match,
            "unexpected R relation for {case}"
        );
        let first_prover_key = (
            first_prepared.context_identity().beacon_block_root(),
            first_prepared.signed_message().proof_type,
            first_prepared.validator_index(),
        );
        let second_prover_key = (
            second_prepared.context_identity().beacon_block_root(),
            second_prepared.signed_message().proof_type,
            second_prepared.validator_index(),
        );
        assert_eq!(
            first_prover_key == second_prover_key,
            prover_keys_should_match,
            "unexpected K relation for {case}"
        );
        assert_execution_proof_bookkeeping_unchanged(&old_snapshot, &old_bookkeeping);

        let mut expected_after_first = old_bookkeeping.clone();
        expected_after_first
            .1
            .entry(block_root)
            .or_default()
            .insert(first_prepared.envelope_root());
        expected_after_first.2.insert(first_prover_key);
        assert!(matches!(
            live_store.admit_execution_proof(first_prepared),
            ExecutionProofAdmission::Admitted(_)
        ));
        assert_eq!(
            execution_proof_bookkeeping(&live_store),
            expected_after_first,
            "first admission must add only its two Seen keys for {case}"
        );
        assert_execution_proof_bookkeeping_unchanged(&old_snapshot, &old_bookkeeping);

        if !roots_should_match && !prover_keys_should_match {
            let mut expected_after_second = expected_after_first;
            expected_after_second
                .1
                .entry(block_root)
                .or_default()
                .insert(second_prepared.envelope_root());
            expected_after_second.2.insert(second_prover_key);
            assert!(matches!(
                live_store.admit_execution_proof(second_prepared),
                ExecutionProofAdmission::Admitted(_)
            ));
            assert_eq!(
                execution_proof_bookkeeping(&live_store),
                expected_after_second,
                "distinct R and K must add exactly two more Seen keys"
            );
        } else {
            let before_loser = execution_proof_bookkeeping(&live_store);
            let expected_decline = if roots_should_match {
                ExecutionProofAdmissionDecline::SeenRoot
            } else {
                ExecutionProofAdmissionDecline::SeenProver
            };
            assert!(matches!(
                live_store.admit_execution_proof(second_prepared),
                ExecutionProofAdmission::Declined(actual) if actual == expected_decline
            ));
            assert_eq!(
                execution_proof_bookkeeping(&live_store),
                before_loser,
                "a losing attempt must add neither key for {case}"
            );
        }
        assert_eq!(
            live_store.execution_proofs, old_bookkeeping.0,
            "admission must not store a verified proof for {case}"
        );
        assert_execution_proof_bookkeeping_unchanged(&old_snapshot, &old_bookkeeping);
    }
}

#[test]
fn execution_proof_admission_declines_each_live_public_input_field_mismatch() {
    for field in [
        "new_payload_request_root",
        "successful_validation",
        "chain_id",
        "schema_id",
    ] {
        let (mut store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
        let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
        let block_root = prepared.context_identity().beacon_block_root();
        let prepared_input = *prepared.context_identity().public_input();
        assert!(store.payloads.contains(&block_root));
        assert_eq!(
            store.execution_proof_contexts.get(&block_root),
            Some(&prepared_input),
            "fixture Q must match the authentic prepared input before changing {field}"
        );

        let mismatch = match field {
            "new_payload_request_root" => PublicInput {
                new_payload_request_root: H256::repeat_byte(0x99),
                ..prepared_input
            },
            "successful_validation" => PublicInput {
                successful_validation: !prepared_input.successful_validation,
                ..prepared_input
            },
            "chain_id" => PublicInput {
                chain_id: prepared_input.chain_id ^ 1,
                ..prepared_input
            },
            "schema_id" => PublicInput {
                schema_id: prepared_input.schema_id ^ 1,
                ..prepared_input
            },
            _ => unreachable!(),
        };
        let changed_fields = (
            mismatch.new_payload_request_root != prepared_input.new_payload_request_root,
            mismatch.successful_validation != prepared_input.successful_validation,
            mismatch.chain_id != prepared_input.chain_id,
            mismatch.schema_id != prepared_input.schema_id,
        );
        let only_expected_field_changed = match field {
            "new_payload_request_root" => (true, false, false, false),
            "successful_validation" => (false, true, false, false),
            "chain_id" => (false, false, true, false),
            "schema_id" => (false, false, false, true),
            _ => unreachable!(),
        };
        assert_eq!(changed_fields, only_expected_field_changed);

        store.execution_proof_contexts.insert(block_root, mismatch);
        assert!(store.payloads.contains(&block_root));
        assert_eq!(
            store.execution_proof_contexts.get(&block_root),
            Some(&mismatch)
        );
        assert_execution_proof_admission_declined_without_writes(
            &mut store,
            prepared,
            ExecutionProofAdmissionDecline::ContextInapplicable,
        );
    }
}

#[test]
fn execution_proof_admission_declines_when_payload_marker_or_q_is_missing() {
    for missing in ["accepted-payload marker", "Q evidence"] {
        let (mut store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
        let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
        let block_root = prepared.context_identity().beacon_block_root();
        let prepared_input = *prepared.context_identity().public_input();
        assert!(store.payloads.contains(&block_root));
        assert_eq!(
            store.execution_proof_contexts.get(&block_root),
            Some(&prepared_input)
        );

        match missing {
            "accepted-payload marker" => {
                store.payloads.remove(&block_root);
                assert!(!store.payloads.contains(&block_root));
                assert_eq!(
                    store.execution_proof_contexts.get(&block_root),
                    Some(&prepared_input)
                );
            }
            "Q evidence" => {
                store.execution_proof_contexts.remove(&block_root);
                assert!(store.payloads.contains(&block_root));
                assert!(store.execution_proof_contexts.get(&block_root).is_none());
            }
            _ => unreachable!(),
        }

        assert_execution_proof_admission_declined_without_writes(
            &mut store,
            prepared,
            ExecutionProofAdmissionDecline::ContextInapplicable,
        );
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "three live-applicability cases share authentic preparation and exact admission assertions"
)]
#[test]
fn execution_proof_admission_accepts_equivalent_q_unrelated_updates_and_cache_eviction() {
    for update in [
        "equal Q reinsertion",
        "unrelated Seen bookkeeping",
        "cache eviction",
    ] {
        let (mut store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
        let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
        let block_root = prepared.context_identity().beacon_block_root();
        let prepared_input = *prepared.context_identity().public_input();
        let proof_type = prepared.signed_message().proof_type;
        let validator_index = prepared.validator_index();
        let envelope_root = prepared.envelope_root();
        let marker_before = store.payloads.contains(&block_root);
        let context_before = store.execution_proof_contexts.get(&block_root).copied();
        assert!(marker_before);
        assert_eq!(context_before, Some(prepared_input));
        let cached_payload = store
            .cached_execution_payload_envelope_by_root(block_root)
            .expect("preparation fixture retains accepted payload bytes");
        let cached_payload_pointer = Arc::as_ptr(cached_payload);
        let cached_payload_slot = cached_payload.slot();

        match update {
            "equal Q reinsertion" => {
                // PublicInput is inline; remove/reinsert publishes an equal-Q map version.
                let previous_contexts = store.execution_proof_contexts.clone();
                let removed_context = store.execution_proof_contexts.remove(&block_root);
                assert_eq!(removed_context, Some(prepared_input));
                assert_eq!(previous_contexts.get(&block_root), Some(&prepared_input));
                store
                    .execution_proof_contexts
                    .insert(block_root, prepared_input);
            }
            "unrelated Seen bookkeeping" => {
                let unrelated_block_root = H256::repeat_byte(0xa1);
                let unrelated_envelope_root = H256::repeat_byte(0xa2);
                assert_ne!(unrelated_block_root, block_root);
                assert_ne!(unrelated_envelope_root, envelope_root);
                assert!(
                    !store
                        .execution_proof_roots
                        .contains_key(&unrelated_block_root)
                );
                let unrelated_prover_key = (unrelated_block_root, proof_type, validator_index);
                assert!(
                    !store
                        .execution_proof_provers
                        .contains(&unrelated_prover_key)
                );
                store
                    .execution_proof_roots
                    .entry(unrelated_block_root)
                    .or_default()
                    .insert(unrelated_envelope_root);
                store.execution_proof_provers.insert(unrelated_prover_key);
            }
            "cache eviction" => {
                assert!(
                    store
                        .cached_execution_payload_envelope_by_root(block_root)
                        .is_some()
                );
                store
                    .execution_payload_envelope_cache
                    .prune_finalized(cached_payload_slot.saturating_add(1));
                assert!(
                    store
                        .cached_execution_payload_envelope_by_root(block_root)
                        .is_none()
                );
            }
            _ => unreachable!(),
        }

        assert_eq!(store.payloads.contains(&block_root), marker_before);
        assert_eq!(
            store.execution_proof_contexts.get(&block_root).copied(),
            context_before
        );
        let prover_key = (block_root, proof_type, validator_index);
        assert!(
            !store
                .execution_proof_roots
                .get(&block_root)
                .is_some_and(|roots| roots.contains(&envelope_root))
        );
        assert!(!store.execution_proof_provers.contains(&prover_key));
        assert!(
            !store
                .execution_proofs
                .get(&block_root)
                .is_some_and(|proofs| proofs.contains_key(&proof_type))
        );

        let mut expected_roots = store.execution_proof_roots.clone();
        expected_roots
            .entry(block_root)
            .or_default()
            .insert(envelope_root);
        let mut expected_provers = store.execution_proof_provers.clone();
        expected_provers.insert(prover_key);
        let expected_proofs = store.execution_proofs.clone();

        let admission = store.admit_execution_proof(prepared);
        assert!(
            matches!(admission, ExecutionProofAdmission::Admitted(_)),
            "{update}"
        );
        assert_eq!(store.execution_proof_roots, expected_roots, "{update}");
        assert_eq!(store.execution_proof_provers, expected_provers, "{update}");
        assert_eq!(
            store.execution_proofs, expected_proofs,
            "no verified proof is inserted"
        );
        assert_eq!(store.payloads.contains(&block_root), marker_before);
        assert_eq!(
            store.execution_proof_contexts.get(&block_root).copied(),
            context_before
        );
        match update {
            "cache eviction" => assert!(
                store
                    .cached_execution_payload_envelope_by_root(block_root)
                    .is_none()
            ),
            _ => assert_eq!(
                Arc::as_ptr(
                    store
                        .cached_execution_payload_envelope_by_root(block_root)
                        .expect("admission preserves resident accepted payload bytes"),
                ),
                cached_payload_pointer,
                "{update}"
            ),
        }
    }
}

#[test]
fn execution_proof_admission_is_independent_by_proof_type() {
    let (mut store, state, signed_type_1) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let key = proof_signing_key();
    let signed_type_2 = signed_execution_proof_for_test(&store, &state, &[0x42], 2, 0, &key);
    let prepared_type_1 = prepared_execution_proof_for_test(&store, &signed_type_1);
    let prepared_type_2 = prepared_execution_proof_for_test(&store, &signed_type_2);
    let block_root = prepared_type_1.context_identity().beacon_block_root();
    assert_eq!(
        prepared_type_2.context_identity().beacon_block_root(),
        block_root
    );
    assert_eq!(prepared_type_1.signed_message().proof_type, 1);
    assert_eq!(prepared_type_2.signed_message().proof_type, 2);
    assert_eq!(prepared_type_1.validator_index(), 0);
    assert_eq!(prepared_type_2.validator_index(), 0);
    assert_eq!(
        prepared_type_1.signed_message().proof_data.as_bytes(),
        prepared_type_2.signed_message().proof_data.as_bytes()
    );
    assert_ne!(
        prepared_type_1.envelope_root(),
        prepared_type_2.envelope_root(),
        "proof_type is part of the bare signed message"
    );

    let before = execution_proof_bookkeeping(&store);
    assert!(before.0.is_empty() && before.1.is_empty() && before.2.is_empty());
    let mut expected_after_type_1 = before.clone();
    expected_after_type_1
        .1
        .entry(block_root)
        .or_default()
        .insert(prepared_type_1.envelope_root());
    expected_after_type_1.2.insert((block_root, 1, 0));
    let mut expected_after_both = expected_after_type_1.clone();
    expected_after_both
        .1
        .entry(block_root)
        .or_default()
        .insert(prepared_type_2.envelope_root());
    expected_after_both.2.insert((block_root, 2, 0));

    assert!(matches!(
        store.admit_execution_proof(prepared_type_1),
        ExecutionProofAdmission::Admitted(_)
    ));
    assert_eq!(execution_proof_bookkeeping(&store), expected_after_type_1);
    assert!(matches!(
        store.admit_execution_proof(prepared_type_2),
        ExecutionProofAdmission::Admitted(_)
    ));
    assert_eq!(execution_proof_bookkeeping(&store), expected_after_both);
    assert_eq!(store.execution_proofs, before.0);
}

#[test]
fn execution_proof_admission_other_type_survives_verified_occupancy() {
    let (mut store, state, signed_type_1) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let key = proof_signing_key();
    let signed_type_2 = signed_execution_proof_for_test(&store, &state, &[0x42], 2, 0, &key);
    let prepared_type_1 = prepared_execution_proof_for_test(&store, &signed_type_1);
    let prepared_type_2 = prepared_execution_proof_for_test(&store, &signed_type_2);
    let block_root = prepared_type_1.context_identity().beacon_block_root();
    assert_eq!(
        prepared_type_2.context_identity().beacon_block_root(),
        block_root
    );
    assert_eq!(
        prepared_type_1.signed_message().proof_data.as_bytes(),
        &[0x42]
    );
    assert_eq!(
        prepared_type_2.signed_message().proof_data.as_bytes(),
        &[0x42]
    );
    assert_ne!(
        prepared_type_1.envelope_root(),
        prepared_type_2.envelope_root(),
        "proof_type is part of the bare signed message"
    );
    assert!(store.execution_proof_roots.is_empty());
    assert!(store.execution_proof_provers.is_empty());
    assert!(!store.execution_proofs.contains_key(&block_root));

    // Both authentic candidates are prepared before the fixture seeds verified type 1.
    let stored_type_1 = Arc::new(prepared_type_1.signed_message().clone());
    store
        .execution_proofs
        .entry(block_root)
        .or_default()
        .insert(1, Arc::clone(&stored_type_1));
    let before_type_1_decline = execution_proof_bookkeeping(&store);
    assert!(matches!(
        store.admit_execution_proof(prepared_type_1),
        ExecutionProofAdmission::Declined(ExecutionProofAdmissionDecline::AlreadyVerified)
    ));
    assert_eq!(execution_proof_bookkeeping(&store), before_type_1_decline);
    assert_eq!(
        store
            .execution_proofs
            .get(&block_root)
            .and_then(|proofs| proofs.get(&1)),
        Some(&stored_type_1),
        "the existing bare type-1 envelope is preserved exactly"
    );

    let mut expected_after_type_2 = before_type_1_decline;
    expected_after_type_2
        .1
        .entry(block_root)
        .or_default()
        .insert(prepared_type_2.envelope_root());
    expected_after_type_2.2.insert((block_root, 2, 0));
    assert!(matches!(
        store.admit_execution_proof(prepared_type_2),
        ExecutionProofAdmission::Admitted(_)
    ));
    assert_eq!(execution_proof_bookkeeping(&store), expected_after_type_2);
    assert_eq!(
        store
            .execution_proofs
            .get(&block_root)
            .and_then(|proofs| proofs.get(&1)),
        Some(&stored_type_1)
    );
}

#[test]
fn execution_proof_completion_stores_valid_bare_envelope_without_copying_proof_bytes() {
    let (mut store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
    let block_root = prepared.context_identity().beacon_block_root();
    let proof_type = prepared.signed_message().proof_type;
    let validator_index = prepared.validator_index();
    let envelope_root = prepared.envelope_root();
    let expected_input = prepared.execution_proof().clone();
    let expected_proof_bytes = prepared.signed_message().proof_data.as_bytes().to_vec();
    let message_data_pointer = prepared.signed_message().proof_data.as_bytes().as_ptr();
    let input_data_pointer = prepared.execution_proof().proof_data.as_bytes().as_ptr();
    assert!(!expected_proof_bytes.is_empty());

    let bookkeeping_before = execution_proof_bookkeeping(&store);
    assert!(bookkeeping_before.0.is_empty());
    let mut expected_roots = bookkeeping_before.1.clone();
    expected_roots
        .entry(block_root)
        .or_default()
        .insert(envelope_root);
    let mut expected_provers = bookkeeping_before.2;
    expected_provers.insert((block_root, proof_type, validator_index));
    let proof_contexts = store.execution_proof_contexts.clone();
    let payloads = store.payloads.clone();
    let tick = store.tick();
    let justified_checkpoint = store.justified_checkpoint();
    let finalized_checkpoint = store.finalized_checkpoint();
    let last_finalized_root = store.last_finalized().block_root;
    let head_root = store.head().block_root;

    let admitted = match store.admit_execution_proof(prepared) {
        ExecutionProofAdmission::Admitted(admitted) => admitted,
        ExecutionProofAdmission::Declined(_) => panic!("fresh authentic proof should admit"),
    };
    let completion = admitted.verify_with(|input| {
        assert_eq!(
            input, expected_input,
            "verification receives the exact bound input"
        );
        assert_eq!(input.proof_data.as_bytes().as_ptr(), input_data_pointer);
        ExecutionProofVerificationOutcome::Valid
    });
    assert_eq!(
        completion.verification_outcome(),
        ExecutionProofVerificationOutcome::Valid
    );

    assert_eq!(
        store.complete_execution_proof(completion),
        ExecutionProofCompletionOutcome::Accept
    );

    let stored = store.execution_proofs[&block_root]
        .get(&proof_type)
        .expect("valid completion stores its bare envelope");
    assert_eq!(stored.beacon_block_root, block_root);
    assert_eq!(stored.proof_type, proof_type);
    assert_eq!(
        stored.proof_data.as_bytes(),
        expected_proof_bytes.as_slice()
    );
    assert_eq!(stored.proof_data.as_bytes().as_ptr(), message_data_pointer);
    assert_eq!(store.execution_proofs.len(), 1);
    assert_eq!(store.execution_proofs[&block_root].len(), 1);
    assert_eq!(store.execution_proof_roots, expected_roots);
    assert_eq!(store.execution_proof_provers, expected_provers);
    assert_eq!(store.execution_proof_contexts, proof_contexts);
    assert_eq!(store.payloads, payloads);
    assert_eq!(store.tick(), tick);
    assert_eq!(store.justified_checkpoint(), justified_checkpoint);
    assert_eq!(store.finalized_checkpoint(), finalized_checkpoint);
    assert_eq!(store.last_finalized().block_root, last_finalized_root);
    assert_eq!(store.head().block_root, head_root);
}

#[test]
fn execution_proof_completion_reports_callback_local_fault_after_live_admission() {
    let (mut store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
    let block_root = prepared.context_identity().beacon_block_root();
    let proof_type = prepared.signed_message().proof_type;
    let validator_index = prepared.validator_index();
    let envelope_root = prepared.envelope_root();
    let expected_input = prepared.execution_proof().clone();
    let expected_message = prepared.signed_message().clone();
    let expected_context_identity = *prepared.context_identity();
    let input_data_pointer = prepared.execution_proof().proof_data.as_bytes().as_ptr();
    let message_data_pointer = prepared.signed_message().proof_data.as_bytes().as_ptr();
    assert!(!expected_input.proof_data.as_bytes().is_empty());

    let bookkeeping_before = execution_proof_bookkeeping(&store);
    assert!(bookkeeping_before.0.is_empty());
    let mut expected_roots = bookkeeping_before.1.clone();
    expected_roots
        .entry(block_root)
        .or_default()
        .insert(envelope_root);
    let mut expected_provers = bookkeeping_before.2;
    expected_provers.insert((block_root, proof_type, validator_index));
    let proof_contexts = store.execution_proof_contexts.clone();
    let payloads = store.payloads.clone();
    let timely_payloads = store.timely_payloads.clone();
    let accepted_payload_markers = store.accepted_execution_payload_envelopes.clone();
    let cached_payload_pointer = Arc::as_ptr(
        store
            .cached_execution_payload_envelope_by_root(block_root)
            .expect("prepared proof fixture retains its accepted payload"),
    );
    let tick = store.tick();
    let justified_checkpoint = store.justified_checkpoint();
    let finalized_checkpoint = store.finalized_checkpoint();
    let last_finalized_root = store.last_finalized().block_root;
    let head_root = store.head().block_root;

    let admitted = match store.admit_execution_proof(prepared) {
        ExecutionProofAdmission::Admitted(admitted) => admitted,
        ExecutionProofAdmission::Declined(_) => panic!("fresh authentic proof should admit"),
    };
    let mut callback_calls = 0_usize;
    // Model the verifier report only; this Store test does not run a proof engine.
    let completion = admitted.verify_with(|input| {
        callback_calls = callback_calls
            .checked_add(1)
            .expect("a FnOnce callback can run at most once");
        assert_eq!(input, expected_input);
        assert_eq!(input.proof_data.as_bytes().as_ptr(), input_data_pointer);
        ExecutionProofVerificationOutcome::LocalFault
    });

    assert_eq!(callback_calls, 1);
    assert_eq!(completion.envelope(), &expected_message);
    assert_eq!(
        completion.signed_envelope.signature,
        signed_envelope.signature
    );
    assert_eq!(
        completion.envelope().proof_data.as_bytes().as_ptr(),
        message_data_pointer
    );
    assert_eq!(completion.validator_index(), validator_index);
    assert_eq!(completion.context_identity(), &expected_context_identity);
    assert_eq!(completion.envelope_root(), envelope_root);
    assert_eq!(
        completion.verification_outcome(),
        ExecutionProofVerificationOutcome::LocalFault
    );

    assert_eq!(
        store.complete_execution_proof(completion),
        ExecutionProofCompletionOutcome::LocalFault
    );

    assert!(store.execution_proofs.is_empty());
    assert_eq!(store.execution_proof_roots, expected_roots);
    assert_eq!(store.execution_proof_provers, expected_provers);
    assert_eq!(store.execution_proof_contexts, proof_contexts);
    assert_eq!(store.payloads, payloads);
    assert_eq!(store.timely_payloads, timely_payloads);
    assert_eq!(
        store.accepted_execution_payload_envelopes,
        accepted_payload_markers
    );
    assert_eq!(
        Arc::as_ptr(
            store
                .cached_execution_payload_envelope_by_root(block_root)
                .expect("accepted payload remains cached"),
        ),
        cached_payload_pointer
    );
    assert_eq!(store.tick(), tick);
    assert_eq!(store.justified_checkpoint(), justified_checkpoint);
    assert_eq!(store.finalized_checkpoint(), finalized_checkpoint);
    assert_eq!(store.last_finalized().block_root, last_finalized_root);
    assert_eq!(store.head().block_root, head_root);
}

#[expect(
    clippy::too_many_lines,
    reason = "one authentic lifecycle fixture covers all nonvalid report paths and replay keys"
)]
#[test]
fn execution_proof_completion_nonvalid_outcomes_keep_seen_and_reject_replays() {
    let keys = [proof_signing_key(), second_proof_signing_key()];
    let cases = [
        (
            "invalid callback report",
            Some(ExecutionProofVerificationOutcome::Invalid),
            ExecutionProofVerificationOutcome::Invalid,
            ExecutionProofCompletionOutcome::Reject,
        ),
        (
            "callback local fault",
            Some(ExecutionProofVerificationOutcome::LocalFault),
            ExecutionProofVerificationOutcome::LocalFault,
            ExecutionProofCompletionOutcome::LocalFault,
        ),
        (
            "pre-verification local fault",
            None,
            ExecutionProofVerificationOutcome::LocalFault,
            ExecutionProofCompletionOutcome::LocalFault,
        ),
    ];

    for (case, callback_outcome, expected_report, expected_completion) in cases {
        let (mut store, state, first_signed) =
            proof_preparation_fixture_with_keys(FAR_FUTURE_EPOCH, true, &keys);
        let same_root_signed =
            signed_execution_proof_for_test(&store, &state, &[0x42], 1, 1, &keys[1]);
        let changed_bytes_signed =
            signed_execution_proof_for_test(&store, &state, &[0x43], 1, 0, &keys[0]);

        let first = prepared_execution_proof_for_test(&store, &first_signed);
        let same_root = prepared_execution_proof_for_test(&store, &same_root_signed);
        let changed_bytes = prepared_execution_proof_for_test(&store, &changed_bytes_signed);
        let block_root = first.context_identity().beacon_block_root();
        let proof_type = first.signed_message().proof_type;
        let first_prover_key = (block_root, proof_type, first.validator_index());
        let same_root_prover_key = (
            same_root.context_identity().beacon_block_root(),
            same_root.signed_message().proof_type,
            same_root.validator_index(),
        );
        let changed_bytes_prover_key = (
            changed_bytes.context_identity().beacon_block_root(),
            changed_bytes.signed_message().proof_type,
            changed_bytes.validator_index(),
        );
        assert_eq!(first.context_identity(), same_root.context_identity());
        assert_eq!(first.context_identity(), changed_bytes.context_identity());
        assert_eq!(first.envelope_root(), same_root.envelope_root());
        assert_eq!(
            (first_prover_key.0, first_prover_key.1),
            (same_root_prover_key.0, same_root_prover_key.1)
        );
        assert_ne!(first_prover_key.2, same_root_prover_key.2);
        assert_ne!(
            first.signed_message().proof_data.as_bytes(),
            changed_bytes.signed_message().proof_data.as_bytes()
        );
        assert_ne!(first.envelope_root(), changed_bytes.envelope_root());
        assert_eq!(first_prover_key, changed_bytes_prover_key);

        let expected_input = first.execution_proof().clone();
        let input_data_pointer = first.execution_proof().proof_data.as_bytes().as_ptr();
        let expected_public_input = *first.context_identity().public_input();
        let unrelated_block_root = H256::repeat_byte(0xe5);
        assert_ne!(unrelated_block_root, block_root);
        // Synthetic unrelated bookkeeping must survive; this is not a valid completion.
        seed_execution_proof_bookkeeping(&mut store, unrelated_block_root);
        let bookkeeping_before = execution_proof_bookkeeping(&store);
        assert!(!bookkeeping_before.0.contains_key(&block_root));
        assert!(!bookkeeping_before.1.contains_key(&block_root));
        assert!(
            !bookkeeping_before
                .2
                .iter()
                .any(|(root, _, _)| *root == block_root)
        );
        assert!(store.execution_proof_context_is_applicable(block_root, &expected_public_input));

        let mut expected_after_admission = bookkeeping_before.clone();
        expected_after_admission
            .1
            .entry(block_root)
            .or_default()
            .insert(first.envelope_root());
        expected_after_admission.2.insert(first_prover_key);
        let unrelated_state = |store: &Store<Minimal, ContextStorage>| {
            (
                store.execution_proof_contexts.clone(),
                store.payloads.clone(),
                store.timely_payloads.clone(),
                store.accepted_execution_payload_envelopes.clone(),
                Arc::as_ptr(
                    store
                        .cached_execution_payload_envelope_by_root(block_root)
                        .expect("accepted payload remains cached"),
                ),
                store.tick(),
                store.justified_checkpoint(),
                store.finalized_checkpoint(),
                store.last_finalized().block_root,
                store.head().block_root,
                store.head_node_payload_status(),
            )
        };
        let unrelated_state_before = unrelated_state(&store);

        assert_eq!(
            execution_proof_bookkeeping(&store),
            bookkeeping_before,
            "{case}"
        );
        let admitted = match store.admit_execution_proof(first) {
            ExecutionProofAdmission::Admitted(admitted) => admitted,
            ExecutionProofAdmission::Declined(_) => {
                panic!("fresh authentic attempt should admit: {case}")
            }
        };
        assert_eq!(
            execution_proof_bookkeeping(&store),
            expected_after_admission,
            "admission consumes exactly both Seen keys: {case}"
        );
        assert_eq!(unrelated_state(&store), unrelated_state_before, "{case}");

        let completion = if let Some(report) = callback_outcome {
            let mut callback_calls = 0_usize;
            // The callback models a typed verifier report; this test does not run an engine.
            let completion = admitted.verify_with(|input| {
                callback_calls = callback_calls
                    .checked_add(1)
                    .expect("a FnOnce callback can run at most once");
                assert_eq!(input, expected_input, "{case}");
                assert_eq!(
                    input.proof_data.as_bytes().as_ptr(),
                    input_data_pointer,
                    "{case}"
                );
                report
            });
            assert_eq!(callback_calls, 1, "{case}");
            completion
        } else {
            admitted.into_local_fault()
        };
        assert_eq!(completion.verification_outcome(), expected_report, "{case}");
        assert_eq!(
            store.complete_execution_proof(completion),
            expected_completion,
            "{case}"
        );
        assert_eq!(
            execution_proof_bookkeeping(&store),
            expected_after_admission,
            "{case}"
        );
        assert_eq!(store.execution_proofs, bookkeeping_before.0, "{case}");
        assert!(!store.execution_proofs.contains_key(&block_root), "{case}");
        assert!(store.execution_proof_context_is_applicable(block_root, &expected_public_input));
        assert_eq!(unrelated_state(&store), unrelated_state_before, "{case}");

        assert_execution_proof_admission_declined_without_writes(
            &mut store,
            same_root,
            ExecutionProofAdmissionDecline::SeenRoot,
        );
        assert_eq!(
            execution_proof_bookkeeping(&store),
            expected_after_admission,
            "{case}"
        );
        assert_eq!(unrelated_state(&store), unrelated_state_before, "{case}");
        assert_execution_proof_admission_declined_without_writes(
            &mut store,
            changed_bytes,
            ExecutionProofAdmissionDecline::SeenProver,
        );
        assert_eq!(
            execution_proof_bookkeeping(&store),
            expected_after_admission,
            "{case}"
        );
        assert_eq!(store.execution_proofs, bookkeeping_before.0, "{case}");
        assert_eq!(unrelated_state(&store), unrelated_state_before, "{case}");
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "each ordered completion checks verdict, storage, Seen, and unrelated Store state"
)]
#[test]
fn execution_proof_completion_overlapping_verdicts_preserve_first_valid_in_both_orders() {
    let cases = [
        (
            "valid/valid",
            [
                ExecutionProofVerificationOutcome::Valid,
                ExecutionProofVerificationOutcome::Valid,
            ],
            [
                ExecutionProofCompletionOutcome::Accept,
                ExecutionProofCompletionOutcome::Accept,
            ],
        ),
        (
            "valid/invalid",
            [
                ExecutionProofVerificationOutcome::Valid,
                ExecutionProofVerificationOutcome::Invalid,
            ],
            [
                ExecutionProofCompletionOutcome::Accept,
                ExecutionProofCompletionOutcome::Reject,
            ],
        ),
        (
            "invalid/invalid",
            [
                ExecutionProofVerificationOutcome::Invalid,
                ExecutionProofVerificationOutcome::Invalid,
            ],
            [
                ExecutionProofCompletionOutcome::Reject,
                ExecutionProofCompletionOutcome::Reject,
            ],
        ),
        (
            "valid/local-fault",
            [
                ExecutionProofVerificationOutcome::Valid,
                ExecutionProofVerificationOutcome::LocalFault,
            ],
            [
                ExecutionProofCompletionOutcome::Accept,
                ExecutionProofCompletionOutcome::LocalFault,
            ],
        ),
    ];

    for (case, verdicts, expected_outcomes) in cases {
        for order in [[0_usize, 1], [1, 0]] {
            let keys = [proof_signing_key(), second_proof_signing_key()];
            // Both keys are registered before the fixture constructs its state and block root.
            let (mut store, state, first_signed) =
                proof_preparation_fixture_with_keys(FAR_FUTURE_EPOCH, true, &keys);
            let second_signed =
                signed_execution_proof_for_test(&store, &state, &[0x43], 1, 1, &keys[1]);
            let first = prepared_execution_proof_for_test(&store, &first_signed);
            let second = prepared_execution_proof_for_test(&store, &second_signed);

            let block_root = first.context_identity().beacon_block_root();
            let proof_type = first.signed_message().proof_type;
            let envelope_roots = [first.envelope_root(), second.envelope_root()];
            let prover_keys = [
                (block_root, proof_type, first.validator_index()),
                (block_root, proof_type, second.validator_index()),
            ];
            let expected_inputs = [
                first.execution_proof().clone(),
                second.execution_proof().clone(),
            ];
            let expected_envelopes = [
                first.signed_message().clone(),
                second.signed_message().clone(),
            ];
            let input_data_pointers = [
                first.execution_proof().proof_data.as_bytes().as_ptr(),
                second.execution_proof().proof_data.as_bytes().as_ptr(),
            ];
            let message_data_pointers = [
                first.signed_message().proof_data.as_bytes().as_ptr(),
                second.signed_message().proof_data.as_bytes().as_ptr(),
            ];
            assert_eq!(second.context_identity().beacon_block_root(), block_root);
            assert_eq!(first.signed_message().proof_type, 1);
            assert_eq!(second.signed_message().proof_type, proof_type);
            assert_ne!(envelope_roots[0], envelope_roots[1], "{case}");
            assert_ne!(prover_keys[0].2, prover_keys[1].2, "{case}");
            assert_ne!(
                expected_envelopes[0].proof_data.as_bytes(),
                expected_envelopes[1].proof_data.as_bytes(),
                "{case}"
            );

            let unrelated_block_root = H256::repeat_byte(0xe5);
            assert_ne!(unrelated_block_root, block_root, "{case}");
            // This synthetic unrelated entry makes preservation observable; it is not completion evidence.
            seed_execution_proof_bookkeeping(&mut store, unrelated_block_root);
            let bookkeeping_before = execution_proof_bookkeeping(&store);
            assert!(!bookkeeping_before.0.contains_key(&block_root), "{case}");
            assert!(!bookkeeping_before.1.contains_key(&block_root), "{case}");
            assert!(
                !bookkeeping_before
                    .2
                    .iter()
                    .any(|(root, _, _)| *root == block_root),
                "{case}"
            );
            let sentinel_arc = Arc::clone(
                bookkeeping_before.0[&unrelated_block_root]
                    .get(&2)
                    .expect("synthetic sentinel stores a bare proof"),
            );

            let unrelated_state = |store: &Store<Minimal, ContextStorage>| {
                (
                    store.execution_proof_contexts.clone(),
                    store.payloads.clone(),
                    store.timely_payloads.clone(),
                    store.accepted_execution_payload_envelopes.clone(),
                    Arc::as_ptr(
                        store
                            .cached_execution_payload_envelope_by_root(block_root)
                            .expect("accepted payload remains cached"),
                    ),
                    store.tick(),
                    store.justified_checkpoint(),
                    store.finalized_checkpoint(),
                    store.last_finalized().block_root,
                    store.head().block_root,
                    store.head_node_payload_status(),
                )
            };

            let unrelated_state_before = unrelated_state(&store);
            let mut expected_after_first_admission = bookkeeping_before.clone();
            expected_after_first_admission
                .1
                .entry(block_root)
                .or_default()
                .insert(envelope_roots[0]);
            expected_after_first_admission.2.insert(prover_keys[0]);
            let mut expected_after_admission = expected_after_first_admission.clone();
            expected_after_admission
                .1
                .entry(block_root)
                .or_default()
                .insert(envelope_roots[1]);
            expected_after_admission.2.insert(prover_keys[1]);

            let admitted_first = match store.admit_execution_proof(first) {
                ExecutionProofAdmission::Admitted(admitted) => admitted,
                ExecutionProofAdmission::Declined(reason) => {
                    panic!("first distinct attempt should admit ({case}, {order:?}): {reason:?}")
                }
            };
            assert_eq!(
                execution_proof_bookkeeping(&store),
                expected_after_first_admission,
                "first admission consumes only its own Seen keys ({case}, {order:?})"
            );
            assert_eq!(unrelated_state(&store), unrelated_state_before, "{case}");
            let admitted_second = match store.admit_execution_proof(second) {
                ExecutionProofAdmission::Admitted(admitted) => admitted,
                ExecutionProofAdmission::Declined(reason) => {
                    panic!(
                        "overlapping distinct attempt should admit ({case}, {order:?}): {reason:?}"
                    )
                }
            };
            let mut admitted = [Some(admitted_first), Some(admitted_second)];
            assert_eq!(
                execution_proof_bookkeeping(&store),
                expected_after_admission,
                "both distinct attempts consume only their own Seen keys ({case}, {order:?})"
            );
            assert!(!store.execution_proofs.contains_key(&block_root), "{case}");
            assert_eq!(unrelated_state(&store), unrelated_state_before, "{case}");

            let mut expected_after_completion = expected_after_admission.clone();
            let mut first_valid_index = None;
            let mut first_valid_arc = None;
            for (completion_position, attempt_index) in order.into_iter().enumerate() {
                let completion = admitted[attempt_index]
                    .take()
                    .expect("each admitted attempt completes exactly once")
                    .verify_with(|input| {
                        assert_eq!(
                            input, expected_inputs[attempt_index],
                            "exact admitted input ({case}, {order:?})"
                        );
                        assert_eq!(
                            input.proof_data.as_bytes().as_ptr(),
                            input_data_pointers[attempt_index],
                            "input retains its prepared proof bytes ({case}, {order:?})"
                        );
                        verdicts[attempt_index]
                    });
                assert_eq!(
                    completion.verification_outcome(),
                    verdicts[attempt_index],
                    "typed callback report ({case}, {order:?})"
                );
                assert_eq!(
                    store.complete_execution_proof(completion),
                    expected_outcomes[attempt_index],
                    "each applicable verdict is independent of occupancy ({case}, {order:?})"
                );

                if verdicts[attempt_index] == ExecutionProofVerificationOutcome::Valid
                    && first_valid_index.is_none()
                {
                    first_valid_index = Some(attempt_index);
                    expected_after_completion
                        .0
                        .entry(block_root)
                        .or_default()
                        .insert(
                            proof_type,
                            Arc::new(expected_envelopes[attempt_index].clone()),
                        );
                }
                assert_eq!(
                    execution_proof_bookkeeping(&store),
                    expected_after_completion,
                    "exact verified map and permanent Seen state ({case}, {order:?}, completion {completion_position})"
                );
                assert_eq!(
                    store.execution_proof_roots, expected_after_admission.1,
                    "both Seen roots remain after completion ({case}, {order:?})"
                );
                assert_eq!(
                    store.execution_proof_provers, expected_after_admission.2,
                    "both Seen provers remain after completion ({case}, {order:?})"
                );

                if let Some(first_valid_index) = first_valid_index {
                    let stored = store.execution_proofs[&block_root]
                        .get(&proof_type)
                        .expect("the first valid completion stores its bare envelope");
                    if first_valid_arc.is_none() {
                        first_valid_arc = Some(Arc::clone(stored));
                    }
                    assert!(
                        Arc::ptr_eq(
                            first_valid_arc.as_ref().expect("captured first Arc"),
                            stored
                        ),
                        "later completions preserve the stored Arc ({case}, {order:?})"
                    );
                    assert_eq!(stored.beacon_block_root, block_root, "{case}");
                    assert_eq!(stored.proof_type, proof_type, "{case}");
                    assert_eq!(
                        stored.proof_data.as_bytes(),
                        expected_envelopes[first_valid_index].proof_data.as_bytes(),
                        "first valid bytes are never overwritten ({case}, {order:?})"
                    );
                    assert_eq!(
                        stored.proof_data.as_bytes().as_ptr(),
                        message_data_pointers[first_valid_index],
                        "stored bare message retains its prepared byte allocation ({case}, {order:?})"
                    );
                } else {
                    assert!(
                        !store.execution_proofs.contains_key(&block_root),
                        "no invalid/local-fault completion creates a target bucket ({case}, {order:?})"
                    );
                }
                let current_sentinel = store.execution_proofs[&unrelated_block_root]
                    .get(&2)
                    .expect("unrelated sentinel remains present");
                assert!(
                    Arc::ptr_eq(&sentinel_arc, current_sentinel),
                    "completion does not replace the unrelated sentinel ({case}, {order:?})"
                );
                assert_eq!(
                    unrelated_state(&store),
                    unrelated_state_before,
                    "completion preserves context, payload/cache, consensus, and EL observables ({case}, {order:?})"
                );
            }
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the authentic post-storage decline checks both fresh keys and preserved first storage"
)]
#[test]
fn execution_proof_admission_after_completion_declines_fresh_candidate_without_seen_writes() {
    let keys = [proof_signing_key(), second_proof_signing_key()];
    let (mut store, state, first_signed) =
        proof_preparation_fixture_with_keys(FAR_FUTURE_EPOCH, true, &keys);
    let second_signed = signed_execution_proof_for_test(&store, &state, &[0x43], 1, 1, &keys[1]);
    let first = prepared_execution_proof_for_test(&store, &first_signed);
    let second = prepared_execution_proof_for_test(&store, &second_signed);

    let block_root = first.context_identity().beacon_block_root();
    let proof_type = first.signed_message().proof_type;
    let first_root = first.envelope_root();
    let second_root = second.envelope_root();
    let first_prover = (block_root, proof_type, first.validator_index());
    let second_prover = (block_root, proof_type, second.validator_index());
    let expected_input = first.execution_proof().clone();
    let input_data_pointer = first.execution_proof().proof_data.as_bytes().as_ptr();
    let expected_message = first.signed_message().clone();
    let message_data_pointer = first.signed_message().proof_data.as_bytes().as_ptr();
    assert_eq!(second.context_identity().beacon_block_root(), block_root);
    assert_eq!(first.signed_message().proof_type, 1);
    assert_eq!(second.signed_message().proof_type, proof_type);
    assert_ne!(first_root, second_root);
    assert_ne!(first_prover.2, second_prover.2);
    assert_ne!(
        expected_message.proof_data.as_bytes(),
        second.signed_message().proof_data.as_bytes()
    );

    let unrelated_block_root = H256::repeat_byte(0xe5);
    assert_ne!(unrelated_block_root, block_root);
    // This synthetic unrelated entry makes preservation observable; it is not completion evidence.
    seed_execution_proof_bookkeeping(&mut store, unrelated_block_root);
    let bookkeeping_before = execution_proof_bookkeeping(&store);
    assert!(!bookkeeping_before.0.contains_key(&block_root));
    assert!(!bookkeeping_before.1.contains_key(&block_root));
    assert!(!bookkeeping_before.2.contains(&first_prover));
    assert!(!bookkeeping_before.2.contains(&second_prover));
    assert!(
        !bookkeeping_before
            .1
            .get(&block_root)
            .is_some_and(|roots| roots.contains(&first_root))
    );
    assert!(
        !bookkeeping_before
            .1
            .get(&block_root)
            .is_some_and(|roots| roots.contains(&second_root))
    );
    let sentinel_arc = Arc::clone(
        bookkeeping_before.0[&unrelated_block_root]
            .get(&2)
            .expect("synthetic sentinel stores a bare proof"),
    );

    let unrelated_state = |store: &Store<Minimal, ContextStorage>| {
        (
            store.execution_proof_contexts.clone(),
            store.payloads.clone(),
            store.timely_payloads.clone(),
            store.accepted_execution_payload_envelopes.clone(),
            Arc::as_ptr(
                store
                    .cached_execution_payload_envelope_by_root(block_root)
                    .expect("accepted payload remains cached"),
            ),
            store.tick(),
            store.justified_checkpoint(),
            store.finalized_checkpoint(),
            store.last_finalized().block_root,
            store.head().block_root,
            store.head_node_payload_status(),
        )
    };
    let unrelated_state_before = unrelated_state(&store);

    let mut expected_after_admission = bookkeeping_before;
    expected_after_admission
        .1
        .entry(block_root)
        .or_default()
        .insert(first_root);
    expected_after_admission.2.insert(first_prover);
    let admitted = match store.admit_execution_proof(first) {
        ExecutionProofAdmission::Admitted(admitted) => admitted,
        ExecutionProofAdmission::Declined(reason) => {
            panic!("first fresh candidate should admit: {reason:?}")
        }
    };
    assert_eq!(
        execution_proof_bookkeeping(&store),
        expected_after_admission,
        "only the first candidate's Seen keys are inserted"
    );
    assert!(!store.execution_proof_roots[&block_root].contains(&second_root));
    assert!(!store.execution_proof_provers.contains(&second_prover));

    let completion = admitted.verify_with(|input| {
        assert_eq!(input, expected_input, "exact admitted input");
        assert_eq!(input.proof_data.as_bytes().as_ptr(), input_data_pointer);
        ExecutionProofVerificationOutcome::Valid
    });
    let mut expected_after_completion = expected_after_admission.clone();
    expected_after_completion
        .0
        .entry(block_root)
        .or_default()
        .insert(proof_type, Arc::new(expected_message.clone()));
    assert_eq!(
        store.complete_execution_proof(completion),
        ExecutionProofCompletionOutcome::Accept
    );
    assert_eq!(
        execution_proof_bookkeeping(&store),
        expected_after_completion,
        "first valid completion stores only the prepared bare message"
    );
    let first_stored_arc = Arc::clone(
        store.execution_proofs[&block_root]
            .get(&proof_type)
            .expect("first valid proof is stored"),
    );
    assert_eq!(first_stored_arc.beacon_block_root, block_root);
    assert_eq!(first_stored_arc.proof_type, proof_type);
    assert_eq!(
        first_stored_arc.proof_data.as_bytes(),
        expected_message.proof_data.as_bytes()
    );
    assert_eq!(
        first_stored_arc.proof_data.as_bytes().as_ptr(),
        message_data_pointer
    );
    assert!(!store.execution_proof_roots[&block_root].contains(&second_root));
    assert!(!store.execution_proof_provers.contains(&second_prover));
    assert!(Arc::ptr_eq(
        &sentinel_arc,
        store.execution_proofs[&unrelated_block_root]
            .get(&2)
            .expect("unrelated sentinel remains present")
    ));
    assert_eq!(unrelated_state(&store), unrelated_state_before);

    assert!(matches!(
        store.admit_execution_proof(second),
        ExecutionProofAdmission::Declined(ExecutionProofAdmissionDecline::AlreadyVerified)
    ));
    assert_eq!(
        execution_proof_bookkeeping(&store),
        expected_after_completion,
        "post-storage decline inserts neither of the losing candidate's fresh keys"
    );
    assert!(!store.execution_proof_roots[&block_root].contains(&second_root));
    assert!(!store.execution_proof_provers.contains(&second_prover));
    let stored_after_decline = store.execution_proofs[&block_root]
        .get(&proof_type)
        .expect("declined candidate cannot replace first storage");
    assert!(Arc::ptr_eq(&first_stored_arc, stored_after_decline));
    assert_eq!(stored_after_decline.beacon_block_root, block_root);
    assert_eq!(stored_after_decline.proof_type, proof_type);
    assert_eq!(
        stored_after_decline.proof_data.as_bytes(),
        expected_message.proof_data.as_bytes()
    );
    assert!(Arc::ptr_eq(
        &sentinel_arc,
        store.execution_proofs[&unrelated_block_root]
            .get(&2)
            .expect("unrelated sentinel remains present")
    ));
    assert_eq!(unrelated_state(&store), unrelated_state_before);
}

#[expect(
    clippy::too_many_lines,
    reason = "the authentic admissions and snapshot ownership assertions form one regression"
)]
#[test]
fn execution_proof_completion_preserves_arc_across_store_snapshot_mutation() {
    let (mut store, state, signed_type_1) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let key = proof_signing_key();
    let signed_type_2 = signed_execution_proof_for_test(&store, &state, &[0x43], 2, 0, &key);
    let prepared_type_1 = prepared_execution_proof_for_test(&store, &signed_type_1);
    let prepared_type_2 = prepared_execution_proof_for_test(&store, &signed_type_2);
    let block_root = prepared_type_1.context_identity().beacon_block_root();
    let type_1_root = prepared_type_1.envelope_root();
    let type_2_root = prepared_type_2.envelope_root();
    let type_1_input = prepared_type_1.execution_proof().clone();
    let type_2_input = prepared_type_2.execution_proof().clone();
    let type_1_message_pointer = prepared_type_1
        .signed_message()
        .proof_data
        .as_bytes()
        .as_ptr();
    let type_2_message_pointer = prepared_type_2
        .signed_message()
        .proof_data
        .as_bytes()
        .as_ptr();
    let type_1_bytes = prepared_type_1
        .signed_message()
        .proof_data
        .as_bytes()
        .to_vec();
    let type_2_bytes = prepared_type_2
        .signed_message()
        .proof_data
        .as_bytes()
        .to_vec();
    assert_eq!(prepared_type_1.signed_message().proof_type, 1);
    assert_eq!(prepared_type_2.signed_message().proof_type, 2);
    assert_eq!(
        prepared_type_2.context_identity().beacon_block_root(),
        block_root
    );
    assert_ne!(type_1_root, type_2_root);
    assert!(!type_1_bytes.is_empty() && !type_2_bytes.is_empty());
    assert!(store.execution_proofs.is_empty());

    let admitted_type_1 = match store.admit_execution_proof(prepared_type_1) {
        ExecutionProofAdmission::Admitted(admitted) => admitted,
        ExecutionProofAdmission::Declined(_) => panic!("fresh type-1 proof should admit"),
    };
    let completion_type_1 = admitted_type_1.verify_with(|input| {
        assert_eq!(input, type_1_input);
        ExecutionProofVerificationOutcome::Valid
    });
    assert_eq!(
        store.complete_execution_proof(completion_type_1),
        ExecutionProofCompletionOutcome::Accept
    );

    let snapshot = store.clone();
    let snapshot_bookkeeping = execution_proof_bookkeeping(&snapshot);
    let snapshot_type_1 = Arc::clone(
        snapshot.execution_proofs[&block_root]
            .get(&1)
            .expect("snapshot retains the first valid type-1 envelope"),
    );
    let type_1_arc_pointer = Arc::as_ptr(&snapshot_type_1);
    assert!(!snapshot.execution_proofs[&block_root].contains_key(&2));
    assert_eq!(
        snapshot_type_1.proof_data.as_bytes().as_ptr(),
        type_1_message_pointer
    );

    let bookkeeping_before_type_2 = execution_proof_bookkeeping(&store);
    let mut expected_roots = bookkeeping_before_type_2.1.clone();
    expected_roots
        .entry(block_root)
        .or_default()
        .insert(type_2_root);
    let mut expected_provers = bookkeeping_before_type_2.2;
    expected_provers.insert((block_root, 2, 0));
    let proof_contexts = store.execution_proof_contexts.clone();
    let payloads = store.payloads.clone();
    let tick = store.tick();
    let justified_checkpoint = store.justified_checkpoint();
    let finalized_checkpoint = store.finalized_checkpoint();
    let last_finalized_root = store.last_finalized().block_root;
    let head_root = store.head().block_root;

    let admitted_type_2 = match store.admit_execution_proof(prepared_type_2) {
        ExecutionProofAdmission::Admitted(admitted) => admitted,
        ExecutionProofAdmission::Declined(_) => panic!("fresh type-2 proof should admit"),
    };
    let completion_type_2 = admitted_type_2.verify_with(|input| {
        assert_eq!(input, type_2_input);
        ExecutionProofVerificationOutcome::Valid
    });
    assert_eq!(
        store.complete_execution_proof(completion_type_2),
        ExecutionProofCompletionOutcome::Accept
    );

    assert_execution_proof_bookkeeping_unchanged(&snapshot, &snapshot_bookkeeping);
    assert_eq!(snapshot.execution_proofs[&block_root].len(), 1);
    assert!(!snapshot.execution_proofs[&block_root].contains_key(&2));
    let snapshot_type_1_stored = snapshot.execution_proofs[&block_root]
        .get(&1)
        .expect("old snapshot still stores type 1 only");
    assert!(Arc::ptr_eq(&snapshot_type_1, snapshot_type_1_stored));
    assert_eq!(
        snapshot_type_1_stored.proof_data.as_bytes().as_ptr(),
        type_1_message_pointer
    );
    assert_eq!(store.execution_proofs.len(), 1);
    assert_eq!(store.execution_proofs[&block_root].len(), 2);
    assert_eq!(store.execution_proof_roots, expected_roots);
    assert_eq!(store.execution_proof_provers, expected_provers);
    assert_eq!(store.execution_proof_contexts, proof_contexts);
    assert_eq!(store.payloads, payloads);
    assert_eq!(store.tick(), tick);
    assert_eq!(store.justified_checkpoint(), justified_checkpoint);
    assert_eq!(store.finalized_checkpoint(), finalized_checkpoint);
    assert_eq!(store.last_finalized().block_root, last_finalized_root);
    assert_eq!(store.head().block_root, head_root);

    let current_type_1 = store.execution_proofs[&block_root]
        .get(&1)
        .expect("current Store preserves the first valid type-1 envelope");
    let current_type_2 = store.execution_proofs[&block_root]
        .get(&2)
        .expect("current Store adds the valid type-2 envelope");
    assert!(Arc::ptr_eq(&snapshot_type_1, current_type_1));
    assert_eq!(Arc::as_ptr(current_type_1), type_1_arc_pointer);
    assert_eq!(current_type_1.beacon_block_root, block_root);
    assert_eq!(current_type_1.proof_type, 1);
    assert_eq!(
        current_type_1.proof_data.as_bytes(),
        type_1_bytes.as_slice()
    );
    assert_eq!(
        current_type_1.proof_data.as_bytes().as_ptr(),
        type_1_message_pointer
    );
    assert_eq!(current_type_2.beacon_block_root, block_root);
    assert_eq!(current_type_2.proof_type, 2);
    assert_eq!(
        current_type_2.proof_data.as_bytes(),
        type_2_bytes.as_slice()
    );
    assert_eq!(
        current_type_2.proof_data.as_bytes().as_ptr(),
        type_2_message_pointer
    );
}

fn report_admitted_execution_proof_for_test(
    admitted: AdmittedExecutionProof,
    expected_input: &ExecutionProof,
    input_data_pointer: *const u8,
    verdict: ExecutionProofVerificationOutcome,
) -> ExecutionProofCompletion {
    let mut callback_calls = 0_usize;
    // Model the trusted callback report; this helper never runs an engine.
    let completion = admitted.verify_with(|input| {
        callback_calls = callback_calls
            .checked_add(1)
            .expect("a FnOnce callback can run at most once");
        assert_eq!(&input, expected_input);
        assert_eq!(input.proof_data.as_bytes().as_ptr(), input_data_pointer);
        verdict
    });
    assert_eq!(callback_calls, 1);
    assert_eq!(completion.verification_outcome(), verdict);
    completion
}

#[expect(
    clippy::too_many_lines,
    reason = "each isolated full-Q mutation proves applicability precedes all three verdicts"
)]
#[test]
fn execution_proof_completion_discards_each_independent_q_change_before_verdict() {
    let verdicts = [
        ExecutionProofVerificationOutcome::Valid,
        ExecutionProofVerificationOutcome::Invalid,
        ExecutionProofVerificationOutcome::LocalFault,
    ];

    for field in [
        "new_payload_request_root",
        "successful_validation",
        "chain_id",
        "schema_id",
    ] {
        for verdict in verdicts {
            let (mut store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
            let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
            let block_root = prepared.context_identity().beacon_block_root();
            let proof_type = prepared.signed_message().proof_type;
            let validator_index = prepared.validator_index();
            let envelope_root = prepared.envelope_root();
            let prepared_context = *prepared.context_identity();
            let prepared_input = *prepared_context.public_input();
            let expected_proof = prepared.execution_proof().clone();
            let expected_message = prepared.signed_message().clone();
            let input_data_pointer = prepared.execution_proof().proof_data.as_bytes().as_ptr();
            let unrelated_block_root = H256::repeat_byte(0xe5);
            assert_ne!(unrelated_block_root, block_root, "{field}: {verdict:?}");
            // This synthetic sentinel makes map preservation observable; it is not authentic completion evidence.
            seed_execution_proof_bookkeeping(&mut store, unrelated_block_root);
            let bookkeeping_before = execution_proof_bookkeeping(&store);
            assert!(bookkeeping_before.0.contains_key(&unrelated_block_root));
            assert!(bookkeeping_before.1.contains_key(&unrelated_block_root));
            assert!(
                bookkeeping_before
                    .2
                    .iter()
                    .any(|(root, _, _)| *root == unrelated_block_root)
            );
            assert!(!bookkeeping_before.0.contains_key(&block_root));
            assert!(!bookkeeping_before.1.contains_key(&block_root));
            assert!(
                !bookkeeping_before
                    .2
                    .iter()
                    .any(|(root, _, _)| *root == block_root)
            );
            let sentinel_arc = Arc::clone(
                bookkeeping_before.0[&unrelated_block_root]
                    .get(&2)
                    .expect("synthetic sentinel contains a bare proof"),
            );
            assert!(store.payloads.contains(&block_root));
            assert_eq!(
                store.execution_proof_contexts.get(&block_root),
                Some(&prepared_input)
            );
            assert!(store.execution_proof_context_is_applicable(block_root, &prepared_input));

            let mut expected_after_admission = bookkeeping_before.clone();
            expected_after_admission
                .1
                .entry(block_root)
                .or_default()
                .insert(envelope_root);
            expected_after_admission
                .2
                .insert((block_root, proof_type, validator_index));
            let admitted = match store.admit_execution_proof(prepared) {
                ExecutionProofAdmission::Admitted(admitted) => admitted,
                ExecutionProofAdmission::Declined(reason) => {
                    panic!("fresh authentic proof should admit ({field}, {verdict:?}): {reason:?}")
                }
            };
            assert_eq!(
                execution_proof_bookkeeping(&store),
                expected_after_admission,
                "admission adds only the target's permanent Seen keys ({field}, {verdict:?})"
            );
            let completion = report_admitted_execution_proof_for_test(
                admitted,
                &expected_proof,
                input_data_pointer,
                verdict,
            );
            assert_eq!(
                completion.envelope(),
                &expected_message,
                "{field}: {verdict:?}"
            );
            assert_eq!(
                completion.context_identity(),
                &prepared_context,
                "completion retains the historical identity ({field}, {verdict:?})"
            );
            assert_eq!(
                completion.context_identity().public_input(),
                &prepared_input
            );

            let mismatch = match field {
                "new_payload_request_root" => PublicInput {
                    new_payload_request_root: H256::repeat_byte(0x99),
                    ..prepared_input
                },
                "successful_validation" => PublicInput {
                    successful_validation: !prepared_input.successful_validation,
                    ..prepared_input
                },
                "chain_id" => PublicInput {
                    chain_id: prepared_input.chain_id ^ 1,
                    ..prepared_input
                },
                "schema_id" => PublicInput {
                    schema_id: prepared_input.schema_id ^ 1,
                    ..prepared_input
                },
                _ => unreachable!(),
            };
            let changed_fields = (
                mismatch.new_payload_request_root != prepared_input.new_payload_request_root,
                mismatch.successful_validation != prepared_input.successful_validation,
                mismatch.chain_id != prepared_input.chain_id,
                mismatch.schema_id != prepared_input.schema_id,
            );
            let only_expected_field_changed = match field {
                "new_payload_request_root" => (true, false, false, false),
                "successful_validation" => (false, true, false, false),
                "chain_id" => (false, false, true, false),
                "schema_id" => (false, false, false, true),
                _ => unreachable!(),
            };
            assert_eq!(changed_fields, only_expected_field_changed, "{field}");
            store.execution_proof_contexts.insert(block_root, mismatch);
            assert!(store.payloads.contains(&block_root), "{field}: {verdict:?}");
            assert_eq!(
                store.execution_proof_contexts.get(&block_root),
                Some(&mismatch),
                "the intended Q mutation is present before completion ({field}, {verdict:?})"
            );
            assert!(!store.execution_proof_context_is_applicable(block_root, &prepared_input));
            assert!(
                store.last_finalized().block_root == block_root
                    || store.unfinalized_locations.contains_key(&block_root)
            );
            let contexts_after_change = store.execution_proof_contexts.clone();
            let other_state_after_change = (
                store.payloads.clone(),
                store.timely_payloads.clone(),
                store.accepted_execution_payload_envelopes.clone(),
                store
                    .cached_execution_payload_envelope_by_root(block_root)
                    .map(Arc::as_ptr),
                store.tick(),
                store.justified_checkpoint(),
                store.finalized_checkpoint(),
                store.last_finalized().block_root,
                store.head().block_root,
                store.head_node_payload_status(),
                store.is_payload_invalid(block_root),
            );

            assert_eq!(
                store.complete_execution_proof(completion),
                ExecutionProofCompletionOutcome::Discarded(
                    ExecutionProofDiscard::ContextInapplicable
                ),
                "applicability precedes {verdict:?} ({field})"
            );
            assert!(
                store.last_finalized().block_root == block_root
                    || store.unfinalized_locations.contains_key(&block_root),
                "discard must not retire the target ({field}, {verdict:?})"
            );
            assert_eq!(
                execution_proof_bookkeeping(&store),
                expected_after_admission,
                "discard preserves every proof map and both permanent Seen keys ({field}, {verdict:?})"
            );
            assert!(!store.execution_proofs.contains_key(&block_root));
            assert!(Arc::ptr_eq(
                &sentinel_arc,
                store.execution_proofs[&unrelated_block_root]
                    .get(&2)
                    .expect("unrelated sentinel remains present")
            ));
            assert_eq!(store.execution_proof_contexts, contexts_after_change);
            assert_eq!(
                store.execution_proof_contexts.get(&block_root),
                Some(&mismatch),
                "the changed Q remains present ({field}, {verdict:?})"
            );
            assert!(store.payloads.contains(&block_root));
            assert_eq!(
                (
                    store.payloads.clone(),
                    store.timely_payloads.clone(),
                    store.accepted_execution_payload_envelopes.clone(),
                    store
                        .cached_execution_payload_envelope_by_root(block_root)
                        .map(Arc::as_ptr),
                    store.tick(),
                    store.justified_checkpoint(),
                    store.finalized_checkpoint(),
                    store.last_finalized().block_root,
                    store.head().block_root,
                    store.head_node_payload_status(),
                    store.is_payload_invalid(block_root),
                ),
                other_state_after_change,
                "completion preserves unrelated Store and EL observables ({field}, {verdict:?})"
            );
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the marker-only and Q-only cases preserve distinct authority through every report"
)]
#[test]
fn execution_proof_completion_discards_missing_marker_or_q_independently() {
    let verdicts = [
        ExecutionProofVerificationOutcome::Valid,
        ExecutionProofVerificationOutcome::Invalid,
        ExecutionProofVerificationOutcome::LocalFault,
    ];

    for missing in ["accepted-payload marker", "Q"] {
        for verdict in verdicts {
            let (mut store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
            let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
            let block_root = prepared.context_identity().beacon_block_root();
            let proof_type = prepared.signed_message().proof_type;
            let validator_index = prepared.validator_index();
            let envelope_root = prepared.envelope_root();
            let prepared_context = *prepared.context_identity();
            let prepared_input = *prepared_context.public_input();
            let expected_proof = prepared.execution_proof().clone();
            let input_data_pointer = prepared.execution_proof().proof_data.as_bytes().as_ptr();
            let unrelated_block_root = H256::repeat_byte(0xe5);
            assert_ne!(unrelated_block_root, block_root, "{missing}: {verdict:?}");
            // This synthetic sentinel makes map preservation observable; it is not authentic completion evidence.
            seed_execution_proof_bookkeeping(&mut store, unrelated_block_root);
            let bookkeeping_before = execution_proof_bookkeeping(&store);
            assert!(bookkeeping_before.0.contains_key(&unrelated_block_root));
            assert!(bookkeeping_before.1.contains_key(&unrelated_block_root));
            assert!(
                bookkeeping_before
                    .2
                    .iter()
                    .any(|(root, _, _)| *root == unrelated_block_root)
            );
            assert!(!bookkeeping_before.0.contains_key(&block_root));
            assert!(!bookkeeping_before.1.contains_key(&block_root));
            assert!(
                !bookkeeping_before
                    .2
                    .iter()
                    .any(|(root, _, _)| *root == block_root)
            );
            let sentinel_arc = Arc::clone(
                bookkeeping_before.0[&unrelated_block_root]
                    .get(&2)
                    .expect("synthetic sentinel contains a bare proof"),
            );
            assert!(store.payloads.contains(&block_root));
            assert_eq!(
                store.execution_proof_contexts.get(&block_root),
                Some(&prepared_input)
            );

            let mut expected_after_admission = bookkeeping_before.clone();
            expected_after_admission
                .1
                .entry(block_root)
                .or_default()
                .insert(envelope_root);
            expected_after_admission
                .2
                .insert((block_root, proof_type, validator_index));
            let admitted = match store.admit_execution_proof(prepared) {
                ExecutionProofAdmission::Admitted(admitted) => admitted,
                ExecutionProofAdmission::Declined(reason) => {
                    panic!(
                        "fresh authentic proof should admit ({missing}, {verdict:?}): {reason:?}"
                    )
                }
            };
            assert_eq!(
                execution_proof_bookkeeping(&store),
                expected_after_admission,
                "admission consumes exactly both target Seen keys ({missing}, {verdict:?})"
            );
            let completion = report_admitted_execution_proof_for_test(
                admitted,
                &expected_proof,
                input_data_pointer,
                verdict,
            );
            assert_eq!(completion.context_identity(), &prepared_context);
            assert_eq!(
                completion.context_identity().public_input(),
                &prepared_input
            );

            match missing {
                "accepted-payload marker" => {
                    store.payloads.remove(&block_root);
                    assert!(!store.payloads.contains(&block_root));
                    assert_eq!(
                        store.execution_proof_contexts.get(&block_root),
                        Some(&prepared_input),
                        "Q remains present when only its authority marker is removed"
                    );
                }
                "Q" => {
                    assert_eq!(
                        store.execution_proof_contexts.remove(&block_root),
                        Some(prepared_input)
                    );
                    assert!(store.payloads.contains(&block_root));
                    assert!(!store.execution_proof_contexts.contains_key(&block_root));
                }
                _ => unreachable!(),
            }
            assert!(!store.execution_proof_context_is_applicable(block_root, &prepared_input));
            assert!(
                store.last_finalized().block_root == block_root
                    || store.unfinalized_locations.contains_key(&block_root)
            );
            let contexts_after_change = store.execution_proof_contexts.clone();
            let markers_after_change = store.payloads.clone();
            let other_state_after_change = (
                store.timely_payloads.clone(),
                store.accepted_execution_payload_envelopes.clone(),
                store
                    .cached_execution_payload_envelope_by_root(block_root)
                    .map(Arc::as_ptr),
                store.tick(),
                store.justified_checkpoint(),
                store.finalized_checkpoint(),
                store.last_finalized().block_root,
                store.head().block_root,
                store.head_node_payload_status(),
                store.is_payload_invalid(block_root),
            );

            assert_eq!(
                store.complete_execution_proof(completion),
                ExecutionProofCompletionOutcome::Discarded(
                    ExecutionProofDiscard::ContextInapplicable
                ),
                "missing authority precedes {verdict:?} ({missing})"
            );
            assert!(
                store.last_finalized().block_root == block_root
                    || store.unfinalized_locations.contains_key(&block_root),
                "discard must not retire the target ({missing}, {verdict:?})"
            );
            assert_eq!(
                execution_proof_bookkeeping(&store),
                expected_after_admission,
                "discard preserves all maps and permanent Seen ({missing}, {verdict:?})"
            );
            assert!(!store.execution_proofs.contains_key(&block_root));
            assert!(Arc::ptr_eq(
                &sentinel_arc,
                store.execution_proofs[&unrelated_block_root]
                    .get(&2)
                    .expect("unrelated sentinel remains present")
            ));
            assert_eq!(store.execution_proof_contexts, contexts_after_change);
            assert_eq!(store.payloads, markers_after_change);
            match missing {
                "accepted-payload marker" => {
                    assert!(!store.payloads.contains(&block_root));
                    assert_eq!(
                        store.execution_proof_contexts.get(&block_root),
                        Some(&prepared_input)
                    );
                }
                "Q" => {
                    assert!(store.payloads.contains(&block_root));
                    assert!(!store.execution_proof_contexts.contains_key(&block_root));
                }
                _ => unreachable!(),
            }
            assert_eq!(
                (
                    store.timely_payloads.clone(),
                    store.accepted_execution_payload_envelopes.clone(),
                    store
                        .cached_execution_payload_envelope_by_root(block_root)
                        .map(Arc::as_ptr),
                    store.tick(),
                    store.justified_checkpoint(),
                    store.finalized_checkpoint(),
                    store.last_finalized().block_root,
                    store.head().block_root,
                    store.head_node_payload_status(),
                    store.is_payload_invalid(block_root),
                ),
                other_state_after_change,
                "completion preserves non-authority Store observables ({missing}, {verdict:?})"
            );
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "three benign updates are checked against all typed reports with exact map expectations"
)]
#[test]
fn execution_proof_completion_keeps_context_applicable_after_benign_changes() {
    let verdicts = [
        (
            ExecutionProofVerificationOutcome::Valid,
            ExecutionProofCompletionOutcome::Accept,
        ),
        (
            ExecutionProofVerificationOutcome::Invalid,
            ExecutionProofCompletionOutcome::Reject,
        ),
        (
            ExecutionProofVerificationOutcome::LocalFault,
            ExecutionProofCompletionOutcome::LocalFault,
        ),
    ];

    for change in [
        "equal Q reinsertion",
        "payload-byte cache eviction",
        "unrelated proof bookkeeping update",
    ] {
        for (verdict, expected_outcome) in verdicts {
            let (mut store, target_state, target_envelope, _, _, key) =
                retained_unfinalized_payload_fixture();
            let block_root = target_envelope.block_root();
            let target_bid = store
                .chain_link(block_root)
                .expect("target remains retained")
                .block
                .message()
                .body()
                .with_payload_bid()
                .map(|body| &body.signed_execution_payload_bid().message)
                .expect("target block contains a bid");
            let public_input = store
                .execution_proof_public_input_from_parts(
                    &target_envelope.message,
                    target_bid
                        .blob_kzg_commitments
                        .iter()
                        .copied()
                        .map(misc::kzg_commitment_to_versioned_hash),
                )
                .expect("target payload and trusted bid bind in the fixture");
            store.apply_execution_payload_envelope(
                AcceptedExecutionPayloadEnvelope::from_validation(
                    target_envelope.clone_arc(),
                    Some(public_input),
                ),
                false,
            );
            let signed_envelope =
                signed_execution_proof_for_test(&store, &target_state, &[0x42], 1, 0, &key);
            let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
            let proof_type = prepared.signed_message().proof_type;
            let validator_index = prepared.validator_index();
            let envelope_root = prepared.envelope_root();
            let prepared_context = *prepared.context_identity();
            let prepared_input = *prepared_context.public_input();
            let expected_proof = prepared.execution_proof().clone();
            let expected_message = prepared.signed_message().clone();
            let input_data_pointer = prepared.execution_proof().proof_data.as_bytes().as_ptr();
            let message_data_pointer = prepared.signed_message().proof_data.as_bytes().as_ptr();
            let cached_payload = store
                .cached_execution_payload_envelope_by_root(block_root)
                .expect("accepted payload bytes are resident before the benign update");
            let cached_payload_pointer = Arc::as_ptr(cached_payload);
            let cached_payload_slot = cached_payload.slot();
            let sentinel_root = H256::repeat_byte(0xe5);
            assert_ne!(sentinel_root, block_root, "{change}: {verdict:?}");
            // This synthetic bookkeeping is seeded after preparation, not authentic completion evidence.
            seed_execution_proof_bookkeeping(&mut store, sentinel_root);
            let bookkeeping_before = execution_proof_bookkeeping(&store);
            assert!(bookkeeping_before.0.contains_key(&sentinel_root));
            assert!(bookkeeping_before.1.contains_key(&sentinel_root));
            assert!(
                bookkeeping_before
                    .2
                    .iter()
                    .any(|(root, _, _)| *root == sentinel_root)
            );
            assert!(!bookkeeping_before.0.contains_key(&block_root));
            assert!(!bookkeeping_before.1.contains_key(&block_root));
            assert!(
                !bookkeeping_before
                    .2
                    .iter()
                    .any(|(root, _, _)| *root == block_root)
            );
            let sentinel_arc = Arc::clone(
                bookkeeping_before.0[&sentinel_root]
                    .get(&2)
                    .expect("synthetic sentinel contains a bare proof"),
            );
            assert!(store.is_payload_verified(block_root));
            assert_eq!(
                store.execution_proof_contexts.get(&block_root),
                Some(&prepared_input)
            );
            assert!(store.execution_proof_context_is_applicable(block_root, &prepared_input));
            let target_link = store.chain_link(block_root).expect("target remains stored");
            assert_eq!(target_link.payload_status, PayloadStatus::Optimistic);
            assert!(
                !target_link.is_valid(),
                "accepted marker is not an EL VALID result"
            );
            assert!(!target_link.is_invalid());

            let mut expected_after_admission = bookkeeping_before.clone();
            expected_after_admission
                .1
                .entry(block_root)
                .or_default()
                .insert(envelope_root);
            expected_after_admission
                .2
                .insert((block_root, proof_type, validator_index));
            let admitted = match store.admit_execution_proof(prepared) {
                ExecutionProofAdmission::Admitted(admitted) => admitted,
                ExecutionProofAdmission::Declined(reason) => {
                    panic!("fresh authentic proof should admit ({change}, {verdict:?}): {reason:?}")
                }
            };
            assert_eq!(
                execution_proof_bookkeeping(&store),
                expected_after_admission,
                "admission changes only the two target Seen keys ({change}, {verdict:?})"
            );
            let completion = report_admitted_execution_proof_for_test(
                admitted,
                &expected_proof,
                input_data_pointer,
                verdict,
            );
            assert_eq!(completion.envelope(), &expected_message);
            assert_eq!(completion.context_identity(), &prepared_context);
            assert_eq!(
                completion.context_identity().public_input(),
                &prepared_input
            );

            let mut expected_before_completion = expected_after_admission.clone();
            match change {
                "equal Q reinsertion" => {
                    let contexts_before = store.execution_proof_contexts.clone();
                    assert_eq!(
                        store.execution_proof_contexts.remove(&block_root),
                        Some(prepared_input)
                    );
                    assert_eq!(
                        contexts_before.get(&block_root),
                        Some(&prepared_input),
                        "the prior persistent-map version still has the same Q"
                    );
                    store
                        .execution_proof_contexts
                        .insert(block_root, prepared_input);
                }
                "payload-byte cache eviction" => {
                    assert!(
                        store
                            .cached_execution_payload_envelope_by_root(block_root)
                            .is_some()
                    );
                    store
                        .execution_payload_envelope_cache
                        .prune_finalized(cached_payload_slot.saturating_add(1));
                    assert!(
                        store
                            .cached_execution_payload_envelope_by_root(block_root)
                            .is_none()
                    );
                }
                "unrelated proof bookkeeping update" => {
                    let update_root = H256::repeat_byte(0xe6);
                    assert_ne!(update_root, block_root, "{change}: {verdict:?}");
                    assert_ne!(update_root, sentinel_root, "{change}: {verdict:?}");
                    let unrelated_message = precheck_fixture(update_root, 2, 7, vec![0x91]);
                    expected_before_completion
                        .0
                        .entry(update_root)
                        .or_default()
                        .insert(2, Arc::new(unrelated_message.message.as_ref().clone()));
                    expected_before_completion
                        .1
                        .entry(update_root)
                        .or_default()
                        .insert(H256::repeat_byte(0x92));
                    expected_before_completion.2.insert((update_root, 2, 7));
                    // This second synthetic entry models bookkeeping, not authentic completion evidence.
                    seed_execution_proof_bookkeeping(&mut store, update_root);
                }
                _ => unreachable!(),
            }
            assert_eq!(
                execution_proof_bookkeeping(&store),
                expected_before_completion,
                "the intentional benign update has an exact expected map ({change}, {verdict:?})"
            );
            assert!(store.is_payload_verified(block_root));
            assert_eq!(
                store.execution_proof_contexts.get(&block_root),
                Some(&prepared_input),
                "accepted marker and full Q remain authoritative ({change}, {verdict:?})"
            );
            assert!(store.execution_proof_context_is_applicable(block_root, &prepared_input));
            assert_eq!(
                store.chain_link(block_root).map(|link| link.payload_status),
                Some(PayloadStatus::Optimistic),
                "completion applicability does not require latest EL VALID ({change}, {verdict:?})"
            );
            match change {
                "payload-byte cache eviction" => assert!(
                    store
                        .cached_execution_payload_envelope_by_root(block_root)
                        .is_none()
                ),
                _ => assert_eq!(
                    store
                        .cached_execution_payload_envelope_by_root(block_root)
                        .map(Arc::as_ptr),
                    Some(cached_payload_pointer),
                    "only the cache-eviction case removes payload bytes ({change}, {verdict:?})"
                ),
            }
            let contexts_before_completion = store.execution_proof_contexts.clone();
            let markers_before_completion = store.payloads.clone();
            let other_state_before_completion = (
                store.timely_payloads.clone(),
                store.accepted_execution_payload_envelopes.clone(),
                store
                    .cached_execution_payload_envelope_by_root(block_root)
                    .map(Arc::as_ptr),
                store.tick(),
                store.justified_checkpoint(),
                store.finalized_checkpoint(),
                store.last_finalized().block_root,
                store.head().block_root,
                store.head_node_payload_status(),
                store.is_payload_invalid(block_root),
            );

            let mut expected_after_completion = expected_before_completion.clone();
            if verdict == ExecutionProofVerificationOutcome::Valid {
                expected_after_completion
                    .0
                    .entry(block_root)
                    .or_default()
                    .insert(proof_type, Arc::new(expected_message.clone()));
            }
            assert_eq!(
                store.complete_execution_proof(completion),
                expected_outcome,
                "benign change does not mask {verdict:?} ({change})"
            );
            assert!(store.unfinalized_locations.contains_key(&block_root));
            assert_eq!(
                execution_proof_bookkeeping(&store),
                expected_after_completion,
                "completion changes only verified storage for Valid ({change}, {verdict:?})"
            );
            assert!(store.is_payload_verified(block_root));
            assert_eq!(
                store.execution_proof_contexts, contexts_before_completion,
                "completion preserves the full live context map ({change}, {verdict:?})"
            );
            assert_eq!(
                store.execution_proof_contexts.get(&block_root),
                Some(&prepared_input)
            );
            assert_eq!(store.payloads, markers_before_completion);
            assert!(store.execution_proof_context_is_applicable(block_root, &prepared_input));
            assert_eq!(
                store.chain_link(block_root).map(|link| link.payload_status),
                Some(PayloadStatus::Optimistic)
            );
            match change {
                "payload-byte cache eviction" => assert!(
                    store
                        .cached_execution_payload_envelope_by_root(block_root)
                        .is_none()
                ),
                _ => assert_eq!(
                    store
                        .cached_execution_payload_envelope_by_root(block_root)
                        .map(Arc::as_ptr),
                    Some(cached_payload_pointer)
                ),
            }
            assert_eq!(
                (
                    store.timely_payloads.clone(),
                    store.accepted_execution_payload_envelopes.clone(),
                    store
                        .cached_execution_payload_envelope_by_root(block_root)
                        .map(Arc::as_ptr),
                    store.tick(),
                    store.justified_checkpoint(),
                    store.finalized_checkpoint(),
                    store.last_finalized().block_root,
                    store.head().block_root,
                    store.head_node_payload_status(),
                    store.is_payload_invalid(block_root),
                ),
                other_state_before_completion,
                "completion preserves payload, cache, consensus and EL observables ({change}, {verdict:?})"
            );
            if verdict == ExecutionProofVerificationOutcome::Valid {
                let stored = store.execution_proofs[&block_root]
                    .get(&proof_type)
                    .expect("Valid stores the first prepared bare envelope");
                assert_eq!(stored.as_ref(), &expected_message);
                assert_eq!(stored.beacon_block_root, block_root);
                assert_eq!(stored.proof_type, proof_type);
                assert_eq!(
                    stored.proof_data.as_bytes().as_ptr(),
                    message_data_pointer,
                    "stored bare message retains the preparation allocation"
                );
            } else {
                assert!(
                    !store.execution_proofs.contains_key(&block_root),
                    "Invalid and LocalFault do not create a target bucket ({change}, {verdict:?})"
                );
            }
            assert!(Arc::ptr_eq(
                &sentinel_arc,
                store.execution_proofs[&sentinel_root]
                    .get(&2)
                    .expect("initial unrelated sentinel remains present")
            ));
            if change == "unrelated proof bookkeeping update" {
                let update_root = H256::repeat_byte(0xe6);
                assert!(store.execution_proofs.contains_key(&update_root));
                assert!(store.execution_proof_roots.contains_key(&update_root));
                assert!(store.execution_proof_provers.contains(&(update_root, 2, 7)));
            }
        }
    }
}

fn assert_independent_block_scope_admissions(
    store: &mut Store<Minimal, NoopStorage>,
    prepared_anchor: Box<PreparedExecutionProof>,
    prepared_target: Box<PreparedExecutionProof>,
) {
    let anchor_root = prepared_anchor.context_identity().beacon_block_root();
    let target_root = prepared_target.context_identity().beacon_block_root();
    assert_ne!(anchor_root, target_root);
    assert_eq!(prepared_anchor.signed_message().proof_type, 1);
    assert_eq!(prepared_target.signed_message().proof_type, 1);
    assert_eq!(prepared_anchor.validator_index(), 0);
    assert_eq!(prepared_target.validator_index(), 0);
    assert_eq!(
        prepared_anchor.signed_message().proof_data.as_bytes(),
        prepared_target.signed_message().proof_data.as_bytes()
    );
    assert_ne!(
        prepared_anchor.envelope_root(),
        prepared_target.envelope_root()
    );
    let anchor_prover = (
        anchor_root,
        prepared_anchor.signed_message().proof_type,
        prepared_anchor.validator_index(),
    );
    let target_prover = (
        target_root,
        prepared_target.signed_message().proof_type,
        prepared_target.validator_index(),
    );
    assert_ne!(anchor_prover, target_prover);

    let anchor_q = *store
        .execution_proof_contexts
        .get(&anchor_root)
        .expect("anchor accepted-payload setup preserves Q");
    let target_q = *store
        .execution_proof_contexts
        .get(&target_root)
        .expect("target accepted-payload setup preserves Q");
    assert!(store.execution_proof_context_is_applicable(anchor_root, &anchor_q));
    assert!(store.execution_proof_context_is_applicable(target_root, &target_q));
    let contexts_before = store.execution_proof_contexts.clone();
    let before = execution_proof_bookkeeping(store);
    let mut expected_after_anchor = before.clone();
    expected_after_anchor
        .1
        .entry(anchor_root)
        .or_default()
        .insert(prepared_anchor.envelope_root());
    expected_after_anchor.2.insert(anchor_prover);
    let mut expected_after_both = expected_after_anchor.clone();
    expected_after_both
        .1
        .entry(target_root)
        .or_default()
        .insert(prepared_target.envelope_root());
    expected_after_both.2.insert(target_prover);

    assert!(matches!(
        store.admit_execution_proof(prepared_anchor),
        ExecutionProofAdmission::Admitted(_)
    ));
    assert_eq!(execution_proof_bookkeeping(store), expected_after_anchor);
    assert!(matches!(
        store.admit_execution_proof(prepared_target),
        ExecutionProofAdmission::Admitted(_)
    ));
    assert_eq!(execution_proof_bookkeeping(store), expected_after_both);
    assert_eq!(store.execution_proofs, before.0);
    assert_eq!(store.execution_proof_contexts, contexts_before);
    assert!(store.execution_proof_context_is_applicable(anchor_root, &anchor_q));
    assert!(store.execution_proof_context_is_applicable(target_root, &target_q));
}

#[test]
fn execution_proof_admission_is_independent_by_block_root() {
    let (mut store, fixture_target_state, target_envelope, _, _, key) =
        retained_unfinalized_payload_fixture();
    let anchor_root = store.last_finalized().block_root;
    let target_root = target_envelope.block_root();
    let target_state = store
        .chain_link(target_root)
        .and_then(|link| link.state.as_ref())
        .expect("retained target has its trusted state")
        .clone_arc();
    assert!(Arc::ptr_eq(&target_state, &fixture_target_state));
    let anchor_state = store
        .chain_link(anchor_root)
        .and_then(|link| link.state.as_ref())
        .expect("retained fixture anchor has its trusted state")
        .clone_arc();
    assert_eq!(accessors::latest_block_root(&anchor_state), anchor_root);
    assert_eq!(accessors::latest_block_root(&target_state), target_root);
    for state in [&anchor_state, &target_state] {
        assert_eq!(state.validators().len_u64(), 1);
        assert_eq!(
            state
                .validators()
                .get(0)
                .expect("both rooted fixture states contain validator 0")
                .pubkey,
            key.to_public_key().into()
        );
    }

    let anchor_payload = cache_accepted_test_payload(&mut store, anchor_root, anchor_state.slot());
    seed_execution_proof_context_for_test(&mut store, &anchor_state, &anchor_payload.message);
    // This synthetic target envelope is explicitly applied as accepted Store fixture data;
    // it makes no execution-layer validity claim.
    let target_bid = store
        .chain_link(target_root)
        .expect("target remains retained")
        .block
        .message()
        .body()
        .with_payload_bid()
        .map(|body| &body.signed_execution_payload_bid().message)
        .expect("target block contains a bid");
    let target_q = store
        .execution_proof_public_input_from_parts(
            &target_envelope.message,
            target_bid
                .blob_kzg_commitments
                .iter()
                .copied()
                .map(misc::kzg_commitment_to_versioned_hash),
        )
        .expect("synthetic target payload and its trusted bid bind in the fixture");
    store.apply_execution_payload_envelope(
        AcceptedExecutionPayloadEnvelope::from_validation(
            target_envelope.clone_arc(),
            Some(target_q),
        ),
        false,
    );

    let anchor_q = *store
        .execution_proof_contexts
        .get(&anchor_root)
        .expect("anchor accepted-payload setup seeds Q");
    assert!(store.payloads.contains(&anchor_root));
    assert!(store.payloads.contains(&target_root));
    assert_eq!(
        store
            .cached_execution_payload_envelope_by_root(anchor_root)
            .expect("anchor accepted payload is cached")
            .as_ref(),
        anchor_payload.as_ref()
    );
    assert_eq!(
        store
            .cached_execution_payload_envelope_by_root(target_root)
            .expect("target fixture envelope is cached")
            .as_ref(),
        target_envelope.as_ref()
    );
    assert_eq!(
        store.execution_proof_contexts.get(&anchor_root),
        Some(&anchor_q)
    );
    assert_eq!(
        store.execution_proof_contexts.get(&target_root),
        Some(&target_q)
    );

    let signed_anchor = signed_execution_proof_for_test(&store, &anchor_state, &[0x42], 1, 0, &key);
    let signed_target = signed_execution_proof_for_test(&store, &target_state, &[0x42], 1, 0, &key);
    let prepared_anchor = prepared_execution_proof_for_test(&store, &signed_anchor);
    let prepared_target = prepared_execution_proof_for_test(&store, &signed_target);
    assert_independent_block_scope_admissions(&mut store, prepared_anchor, prepared_target);
}

#[test]
fn execution_proof_admission_declines_retired_target_with_or_without_stale_marker() {
    for restore_stale_marker in [false, true] {
        let (mut store, target_state, target_envelope, descendant_root, post_checkpoint_root, key) =
            retained_unfinalized_payload_fixture();
        let target_root = target_envelope.block_root();
        let target_bid = store
            .chain_link(target_root)
            .expect("target remains retained")
            .block
            .message()
            .body()
            .with_payload_bid()
            .map(|body| &body.signed_execution_payload_bid().message)
            .expect("target block contains a bid");
        let target_q = store
            .execution_proof_public_input_from_parts(
                &target_envelope.message,
                target_bid
                    .blob_kzg_commitments
                    .iter()
                    .copied()
                    .map(misc::kzg_commitment_to_versioned_hash),
            )
            .expect("target request should bind");
        store.apply_execution_payload_envelope(
            AcceptedExecutionPayloadEnvelope::from_validation(
                target_envelope.clone_arc(),
                Some(target_q),
            ),
            false,
        );

        assert_selected_payload_application(&store, &target_envelope, Some(target_q), false);

        let signed_proof =
            signed_execution_proof_for_test(&store, &target_state, &[0x42], 1, 0, &key);
        let prepared = prepared_execution_proof_for_test(&store, &signed_proof);
        let target_context = *prepared.context_identity().public_input();
        assert_eq!(target_context, target_q);

        store.finalized_checkpoint = Checkpoint {
            epoch: 0,
            root: descendant_root,
        };
        store.prune_after_finalization();
        assert_eq!(store.last_finalized().block_root, descendant_root);
        assert_ne!(store.last_finalized().block_root, target_root);
        assert!(!store.unfinalized_locations.contains_key(&target_root));
        assert!(store.chain_link(target_root).is_some());
        assert!(
            store
                .unfinalized_locations
                .contains_key(&post_checkpoint_root)
        );
        assert_eq!(
            store
                .chain_link(post_checkpoint_root)
                .expect("post-checkpoint child remains in the live segment")
                .parent_root(),
            descendant_root
        );
        assert_eq!(
            store.execution_proof_contexts.get(&target_root),
            Some(&target_context),
            "retirement must leave stale Q available for the admission check"
        );
        if restore_stale_marker {
            // Isolate the stale-metadata case without applying a late payload that clears Q.
            store.payloads.insert(target_root);
        }
        assert_eq!(store.payloads.contains(&target_root), restore_stale_marker);

        let before = execution_proof_bookkeeping(&store);
        let admission = store.admit_execution_proof(prepared);
        assert!(matches!(
            admission,
            ExecutionProofAdmission::Declined(ExecutionProofAdmissionDecline::Retired)
        ));
        assert_eq!(
            execution_proof_bookkeeping(&store),
            before,
            "retired admission must preserve all proof maps"
        );
        assert_eq!(
            store.execution_proof_contexts.get(&target_root),
            Some(&target_context)
        );
        assert_eq!(store.payloads.contains(&target_root), restore_stale_marker);
    }
}

#[test]
fn execution_proof_admission_forged_signature_does_not_consume_seen_keys() {
    let (mut store, _, signed_proof) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let bookkeeping = execution_proof_bookkeeping(&store);
    let mut forged_proof = signed_proof.clone();
    forged_proof.signature = SignedExecutionProofEnvelope::default().signature;

    assert_preparation_rejected(&store, &forged_proof, |error| {
        matches!(error, Error::ExecutionProofEnvelopeInvalidSignature { .. })
    });
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);

    let prepared = prepared_execution_proof_for_test(&store, &signed_proof);
    let block_root = prepared.context_identity().beacon_block_root();
    let proof_type = prepared.signed_message().proof_type;
    let envelope_root = prepared.envelope_root();
    let prover_key = (block_root, proof_type, prepared.validator_index());
    let mut expected = bookkeeping;
    expected
        .1
        .entry(block_root)
        .or_default()
        .insert(envelope_root);
    expected.2.insert(prover_key);

    assert!(matches!(
        store.admit_execution_proof(prepared),
        ExecutionProofAdmission::Admitted(_)
    ));
    assert_eq!(execution_proof_bookkeeping(&store), expected);
}

#[test]
fn execution_proof_admission_dropped_work_keeps_seen_keys_permanently() {
    let (mut store, state, signed_proof) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let first = prepared_execution_proof_for_test(&store, &signed_proof);
    let same_carrier = prepared_execution_proof_for_test(&store, &signed_proof);
    let changed_bytes =
        signed_execution_proof_for_test(&store, &state, &[0x43], 1, 0, &proof_signing_key());
    let same_prover = prepared_execution_proof_for_test(&store, &changed_bytes);
    let block_root = first.context_identity().beacon_block_root();
    let envelope_root = first.envelope_root();
    let prover_key = (
        block_root,
        first.signed_message().proof_type,
        first.validator_index(),
    );
    assert_eq!(same_carrier.envelope_root(), envelope_root);
    assert_eq!(
        (
            same_prover.context_identity().beacon_block_root(),
            same_prover.signed_message().proof_type,
            same_prover.validator_index(),
        ),
        prover_key
    );
    assert_ne!(same_prover.envelope_root(), envelope_root);

    let before = execution_proof_bookkeeping(&store);
    let mut expected_after_admission = before.clone();
    expected_after_admission
        .1
        .entry(block_root)
        .or_default()
        .insert(envelope_root);
    expected_after_admission.2.insert(prover_key);
    let admitted = match store.admit_execution_proof(first) {
        ExecutionProofAdmission::Admitted(admitted) => admitted,
        ExecutionProofAdmission::Declined(_) => {
            panic!("first authentic attempt should be admitted")
        }
    };
    drop(admitted);
    assert_eq!(
        execution_proof_bookkeeping(&store),
        expected_after_admission,
        "dropping never-started work must retain both Seen keys"
    );
    assert_eq!(store.execution_proofs, before.0);

    assert_execution_proof_admission_declined_without_writes(
        &mut store,
        same_carrier,
        ExecutionProofAdmissionDecline::SeenRoot,
    );
    assert_execution_proof_admission_declined_without_writes(
        &mut store,
        same_prover,
        ExecutionProofAdmissionDecline::SeenProver,
    );
    assert_eq!(
        execution_proof_bookkeeping(&store),
        expected_after_admission
    );
    assert_eq!(store.execution_proofs, before.0);
}

#[test]
fn execution_proof_admission_scopes_root_seen_buckets_by_block() {
    let (mut store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
    let block_root = prepared.context_identity().beacon_block_root();
    let envelope_root = prepared.envelope_root();
    let other_block_root = H256::repeat_byte(0xa7);
    assert_ne!(other_block_root, block_root);
    assert!(!store.execution_proof_roots.contains_key(&block_root));
    assert!(!store.execution_proof_roots.contains_key(&other_block_root));

    // Synthetic bucket placement isolates B scoping; it is not a real hash collision.
    store
        .execution_proof_roots
        .entry(other_block_root)
        .or_default()
        .insert(envelope_root);
    assert!(!store.execution_proof_roots.contains_key(&block_root));
    let before = execution_proof_bookkeeping(&store);
    let mut expected = before.clone();
    expected
        .1
        .entry(block_root)
        .or_default()
        .insert(envelope_root);
    expected.2.insert((
        block_root,
        prepared.signed_message().proof_type,
        prepared.validator_index(),
    ));

    assert!(matches!(
        store.admit_execution_proof(prepared),
        ExecutionProofAdmission::Admitted(_)
    ));
    assert_eq!(execution_proof_bookkeeping(&store), expected);
    assert!(store.execution_proof_roots[&other_block_root].contains(&envelope_root));
    assert!(store.execution_proof_roots[&block_root].contains(&envelope_root));
    assert_eq!(store.execution_proofs, before.0);
}

#[test]
fn prepared_execution_proof_into_parts_moves_all_components_and_cached_root() {
    let (store, _, signed_envelope) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
    let expected_input = prepared.execution_proof().clone();
    let expected_message = prepared.signed_message().clone();
    let expected_context_identity = *prepared.context_identity();
    let expected_envelope_root = prepared.envelope_root();
    let input_data_pointer = prepared.execution_proof().proof_data.as_bytes().as_ptr();
    let message_data_pointer = prepared.signed_message().proof_data.as_bytes().as_ptr();

    let (actual_signed_envelope, actual_input, actual_context_identity, actual_envelope_root) =
        (*prepared).into_parts();

    assert_eq!(actual_signed_envelope.message.as_ref(), &expected_message);
    assert_eq!(actual_signed_envelope.signature, signed_envelope.signature);
    assert_eq!(actual_input, expected_input);
    assert_eq!(actual_context_identity, expected_context_identity);
    assert_eq!(actual_envelope_root, expected_envelope_root);
    assert_eq!(
        actual_input.proof_data.as_bytes().as_ptr(),
        input_data_pointer,
        "consuming extraction preserves the engine-input allocation"
    );
    assert_eq!(
        actual_signed_envelope
            .message
            .proof_data
            .as_bytes()
            .as_ptr(),
        message_data_pointer,
        "consuming extraction preserves the signed-message allocation"
    );
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
        .insert(1, Arc::new(signed_proof.message.as_ref().clone()));
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

#[test]
fn execution_proof_payload_context_capture_failure_is_after_notify_and_does_not_change_acceptance()
{
    let (mut store, _, envelope) = payload_validation_fixture();
    store.fail_execution_proof_context_capture = true;
    let engine = recording_payload_engine(&store, false);
    let block_root = envelope.block_root();

    let accepted = accepted_payload_carrier(&store, &envelope, &engine);

    assert_eq!(
        *store.execution_proof_context_capture_trace.lock(),
        ["notify", "capture"]
    );
    assert_eq!(
        store
            .execution_proof_context_capture_attempts
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(engine.requests.lock().len(), 1);
    assert!(accepted.proof_public_input.is_none());
    assert!(!store.is_payload_verified(block_root));

    store.apply_execution_payload_envelope(accepted, true);

    assert!(store.is_payload_verified(block_root));
    assert_selected_payload_application(&store, &envelope, None, true);
}

#[test]
fn execution_proof_payload_context_capture_is_skipped_when_engine_submission_fails() {
    let (mut store, _, envelope) = payload_validation_fixture();
    store.fail_execution_proof_context_capture = true;
    let engine = RecordingPayloadEngine {
        fail_notification: true,
        ..recording_payload_engine(&store, true)
    };

    let error = store
        .validate_execution_payload_envelope(
            &envelope,
            &ExecutionPayloadEnvelopeOrigin::Own,
            &engine,
            NullVerifier,
        )
        .expect_err("ordinary EL submission failure must remain an error");

    assert!(
        error
            .to_string()
            .contains("test-only execution submission failure")
    );
    assert_eq!(
        *store.execution_proof_context_capture_trace.lock(),
        ["notify"]
    );
    assert_eq!(
        store
            .execution_proof_context_capture_attempts
            .load(Ordering::SeqCst),
        0
    );
    assert!(store.execution_proof_contexts.is_empty());
    assert!(!store.is_payload_verified(envelope.block_root()));
}

#[test]
fn execution_proof_payload_capture_is_not_run_before_ordinary_rejection() {
    let (store, _, envelope) = payload_validation_fixture();
    let mut invalid_envelope = envelope.as_ref().clone();
    invalid_envelope.message.payload.block_hash = ExecutionBlockHash::repeat_byte(0x77);
    let invalid_envelope = Arc::new(invalid_envelope);
    let engine = recording_payload_engine(&store, false);

    let error = store
        .validate_execution_payload_envelope(
            &invalid_envelope,
            &ExecutionPayloadEnvelopeOrigin::Own,
            &engine,
            NullVerifier,
        )
        .expect_err("ordinary bid binding rejection should remain an error");

    assert!(matches!(
        error.downcast_ref::<Error<Minimal>>(),
        Some(Error::ExecutionPayloadBlockHashMismatch { .. })
    ));
    assert!(
        store
            .execution_proof_context_capture_trace
            .lock()
            .is_empty()
    );
    assert_eq!(
        store
            .execution_proof_context_capture_attempts
            .load(Ordering::SeqCst),
        0
    );
    assert!(engine.requests.lock().is_empty());
    assert!(!store.is_payload_verified(envelope.block_root()));
}

#[test]
fn execution_proof_payload_capture_matches_full_submitted_request_and_trusted_proof_binder() {
    let (mut store, state, envelope) = payload_validation_fixture();
    let engine = recording_payload_engine(&store, false);
    let accepted = accepted_payload_carrier(&store, &envelope, &engine);
    let captured = accepted
        .proof_public_input
        .expect("healthy ordinary validation should capture its statement");
    let block_root = envelope.block_root();
    let (notified_root, submitted_request) = recorded_payload_request(&engine, 0);
    assert_eq!(notified_root, block_root);

    let block = &store
        .chain_link(block_root)
        .expect("fixture block is retained")
        .block;
    let bid = block
        .message()
        .body()
        .with_payload_bid()
        .map(|body| &body.signed_execution_payload_bid().message)
        .expect("fixture block has the selected payload bid");
    let state_bid = state
        .post_gloas()
        .expect("fixture state is Gloas")
        .latest_execution_payload_bid();
    assert_eq!(bid, state_bid);
    assert_eq!(bid.blob_kzg_commitments.len(), 2);
    assert_eq!(envelope.message.execution_requests.deposits.len(), 1);
    assert_eq!(envelope.message.payload.transactions.len(), 1);
    assert_ne!(
        envelope.message.parent_beacon_block_root,
        H256::zero(),
        "fixture parent beacon block root must exercise request binding"
    );
    assert_eq!(
        envelope.message.parent_beacon_block_root,
        state.latest_block_header().parent_root
    );
    let expected_payload =
        types::combined::ExecutionPayload::Gloas(envelope.message.payload.clone());
    let expected_params = ExecutionPayloadParams::Gloas {
        versioned_hashes: bid
            .blob_kzg_commitments
            .iter()
            .copied()
            .map(misc::kzg_commitment_to_versioned_hash)
            .collect(),
        parent_beacon_block_root: state.latest_block_header().parent_root,
        execution_requests: envelope.message.execution_requests.clone(),
    };
    let reconstructed_request = NewPayloadRequest::new(&expected_payload, &expected_params)
        .expect("selected block bid and Gloas envelope form a request");
    assert_eq!(
        submitted_request, reconstructed_request,
        "capture must use every field from the ordinary submitted request"
    );
    assert_eq!(
        captured.new_payload_request_root,
        submitted_request.zkboost_compatible_root()
    );

    let trusted_binding = store
        .get_execution_proof(
            &state,
            &ExecutionProofEnvelope::default(),
            &envelope.message,
        )
        .expect("the trusted PR17 binder should reconstruct the same healthy statement");
    assert_eq!(captured, trusted_binding.public_input);

    store.apply_execution_payload_envelope(accepted, false);
    assert_eq!(
        store.execution_proof_contexts.get(&block_root),
        Some(&captured)
    );
    assert!(store.execution_proof_context_is_applicable(block_root, &captured));
}

#[test]
fn execution_proof_payload_context_capture_declines_oversized_binding_without_changing_acceptance()
{
    let oversized_commitments = vec![KzgCommitment::repeat_byte(0x66); 4097];
    let (mut store, _, envelope) = payload_validation_fixture_with_state_bid_commitments(
        Arc::new(NoopStorage),
        Some(oversized_commitments),
        None,
        None,
    );
    let engine = recording_payload_engine(&store, false);
    let block_root = envelope.block_root();

    let accepted = accepted_payload_carrier(&store, &envelope, &engine);

    assert_eq!(
        *store.execution_proof_context_capture_trace.lock(),
        ["notify", "capture"]
    );
    assert_eq!(
        store
            .execution_proof_context_capture_attempts
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(engine.requests.lock().len(), 1);
    {
        let submissions = engine.requests.lock();
        let submission = &submissions[0];
        assert_eq!(submission.block_root, block_root);
        assert!(matches!(
            &submission.payload,
            types::combined::ExecutionPayload::Gloas(_)
        ));
        let Some(ExecutionPayloadParams::Gloas {
            versioned_hashes, ..
        }) = submission.params.as_ref()
        else {
            panic!("ordinary oversized submission must preserve its raw Gloas params");
        };
        assert_eq!(versioned_hashes.len(), 4097);
    }
    assert!(accepted.proof_public_input.is_none());
    assert!(!store.is_payload_verified(block_root));

    store.apply_execution_payload_envelope(accepted, true);

    assert!(store.is_payload_verified(block_root));
    assert_selected_payload_application(&store, &envelope, None, true);
}

#[test]
fn execution_proof_payload_capture_is_skipped_for_ignore_and_delay_actions() {
    let (mut ignored_store, _, envelope) = payload_validation_fixture();
    ignored_store.accepted_execution_payload_envelopes.insert((
        envelope.slot(),
        envelope.block_root(),
        envelope.builder_index(),
    ));
    let ignored_engine = recording_payload_engine(&ignored_store, true);
    let ignored = ignored_store
        .validate_execution_payload_envelope(
            &envelope,
            &ExecutionPayloadEnvelopeOrigin::Own,
            &ignored_engine,
            NullVerifier,
        )
        .expect("duplicate envelope should be ignored before execution");
    assert!(matches!(
        ignored,
        ExecutionPayloadEnvelopeValidationAction::Ignore(true)
    ));
    assert!(ignored_engine.requests.lock().is_empty());
    assert!(
        ignored_store
            .execution_proof_context_capture_trace
            .lock()
            .is_empty()
    );
    assert_eq!(
        ignored_store
            .execution_proof_context_capture_attempts
            .load(Ordering::SeqCst),
        0
    );

    let (delayed_store, _, envelope) = payload_validation_fixture();
    let mut unknown_envelope = envelope.as_ref().clone();
    let unknown_root = H256::repeat_byte(0xee);
    unknown_envelope.message.beacon_block_root = unknown_root;
    let unknown_envelope = Arc::new(unknown_envelope);
    let delayed_engine = recording_payload_engine(&delayed_store, true);
    let delayed = delayed_store
        .validate_execution_payload_envelope(
            &unknown_envelope,
            &ExecutionPayloadEnvelopeOrigin::Own,
            &delayed_engine,
            NullVerifier,
        )
        .expect("unknown block should delay the envelope before execution");
    assert!(matches!(
        delayed,
        ExecutionPayloadEnvelopeValidationAction::DelayUntilBeaconBlock(_, root)
            if root == unknown_root
    ));
    assert!(delayed_engine.requests.lock().is_empty());
    assert!(
        delayed_store
            .execution_proof_context_capture_trace
            .lock()
            .is_empty()
    );
    assert_eq!(
        delayed_store
            .execution_proof_context_capture_attempts
            .load(Ordering::SeqCst),
        0
    );
}

#[test]
fn execution_proof_payload_signature_error_skips_notification_and_capture() {
    let key = proof_signing_key();
    let validator = Validator {
        pubkey: key.to_public_key().into(),
        activation_epoch: 0,
        exit_epoch: FAR_FUTURE_EPOCH,
        ..Default::default()
    };
    let (store, state, envelope) = payload_validation_fixture_with_state_bid_commitments(
        Arc::new(NoopStorage),
        None,
        None,
        Some(validator),
    );
    let mut wrong_signer_bytes = SecretKeyBytes::default();
    wrong_signer_bytes.as_mut()[31] = 2;
    let wrong_signer: SecretKey = wrong_signer_bytes
        .try_into()
        .expect("scalar two is a valid test key");
    let mut invalid_envelope = envelope.as_ref().clone();
    invalid_envelope.signature = invalid_envelope
        .message
        .sign(&store.chain_config, &state, &wrong_signer)
        .into();
    let invalid_envelope = Arc::new(invalid_envelope);
    let engine = recording_payload_engine(&store, false);

    let error = store
        .validate_execution_payload_envelope(
            &invalid_envelope,
            &ExecutionPayloadEnvelopeOrigin::Gossip(GossipId::default()),
            &engine,
            NullVerifier,
        )
        .expect_err("a validly encoded signature from the wrong key must fail authentication");

    assert!(matches!(
        error.downcast_ref::<helper_functions::error::Error>(),
        Some(helper_functions::error::Error::SignatureInvalid(
            SignatureKind::ExecutionPayloadEnvelope
        ))
    ));
    assert!(engine.requests.lock().is_empty());
    assert!(
        store
            .execution_proof_context_capture_trace
            .lock()
            .is_empty()
    );
    assert_eq!(
        store
            .execution_proof_context_capture_attempts
            .load(Ordering::SeqCst),
        0
    );
}

#[test]
fn execution_proof_payload_data_availability_delay_skips_notification_and_capture() {
    let (mut store, _, envelope) = payload_validation_fixture();
    // All earlier forks must be active before Fulu in fork_slots() iteration; otherwise
    // phase_at_slot stops at the first unscheduled fork and selects the blob availability
    // window instead of the data-column window.
    let chain_config = ChainConfig {
        altair_fork_epoch: GENESIS_EPOCH,
        bellatrix_fork_epoch: GENESIS_EPOCH,
        capella_fork_epoch: GENESIS_EPOCH,
        deneb_fork_epoch: GENESIS_EPOCH,
        electra_fork_epoch: GENESIS_EPOCH,
        fulu_fork_epoch: GENESIS_EPOCH,
        gloas_fork_epoch: GENESIS_EPOCH,
        ..Default::default()
    };
    store.chain_config = Arc::new(chain_config);
    store.tick = Tick::start_of_slot(envelope.slot());
    store.store_sampling_columns([0].into());

    let slot_epoch = misc::compute_epoch_at_slot::<Minimal>(envelope.slot());
    assert_eq!(slot_epoch, GENESIS_EPOCH);
    assert_eq!(store.tick.epoch::<Minimal>(), slot_epoch);
    assert_eq!(
        store.chain_config.phase_at_slot::<Minimal>(envelope.slot()),
        Phase::Gloas
    );
    assert!(matches!(
        store.storage_mode(),
        StorageMode::Standard {
            custom_data_availability_window: None
        }
    ));
    assert_eq!(
        store
            .chain_config
            .min_epochs_for_data_column_sidecars_requests,
        4_096
    );
    assert_eq!(
        store
            .storage_mode()
            .min_epochs_for_data_column_sidecars_requests(&store.chain_config),
        4_096
    );
    assert_eq!(
        store.min_checked_data_column_availability_epoch(),
        GENESIS_EPOCH
    );
    assert_eq!(
        store.min_checked_data_availability_epoch(envelope.slot()),
        GENESIS_EPOCH
    );
    assert!(store.should_check_data_availability_at_slot(envelope.slot()));

    let target_block = &store
        .chain_link(envelope.block_root())
        .expect("fixture target block is retained")
        .block;
    assert_eq!(target_block.phase(), Phase::Gloas);
    assert_eq!(store.indices_of_missing_data_columns(target_block), vec![0]);

    let engine = recording_payload_engine(&store, false);
    let block_root = envelope.block_root();
    let action = store
        .validate_execution_payload_envelope(
            &envelope,
            &ExecutionPayloadEnvelopeOrigin::Own,
            &engine,
            NullVerifier,
        )
        .expect("missing Gloas data columns should delay, not reject");
    assert!(matches!(
        action,
        ExecutionPayloadEnvelopeValidationAction::DelayUntilData(_, block)
            if block.message().hash_tree_root() == block_root
    ));
    assert!(engine.requests.lock().is_empty());
    assert!(
        store
            .execution_proof_context_capture_trace
            .lock()
            .is_empty()
    );
    assert_eq!(
        store
            .execution_proof_context_capture_attempts
            .load(Ordering::SeqCst),
        0
    );
}

#[test]
fn execution_proof_payload_missing_state_delays_without_notification_or_capture() {
    let (store, _, envelope) = payload_validation_fixture();
    let block_root = envelope.block_root();
    let block = store
        .chain_link(block_root)
        .expect("fixture target block is retained")
        .block
        .clone_arc();
    let engine = recording_payload_engine(&store, false);

    let action = store
        .validate_execution_payload_envelope_with_state(
            envelope,
            &ExecutionPayloadEnvelopeOrigin::Own,
            || Some(block),
            || None,
            &engine,
        )
        .expect("missing callback state should preserve the ordinary delay action");
    assert!(matches!(
        action,
        ExecutionPayloadEnvelopeAction::DelayUntilState(_, root)
            if root == block_root
    ));
    assert!(engine.requests.lock().is_empty());
    assert!(
        store
            .execution_proof_context_capture_trace
            .lock()
            .is_empty()
    );
    assert_eq!(
        store
            .execution_proof_context_capture_attempts
            .load(Ordering::SeqCst),
        0
    );
}

#[test]
fn execution_proof_payload_state_slot_mismatch_rejects_without_notification_or_capture() {
    let (mut store, _, envelope) = payload_validation_fixture();
    let mismatched_state = Arc::new(BeaconState::from(GloasBeaconState::<Minimal> {
        slot: envelope.slot() + 1,
        ..Default::default()
    }));
    store
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor remains in the finalized chain")
        .state = Some(mismatched_state.clone_arc());
    let engine = recording_payload_engine(&store, false);

    let error = store
        .validate_execution_payload_envelope(
            &envelope,
            &ExecutionPayloadEnvelopeOrigin::Own,
            &engine,
            NullVerifier,
        )
        .expect_err("an inconsistent selected state must preserve ordinary rejection");
    assert!(matches!(
        error.downcast_ref::<Error<Minimal>>(),
        Some(Error::ExecutionPayloadEnvelopeSlotMismatch { .. })
    ));
    assert!(engine.requests.lock().is_empty());
    assert!(
        store
            .execution_proof_context_capture_trace
            .lock()
            .is_empty()
    );
    assert_eq!(
        store
            .execution_proof_context_capture_attempts
            .load(Ordering::SeqCst),
        0
    );
}

#[test]
fn execution_proof_capture_disabled_preserves_ordinary_payload_validation_observables() {
    let (store, state, envelope) = payload_validation_fixture();
    let ordinary_engine = recording_payload_engine(&store, false);
    let ordinary = accepted_payload_carrier(&store, &envelope, &ordinary_engine);
    assert!(ordinary.proof_public_input.is_some());

    let disabled_engine = recording_payload_engine(&store, false);
    let block_root = envelope.block_root();
    let disabled = store
        .validate_execution_payload_envelope_with_state(
            envelope.clone_arc(),
            &ExecutionPayloadEnvelopeOrigin::Own,
            || {
                store
                    .chain_link(block_root)
                    .map(|link| link.block.clone_arc())
            },
            || Some(state.clone_arc()),
            &disabled_engine,
        )
        .expect("capture-disabled validation should preserve ordinary acceptance");
    assert!(matches!(
        disabled,
        ExecutionPayloadEnvelopeAction::Accept(_)
    ));
    assert_eq!(
        recorded_payload_request(&ordinary_engine, 0),
        recorded_payload_request(&disabled_engine, 0)
    );
    assert_eq!(
        *store.execution_proof_context_capture_trace.lock(),
        ["notify", "capture", "notify"]
    );
    assert_eq!(
        store
            .execution_proof_context_capture_attempts
            .load(Ordering::SeqCst),
        1
    );
}

#[test]
fn execution_proof_payload_validation_accepts_from_exact_cached_state() {
    let (mut store, state, envelope) = payload_validation_fixture();
    let block_root = envelope.block_root();
    store
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = None;
    store
        .state_cache
        .get_or_insert_with(block_root, state.slot(), true, || {
            Ok((state.clone_arc(), None))
        })
        .expect("exact fixture state should be cached");
    assert!(
        store
            .state_cache
            .before_or_at_slot_in_cache_only(block_root, state.slot())
            .is_some()
    );

    let engine = recording_payload_engine(&store, false);
    let accepted = accepted_payload_carrier(&store, &envelope, &engine);
    let captured = accepted
        .proof_public_input
        .expect("exact cached state should preserve healthy capture");
    let (notified_root, submitted_request) = recorded_payload_request(&engine, 0);
    assert_eq!(notified_root, block_root);
    assert_eq!(
        captured.new_payload_request_root,
        submitted_request.zkboost_compatible_root()
    );
    assert_eq!(
        *store.execution_proof_context_capture_trace.lock(),
        ["notify", "capture"]
    );

    store.apply_execution_payload_envelope(accepted, false);
    assert_selected_payload_application(&store, &envelope, Some(captured), false);
}

#[test]
fn execution_proof_payload_validation_accepts_from_persisted_exact_state() {
    let storage = Arc::new(ContextStorage::default());
    let (mut store, state, envelope) = payload_validation_fixture_with_state_bid_commitments(
        storage.clone_arc(),
        None,
        None,
        None,
    );
    let block_root = envelope.block_root();
    store
        .finalized
        .iter_mut()
        .next()
        .expect("fixture anchor must remain in the finalized chain")
        .state = None;
    storage.states.lock().insert(block_root, state.clone_arc());
    assert!(
        store
            .state_cache
            .before_or_at_slot_in_cache_only(block_root, state.slot())
            .is_none()
    );
    assert!(storage.requested_roots.lock().is_empty());

    let engine = recording_payload_engine(&store, false);
    let accepted = accepted_payload_carrier(&store, &envelope, &engine);
    let captured = accepted
        .proof_public_input
        .expect("persisted exact state should preserve healthy capture");
    assert_eq!(*storage.requested_roots.lock(), [block_root]);
    let (notified_root, submitted_request) = recorded_payload_request(&engine, 0);
    assert_eq!(notified_root, block_root);
    assert_eq!(
        captured.new_payload_request_root,
        submitted_request.zkboost_compatible_root()
    );

    store.apply_execution_payload_envelope(accepted, false);
    assert_selected_payload_application(&store, &envelope, Some(captured), false);
}

#[test]
fn execution_proof_payload_validation_does_not_select_next_slot_only_cache_state() {
    let (mut store, state, envelope) = payload_validation_fixture();
    let block_root = envelope.block_root();
    let next_slot_state = Arc::new(BeaconState::from(GloasBeaconState::<Minimal> {
        slot: state.slot() + 1,
        ..Default::default()
    }));
    store
        .state_cache
        .get_or_insert_with(block_root, next_slot_state.slot(), true, || {
            Ok((next_slot_state.clone_arc(), None))
        })
        .expect("next-slot-only fixture cache should be inserted");
    assert!(
        store
            .state_cache
            .before_or_at_slot_in_cache_only(block_root, state.slot())
            .is_none()
    );
    assert!(
        store
            .state_cache
            .before_or_at_slot_in_cache_only(block_root, next_slot_state.slot())
            .is_some()
    );

    let engine = recording_payload_engine(&store, false);
    let accepted = accepted_payload_carrier(&store, &envelope, &engine);
    let captured = accepted
        .proof_public_input
        .expect("ordinary fallback state should preserve healthy capture");
    let (notified_root, submitted_request) = recorded_payload_request(&engine, 0);
    assert_eq!(notified_root, block_root);
    assert_eq!(
        captured.new_payload_request_root,
        submitted_request.zkboost_compatible_root()
    );

    store.apply_execution_payload_envelope(accepted, false);
    assert_selected_payload_application(&store, &envelope, Some(captured), false);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the bid mutation, replay, state selection, and capture assertions are chronological"
)]
fn execution_proof_payload_validation_accepts_after_ordinary_state_reconstruction() {
    let (config, pre_state, mut blocks, _) =
        load_gloas_block_fixture(APPLIED_PARENT_PAYLOAD_TWO_BLOCKS);
    assert_eq!(blocks.len(), 2, "fixture must contain a replay target");
    let execution_requests = ExecutionRequests::<Minimal>::default();
    let target_block = blocks.last_mut().expect("fixture has a target block");
    let SignedBeaconBlock::Gloas(target_block) = target_block else {
        panic!("fixture target must use the Gloas block schema");
    };
    let target_bid = &mut target_block
        .message
        .body
        .signed_execution_payload_bid
        .message;
    target_bid.execution_requests_root = execution_requests.hash_tree_root();
    target_bid.blob_kzg_commitments = ProgressiveList::default();

    // Recompute the fixture post-state from its persisted parent seed after changing only
    // the target bid fields needed to produce a healthy, DA-independent envelope fixture.
    let pubkey_cache = PubkeyCache::default();
    let mut reconstructed_state = pre_state.clone();
    for block in &blocks {
        combined::trusted_state_transition(
            config.as_ref(),
            &pubkey_cache,
            &mut reconstructed_state,
            block,
        )
        .expect("modified fixture chain should replay through the normal transition");
    }
    let target_block = blocks.last_mut().expect("fixture has a target block");
    let SignedBeaconBlock::Gloas(target_block) = target_block else {
        unreachable!("target schema was checked above");
    };
    target_block.message.state_root = reconstructed_state.hash_tree_root();
    let target_root = blocks
        .last()
        .expect("fixture has a target block")
        .message()
        .hash_tree_root();
    assert_eq!(
        accessors::latest_block_root(&reconstructed_state),
        target_root
    );
    let target_state = Arc::new(reconstructed_state);

    let storage = Arc::new(ContextStorage::default());
    let (mut store, _anchor_root, block_roots) =
        fixture_chain_store(config.clone_arc(), pre_state, blocks, storage.clone_arc());
    // The persisted seed predates the target. Validate when that target is current rather
    // than triggering the ordinary future-envelope gossip guard before reconstruction.
    store.tick = Tick::start_of_slot(target_state.slot());
    assert_eq!(store.slot(), target_state.slot());
    assert_eq!(block_roots.last(), Some(&target_root));
    assert!(
        store
            .state_cache
            .before_or_at_slot_in_cache_only(target_root, target_state.slot())
            .is_none()
    );
    assert!(storage.requested_roots.lock().is_empty());
    assert!(
        store
            .chain_link(target_root)
            .expect("target block remains in Store")
            .state
            .is_none()
    );

    let target_bid = store
        .chain_link(target_root)
        .expect("target block remains in Store")
        .block
        .message()
        .body()
        .with_payload_bid()
        .map(|body| &body.signed_execution_payload_bid().message)
        .expect("fixture target contains a payload bid");
    let timestamp = misc::compute_timestamp_at_slot(&config, &target_state, target_state.slot())
        .expect("fixture target timestamp should be computable");
    let post_gloas_state = target_state.post_gloas().expect("target state is Gloas");
    let envelope = Arc::new(SignedExecutionPayloadEnvelope {
        message: ExecutionPayloadEnvelope {
            payload: GloasExecutionPayload {
                parent_hash: post_gloas_state.latest_block_hash(),
                prev_randao: target_bid.prev_randao,
                gas_limit: target_bid.gas_limit,
                timestamp,
                withdrawals: ProgressiveList::try_from(
                    post_gloas_state
                        .payload_expected_withdrawals()
                        .iter()
                        .copied()
                        .collect::<Vec<_>>(),
                )
                .expect("expected withdrawals fit in the payload progressive list"),
                block_hash: target_bid.block_hash,
                slot_number: target_state.slot(),
                ..Default::default()
            },
            execution_requests,
            builder_index: target_bid.builder_index,
            beacon_block_root: target_root,
            parent_beacon_block_root: target_state.latest_block_header().parent_root,
        },
        ..Default::default()
    });
    let engine = recording_payload_engine(&store, false);
    let accepted = accepted_payload_carrier(&store, &envelope, &engine);
    let captured = accepted
        .proof_public_input
        .expect("reconstructed ordinary state should preserve healthy capture");
    let (notified_root, submitted_request) = recorded_payload_request(&engine, 0);
    assert_eq!(notified_root, target_root);
    assert_eq!(
        captured.new_payload_request_root,
        submitted_request.zkboost_compatible_root()
    );
    assert!(storage.requested_roots.lock().contains(&target_root));
    assert!(
        store
            .state_cache
            .before_or_at_slot_in_cache_only(target_root, target_state.slot())
            .is_some(),
        "ordinary slot selection should publish its reconstructed result through the existing cache"
    );

    store.apply_execution_payload_envelope(accepted, false);
    assert_selected_payload_application(&store, &envelope, Some(captured), false);
}

#[test]
fn execution_proof_block_bid_is_ordinary_source_and_state_disagreement_declines_preparation() {
    let key = proof_signing_key();
    let validator = Validator {
        pubkey: key.to_public_key().into(),
        activation_epoch: 0,
        exit_epoch: FAR_FUTURE_EPOCH,
        ..Default::default()
    };
    let state_commitments = vec![
        KzgCommitment::repeat_byte(0x99),
        KzgCommitment::repeat_byte(0xaa),
    ];
    let (mut store, state, payload_envelope) =
        payload_validation_fixture_with_state_bid_commitments(
            Arc::new(NoopStorage),
            None,
            Some(state_commitments),
            Some(validator),
        );
    let engine = recording_payload_engine(&store, false);
    let accepted = accepted_payload_carrier(&store, &payload_envelope, &engine);
    let captured = accepted
        .proof_public_input
        .expect("ordinary request capture should use the block bid");
    let block_root = payload_envelope.block_root();
    let block_bid = store
        .chain_link(block_root)
        .expect("target block remains stored")
        .block
        .message()
        .body()
        .with_payload_bid()
        .map(|body| &body.signed_execution_payload_bid().message)
        .expect("fixture block contains its bid");
    let state_bid = state
        .post_gloas()
        .expect("fixture state is Gloas")
        .latest_execution_payload_bid();
    assert_ne!(
        block_bid.blob_kzg_commitments,
        state_bid.blob_kzg_commitments
    );

    let (notified_root, submitted_request) = recorded_payload_request(&engine, 0);
    assert_eq!(notified_root, block_root);
    let expected_params = ExecutionPayloadParams::Gloas {
        versioned_hashes: block_bid
            .blob_kzg_commitments
            .iter()
            .copied()
            .map(misc::kzg_commitment_to_versioned_hash)
            .collect(),
        parent_beacon_block_root: payload_envelope.message.parent_beacon_block_root,
        execution_requests: payload_envelope.message.execution_requests.clone(),
    };
    let expected_request = NewPayloadRequest::new(
        &types::combined::ExecutionPayload::Gloas(payload_envelope.message.payload.clone()),
        &expected_params,
    )
    .expect("block bid and envelope should form the ordinary request");
    assert_eq!(submitted_request, expected_request);
    assert_eq!(
        captured.new_payload_request_root,
        submitted_request.zkboost_compatible_root()
    );

    // Ordinary validation remains based on the block's bid; PR17 preparation remains based
    // on its trusted target state. The mismatch must locally decline, never repair either side.
    let trusted_binding = store
        .get_execution_proof(
            &state,
            &ExecutionProofEnvelope::default(),
            &payload_envelope.message,
        )
        .expect("the state-based binder should remain available for comparison");
    assert_ne!(captured, trusted_binding.public_input);
    store.apply_execution_payload_envelope(accepted, false);
    assert_eq!(
        store.execution_proof_contexts.get(&block_root),
        Some(&captured)
    );

    let proof_envelope = ExecutionProofEnvelope {
        proof_data: ProofData::try_from(vec![0x42])
            .expect("one byte is within the proof-data bound"),
        proof_type: 1,
        beacon_block_root: block_root,
    };
    let signed_proof = SignedExecutionProofEnvelope {
        signature: proof_envelope
            .sign(&store.chain_config, &state, state.slot(), &key)
            .into(),
        message: Hc::from(proof_envelope),
        validator_index: 0,
    };
    let bookkeeping = execution_proof_bookkeeping(&store);
    assert!(matches!(
        crate::prepare_execution_proof(&store, &signed_proof),
        Ok(crate::ExecutionProofPreparation::Ignore(
            "execution proof's accepted payload context is no longer applicable"
        ))
    ));
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);
}

#[test]
fn execution_proof_custom_state_payload_validation_cannot_mint_live_proof_authority() {
    let (store, state, envelope) = payload_validation_fixture();
    let engine = recording_payload_engine(&store, false);
    let block = store
        .chain_link(envelope.block_root())
        .expect("fixture block is retained")
        .block
        .clone_arc();

    let raw_action = store
        .validate_execution_payload_envelope_with_state(
            envelope.clone_arc(),
            &ExecutionPayloadEnvelopeOrigin::Own,
            || Some(block),
            || Some(state),
            &engine,
        )
        .expect("custom-state validation should retain its raw result contract");

    assert!(matches!(
        raw_action,
        ExecutionPayloadEnvelopeAction::Accept(_)
    ));
    assert_eq!(
        *store.execution_proof_context_capture_trace.lock(),
        ["notify"]
    );
    assert_eq!(
        store
            .execution_proof_context_capture_attempts
            .load(Ordering::SeqCst),
        0
    );
    assert!(store.execution_proof_contexts.is_empty());
    assert!(!store.is_payload_verified(envelope.block_root()));
}

#[test]
fn execution_proof_payload_context_replacement_tracks_some_to_some_content_and_snapshots() {
    let (mut store, _, envelope) = payload_validation_fixture();
    let first = payload_carrier_from_snapshot(&store, &envelope, false);
    let first_q = first.proof_public_input.expect("capture should succeed");
    let equivalent_envelope = Arc::new(envelope.as_ref().clone());
    let equivalent = payload_carrier_from_snapshot(&store, &equivalent_envelope, false);
    let equivalent_q = equivalent
        .proof_public_input
        .expect("equivalent capture should succeed");
    let changed_envelope = payload_with_gas_used(&envelope, 1);
    let changed = payload_carrier_from_snapshot(&store, &changed_envelope, false);
    let changed_q = changed
        .proof_public_input
        .expect("changed capture should succeed");

    assert_eq!(
        first_q, equivalent_q,
        "allocation identity is not Q identity"
    );
    assert_ne!(first_q, changed_q, "full request content changes Q");

    let block_root = envelope.block_root();
    store.apply_execution_payload_envelope(first, false);
    assert_selected_payload_application(&store, &envelope, Some(first_q), false);
    let first_snapshot = store.clone();
    store.apply_execution_payload_envelope(equivalent, true);
    assert_selected_payload_application(&store, &equivalent_envelope, Some(first_q), true);
    assert_eq!(
        store.execution_proof_contexts.get(&block_root),
        Some(&first_q)
    );
    assert_eq!(
        store
            .cached_execution_payload_envelope_by_root(block_root)
            .expect("replacement payload should remain selected")
            .as_ref(),
        equivalent_envelope.as_ref()
    );
    assert_eq!(
        first_snapshot.execution_proof_contexts.get(&block_root),
        Some(&first_q)
    );
    assert!(first_snapshot.execution_proof_context_is_applicable(block_root, &first_q));

    let equivalent_snapshot = store.clone();
    store.apply_execution_payload_envelope(changed, false);
    assert_selected_payload_application(&store, &changed_envelope, Some(changed_q), true);
    assert_eq!(
        store.execution_proof_contexts.get(&block_root),
        Some(&changed_q)
    );
    assert!(!store.execution_proof_context_is_applicable(block_root, &first_q));
    assert_eq!(
        equivalent_snapshot
            .execution_proof_contexts
            .get(&block_root),
        Some(&first_q),
        "older persistent snapshots retain their prior selection and evidence"
    );
}

#[test]
fn execution_proof_payload_context_some_none_pairing_matrix_clears_old_authority() {
    let (mut store, _, envelope) = payload_validation_fixture();
    let none_a = payload_carrier_from_snapshot(&store, &envelope, true);
    let none_b = payload_carrier_from_snapshot(&store, &envelope, true);
    let some = payload_carrier_from_snapshot(&store, &envelope, false);
    let some_q = some.proof_public_input.expect("capture should succeed");
    let none_c = payload_carrier_from_snapshot(&store, &envelope, true);
    let block_root = envelope.block_root();

    assert!(none_a.proof_public_input.is_none());
    assert!(none_b.proof_public_input.is_none());
    assert!(none_c.proof_public_input.is_none());
    store.apply_execution_payload_envelope(none_a, false);
    assert_selected_payload_application(&store, &envelope, None, false);
    store.apply_execution_payload_envelope(none_b, true);
    assert_selected_payload_application(&store, &envelope, None, true);
    store.apply_execution_payload_envelope(some, false);
    assert_selected_payload_application(&store, &envelope, Some(some_q), true);
    let some_snapshot = store.clone();
    store.apply_execution_payload_envelope(none_c, true);
    assert_selected_payload_application(&store, &envelope, None, true);
    assert!(some_snapshot.execution_proof_context_is_applicable(block_root, &some_q));
}

#[test]
fn execution_proof_reverse_application_order_tracks_selected_envelope_and_full_q() {
    let (mut store, _, envelope_a) = payload_validation_fixture();
    let envelope_b = payload_with_gas_used(&envelope_a, 45_000);
    let carrier_a = payload_carrier_from_snapshot(&store, &envelope_a, false);
    let q_a = carrier_a.proof_public_input.expect("A should capture Q");
    let carrier_b = payload_carrier_from_snapshot(&store, &envelope_b, false);
    let q_b = carrier_b.proof_public_input.expect("B should capture Q");
    assert_ne!(q_a, q_b);

    store.apply_execution_payload_envelope(carrier_b, false);
    assert_selected_payload_application(&store, &envelope_b, Some(q_b), false);
    store.apply_execution_payload_envelope(carrier_a, false);
    assert_selected_payload_application(&store, &envelope_a, Some(q_a), false);
}

#[test]
fn execution_proof_a_b_a_application_tracks_selected_envelope_and_full_q_each_time() {
    let (mut store, _, envelope_a) = payload_validation_fixture();
    let envelope_b = payload_with_gas_used(&envelope_a, 46_000);
    let equivalent_a = Arc::new(envelope_a.as_ref().clone());
    let carrier_a1 = payload_carrier_from_snapshot(&store, &envelope_a, false);
    let q_a = carrier_a1
        .proof_public_input
        .expect("first A should capture Q");
    let carrier_b = payload_carrier_from_snapshot(&store, &envelope_b, false);
    let q_b = carrier_b.proof_public_input.expect("B should capture Q");
    let carrier_a2 = payload_carrier_from_snapshot(&store, &equivalent_a, false);
    let q_a2 = carrier_a2
        .proof_public_input
        .expect("second A should capture Q");
    assert_eq!(q_a, q_a2);
    assert_ne!(q_a, q_b);

    store.apply_execution_payload_envelope(carrier_a1, false);
    assert_selected_payload_application(&store, &envelope_a, Some(q_a), false);
    store.apply_execution_payload_envelope(carrier_b, false);
    assert_selected_payload_application(&store, &envelope_b, Some(q_b), false);
    store.apply_execution_payload_envelope(carrier_a2, false);
    assert_selected_payload_application(&store, &equivalent_a, Some(q_a), false);
}

#[test]
fn execution_proof_equivalent_replacement_capture_failure_clears_q_without_affecting_snapshot() {
    let (mut store, _, envelope) = payload_validation_fixture();
    let selected = payload_carrier_from_snapshot(&store, &envelope, false);
    let selected_q = selected.proof_public_input.expect("capture should succeed");
    let equivalent_envelope = Arc::new(envelope.as_ref().clone());
    let failed_replacement = payload_carrier_from_snapshot(&store, &equivalent_envelope, true);
    let block_root = envelope.block_root();

    store.apply_execution_payload_envelope(selected, false);
    let old_snapshot = store.clone();
    store.apply_execution_payload_envelope(failed_replacement, true);

    assert!(store.is_payload_verified(block_root));
    assert_selected_payload_application(&store, &equivalent_envelope, None, true);
    assert_eq!(
        old_snapshot.execution_proof_contexts.get(&block_root),
        Some(&selected_q)
    );
    assert!(old_snapshot.execution_proof_context_is_applicable(block_root, &selected_q));
}

#[test]
fn execution_proof_live_payload_applicability_compares_every_public_input_field() {
    let (mut store, _, envelope) = payload_validation_fixture();
    let accepted = payload_carrier_from_snapshot(&store, &envelope, false);
    let public_input = accepted.proof_public_input.expect("capture should succeed");
    let block_root = envelope.block_root();
    store.apply_execution_payload_envelope(accepted, false);

    let different_request_root = H256::repeat_byte(0x99);
    assert_ne!(
        different_request_root,
        public_input.new_payload_request_root
    );
    let mismatches = [
        PublicInput {
            new_payload_request_root: different_request_root,
            ..public_input
        },
        PublicInput {
            successful_validation: !public_input.successful_validation,
            ..public_input
        },
        PublicInput {
            chain_id: public_input.chain_id.wrapping_add(1),
            ..public_input
        },
        PublicInput {
            schema_id: public_input.schema_id ^ 1,
            ..public_input
        },
    ];
    for mismatch in mismatches {
        assert!(!store.execution_proof_context_is_applicable(block_root, &mismatch));
    }
    let mut markerless_snapshot = store.clone();
    markerless_snapshot.payloads.remove(&block_root);
    assert!(!markerless_snapshot.execution_proof_context_is_applicable(block_root, &public_input));
    assert!(store.execution_proof_context_is_applicable(block_root, &public_input));
}

#[expect(
    clippy::too_many_lines,
    reason = "all typed reports and marker variants share one real finalization lifecycle"
)]
#[test]
fn execution_proof_completion_discards_all_reports_after_descendant_finalization() {
    let verdicts = [
        ExecutionProofVerificationOutcome::Valid,
        ExecutionProofVerificationOutcome::Invalid,
        ExecutionProofVerificationOutcome::LocalFault,
    ];

    for (restore_stale_marker, marker_case) in
        [(false, "pruned marker"), (true, "restored stale marker")]
    {
        for verdict in verdicts {
            let (
                mut store,
                target_state,
                target_envelope,
                descendant_root,
                post_checkpoint_root,
                key,
            ) = retained_unfinalized_payload_fixture();
            let target_root = target_envelope.block_root();
            let initial_anchor_root = store.last_finalized().block_root;
            let target_bid = store
                .chain_link(target_root)
                .expect("fixture target remains retained")
                .block
                .message()
                .body()
                .with_payload_bid()
                .map(|body| &body.signed_execution_payload_bid().message)
                .expect("fixture target block contains a bid");
            let target_q = store
                .execution_proof_public_input_from_parts(
                    &target_envelope.message,
                    target_bid
                        .blob_kzg_commitments
                        .iter()
                        .copied()
                        .map(misc::kzg_commitment_to_versioned_hash),
                )
                .expect("fixture target payload and trusted bid bind");

            // The fixture returns a payload, not an applied Store acceptance result.
            store.apply_execution_payload_envelope(
                AcceptedExecutionPayloadEnvelope::from_validation(
                    target_envelope.clone_arc(),
                    Some(target_q),
                ),
                false,
            );
            assert_selected_payload_application(&store, &target_envelope, Some(target_q), false);
            let target_link = store
                .chain_link(target_root)
                .expect("target remains retained");
            assert_eq!(target_link.payload_status, PayloadStatus::Optimistic);
            assert!(!target_link.is_valid());
            assert!(!target_link.is_invalid());

            let signed_envelope =
                signed_execution_proof_for_test(&store, &target_state, &[0x42], 1, 0, &key);
            let prepared = prepared_execution_proof_for_test(&store, &signed_envelope);
            let proof_type = prepared.signed_message().proof_type;
            let validator_index = prepared.validator_index();
            let envelope_root = prepared.envelope_root();
            let prepared_context = *prepared.context_identity();
            let expected_input = prepared.execution_proof().clone();
            let expected_message = prepared.signed_message().clone();
            let input_data_pointer = prepared.execution_proof().proof_data.as_bytes().as_ptr();
            assert_eq!(prepared_context.beacon_block_root(), target_root);
            assert_eq!(prepared_context.public_input(), &target_q);
            assert!(!expected_input.proof_data.as_bytes().is_empty());

            let unrelated_root = H256::repeat_byte(0xe5);
            assert_ne!(unrelated_root, target_root);
            assert_ne!(unrelated_root, initial_anchor_root);
            assert_ne!(unrelated_root, descendant_root);
            assert_ne!(unrelated_root, post_checkpoint_root);
            // This synthetic sentinel is unrelated bookkeeping, not valid completion evidence.
            seed_execution_proof_bookkeeping(&mut store, unrelated_root);
            let bookkeeping_before_admission = execution_proof_bookkeeping(&store);
            assert!(bookkeeping_before_admission.0.contains_key(&unrelated_root));
            assert!(bookkeeping_before_admission.1.contains_key(&unrelated_root));
            assert!(
                bookkeeping_before_admission
                    .2
                    .iter()
                    .any(|(root, _, _)| *root == unrelated_root)
            );
            assert!(!bookkeeping_before_admission.0.contains_key(&target_root));
            assert!(!bookkeeping_before_admission.1.contains_key(&target_root));
            assert!(
                !bookkeeping_before_admission
                    .2
                    .iter()
                    .any(|(root, _, _)| *root == target_root)
            );
            let unrelated_arc = Arc::clone(
                bookkeeping_before_admission.0[&unrelated_root]
                    .get(&2)
                    .expect("synthetic sentinel has a stored bare envelope"),
            );
            assert!(store.execution_proof_context_is_applicable(target_root, &target_q));

            let contexts_before_admission = store.execution_proof_contexts.clone();
            let mut expected_after_admission = bookkeeping_before_admission.clone();
            expected_after_admission
                .1
                .entry(target_root)
                .or_default()
                .insert(envelope_root);
            expected_after_admission
                .2
                .insert((target_root, proof_type, validator_index));
            let admitted = match store.admit_execution_proof(prepared) {
                ExecutionProofAdmission::Admitted(admitted) => admitted,
                ExecutionProofAdmission::Declined(reason) => {
                    panic!("fresh authentic proof should admit before finalization: {reason:?}")
                }
            };
            assert_eq!(
                execution_proof_bookkeeping(&store),
                expected_after_admission,
                "live admission consumes exactly the target keys ({marker_case}, {verdict:?})"
            );
            assert_eq!(store.execution_proof_contexts, contexts_before_admission);
            assert_eq!(
                store.execution_proof_contexts.get(&target_root),
                Some(prepared_context.public_input())
            );

            let completion = report_admitted_execution_proof_for_test(
                admitted,
                &expected_input,
                input_data_pointer,
                verdict,
            );
            assert_eq!(completion.envelope(), &expected_message);
            assert_eq!(completion.context_identity(), &prepared_context);
            assert_eq!(completion.verification_outcome(), verdict);

            store.finalized_checkpoint = Checkpoint {
                epoch: 0,
                root: descendant_root,
            };
            store.prune_after_finalization();
            assert_eq!(store.last_finalized().block_root, descendant_root);
            assert_ne!(store.last_finalized().block_root, target_root);
            assert_eq!(store.finalized_checkpoint.root, descendant_root);
            assert!(store.finalized_indices.contains_key(&target_root));
            assert!(store.finalized_indices.contains_key(&descendant_root));
            assert!(!store.unfinalized_locations.contains_key(&target_root));
            assert!(!store.unfinalized_locations.contains_key(&descendant_root));
            let retained_child = store
                .chain_link(post_checkpoint_root)
                .expect("post-checkpoint child remains in the live segment");
            assert!(
                store
                    .unfinalized_locations
                    .contains_key(&post_checkpoint_root)
            );
            assert_eq!(retained_child.parent_root(), descendant_root);
            assert!(store.chain_link(target_root).is_some());
            assert!(!store.payloads.contains(&target_root));
            if restore_stale_marker {
                // Restore only the stale marker; applying a late payload would clear stale Q.
                store.payloads.insert(target_root);
            }
            assert_eq!(store.payloads.contains(&target_root), restore_stale_marker);
            assert_eq!(
                store.execution_proof_contexts.get(&target_root),
                Some(&target_q),
                "finalization retains stale Q for this retirement regression"
            );
            assert_eq!(
                completion.context_identity().public_input(),
                store
                    .execution_proof_contexts
                    .get(&target_root)
                    .expect("the retired target retains its stale Q")
            );
            assert!(!store.execution_proof_context_is_applicable(target_root, &target_q));

            let proof_maps_before_completion = execution_proof_bookkeeping(&store);
            assert_eq!(proof_maps_before_completion, expected_after_admission);
            assert!(!proof_maps_before_completion.0.contains_key(&target_root));
            assert!(proof_maps_before_completion.1[&target_root].contains(&envelope_root));
            assert!(proof_maps_before_completion.2.contains(&(
                target_root,
                proof_type,
                validator_index
            )));
            assert!(Arc::ptr_eq(
                &unrelated_arc,
                proof_maps_before_completion.0[&unrelated_root]
                    .get(&2)
                    .expect("unrelated sentinel survives finalization")
            ));

            let contexts_before_completion = store.execution_proof_contexts.clone();
            let payload_markers_before_completion = store.payloads.clone();
            let timely_markers_before_completion = store.timely_payloads.clone();
            let accepted_envelopes_before_completion =
                store.accepted_execution_payload_envelopes.clone();
            let cached_payload_pointer_before_completion = store
                .cached_execution_payload_envelope_by_root(target_root)
                .map(Arc::as_ptr);
            let consensus_observables_before_completion = (
                store.tick(),
                store.justified_checkpoint(),
                store.finalized_checkpoint(),
                store.last_finalized().block_root,
                store.head().block_root,
                store.head_node_payload_status(),
                store
                    .chain_link(target_root)
                    .map(|link| link.payload_status),
                store.is_payload_invalid(target_root),
                store.chain_link(target_root).and_then(|link| {
                    link.state
                        .as_ref()
                        .map(|state| (Arc::as_ptr(state), state.hash_tree_root()))
                }),
            );

            assert_eq!(
                store.complete_execution_proof(completion),
                ExecutionProofCompletionOutcome::Discarded(ExecutionProofDiscard::Retired),
                "retirement precedes the {verdict:?} verdict ({marker_case})"
            );
            assert_eq!(
                execution_proof_bookkeeping(&store),
                proof_maps_before_completion
            );
            assert_eq!(store.execution_proofs, proof_maps_before_completion.0);
            assert!(!store.execution_proofs.contains_key(&target_root));
            assert_eq!(store.execution_proof_contexts, contexts_before_completion);
            assert_eq!(store.payloads, payload_markers_before_completion);
            assert_eq!(store.timely_payloads, timely_markers_before_completion);
            assert_eq!(
                store.accepted_execution_payload_envelopes,
                accepted_envelopes_before_completion
            );
            assert_eq!(
                store
                    .cached_execution_payload_envelope_by_root(target_root)
                    .map(Arc::as_ptr),
                cached_payload_pointer_before_completion
            );
            assert_eq!(
                (
                    store.tick(),
                    store.justified_checkpoint(),
                    store.finalized_checkpoint(),
                    store.last_finalized().block_root,
                    store.head().block_root,
                    store.head_node_payload_status(),
                    store
                        .chain_link(target_root)
                        .map(|link| link.payload_status),
                    store.is_payload_invalid(target_root),
                    store.chain_link(target_root).and_then(|link| {
                        link.state
                            .as_ref()
                            .map(|state| (Arc::as_ptr(state), state.hash_tree_root()))
                    }),
                ),
                consensus_observables_before_completion,
                "late report cannot change consensus or EL observables ({marker_case}, {verdict:?})"
            );
            assert!(Arc::ptr_eq(
                &unrelated_arc,
                store.execution_proofs[&unrelated_root]
                    .get(&2)
                    .expect("unrelated sentinel survives completion")
            ));
        }
    }
}

#[test]
fn execution_proof_unfinalized_target_late_results_preserve_ordinary_apply_but_not_authority() {
    let (mut store, target_state, target_envelope, descendant_root, post_checkpoint_root, key) =
        retained_unfinalized_payload_fixture();
    let target_root = target_envelope.block_root();
    let target_bid = store
        .chain_link(target_root)
        .expect("target remains retained")
        .block
        .message()
        .body()
        .with_payload_bid()
        .map(|body| &body.signed_execution_payload_bid().message)
        .expect("target block contains a bid");
    let target_q = store
        .execution_proof_public_input_from_parts(
            &target_envelope.message,
            target_bid
                .blob_kzg_commitments
                .iter()
                .copied()
                .map(misc::kzg_commitment_to_versioned_hash),
        )
        .expect("target request should bind");
    let selected = AcceptedExecutionPayloadEnvelope::from_validation(
        target_envelope.clone_arc(),
        Some(target_q),
    );
    store.apply_execution_payload_envelope(selected, false);
    assert!(store.unfinalized_locations.contains_key(&target_root));
    assert_selected_payload_application(&store, &target_envelope, Some(target_q), false);
    assert!(store.execution_proof_context_is_applicable(target_root, &target_q));

    // Finalize the descendant. The target becomes a historical finalized ancestor: its
    // ChainLink remains readable, but it leaves the shared live eligibility domain.
    store.finalized_checkpoint = Checkpoint {
        epoch: 0,
        root: descendant_root,
    };
    store.prune_after_finalization();
    assert!(store.finalized_indices.contains_key(&target_root));
    assert!(store.finalized_indices.contains_key(&descendant_root));
    assert_eq!(store.last_finalized().block_root, descendant_root);
    assert!(!store.unfinalized_locations.contains_key(&target_root));
    assert!(!store.unfinalized_locations.contains_key(&descendant_root));
    assert!(
        store
            .unfinalized_locations
            .contains_key(&post_checkpoint_root)
    );
    assert_eq!(
        store
            .chain_link(post_checkpoint_root)
            .expect("post-checkpoint child must remain in the live segment")
            .parent_root(),
        descendant_root
    );
    assert!(store.chain_link(target_root).is_some());
    assert!(!store.payloads.contains(&target_root));
    assert_eq!(
        store.execution_proof_contexts.get(&target_root),
        Some(&target_q)
    );
    assert!(!store.execution_proof_context_is_applicable(target_root, &target_q));

    // Late Some still performs the ordinary selection/cache writes, but cannot reinstall
    // authority for the retired root.
    let late_some = AcceptedExecutionPayloadEnvelope::from_validation(
        target_envelope.clone_arc(),
        Some(target_q),
    );
    store.apply_execution_payload_envelope(late_some, false);
    assert_selected_payload_application(&store, &target_envelope, None, false);
    assert!(!store.execution_proof_context_is_applicable(target_root, &target_q));

    let proof_envelope = ExecutionProofEnvelope {
        proof_data: ProofData::try_from(vec![0x42])
            .expect("one byte is within the proof-data bound"),
        proof_type: 1,
        beacon_block_root: target_root,
    };
    let signed_proof = SignedExecutionProofEnvelope {
        signature: proof_envelope
            .sign(
                &store.chain_config,
                &target_state,
                target_state.slot(),
                &key,
            )
            .into(),
        message: Hc::from(proof_envelope),
        validator_index: 0,
    };
    let bookkeeping = execution_proof_bookkeeping(&store);
    assert!(matches!(
        crate::prepare_execution_proof(&store, &signed_proof),
        Ok(crate::ExecutionProofPreparation::Ignore(
            "execution proof's accepted payload context is no longer applicable"
        ))
    ));
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);

    // A still later None result replaces selected bytes as usual and clears any stale Q.
    let changed_envelope = payload_with_gas_used(&target_envelope, 99);
    let late_none =
        AcceptedExecutionPayloadEnvelope::from_validation(changed_envelope.clone_arc(), None);
    store.apply_execution_payload_envelope(late_none, true);
    assert_selected_payload_application(&store, &changed_envelope, None, true);
    assert!(!store.execution_proof_context_is_applicable(target_root, &target_q));
}

#[test]
fn execution_proof_payload_context_survives_byte_eviction_and_retirement_needs_no_gc() {
    let (mut store, _, envelope) = payload_validation_fixture();
    let accepted = payload_carrier_from_snapshot(&store, &envelope, false);
    let public_input = accepted.proof_public_input.expect("capture should succeed");
    let block_root = envelope.block_root();
    store.apply_execution_payload_envelope(accepted, false);

    store
        .execution_payload_envelope_cache
        .prune_finalized(envelope.slot().saturating_add(1));
    assert!(
        store
            .cached_execution_payload_envelope_by_root(block_root)
            .is_none()
    );
    assert!(store.execution_proof_context_is_applicable(block_root, &public_input));

    let retired_root = H256::repeat_byte(0xaa);
    assert_ne!(retired_root, store.last_finalized().block_root);
    store.payloads.insert(retired_root);
    store
        .execution_proof_contexts
        .insert(retired_root, public_input);
    assert!(!store.execution_proof_context_is_applicable(retired_root, &public_input));
    assert_eq!(
        store.execution_proof_contexts.get(&retired_root),
        Some(&public_input),
        "retained-domain eligibility blocks stale evidence without physical pruning"
    );
}

#[test]
fn execution_proof_preparation_ignores_missing_live_payload_identity() {
    let (mut store, _, signed_proof) = proof_preparation_fixture(FAR_FUTURE_EPOCH, true);
    let block_root = signed_proof.message.beacon_block_root;
    store.execution_proof_contexts.remove(&block_root);
    let bookkeeping = execution_proof_bookkeeping(&store);

    assert!(matches!(
        crate::prepare_execution_proof(&store, &signed_proof),
        Ok(crate::ExecutionProofPreparation::Ignore(
            "execution proof's accepted payload context is no longer applicable"
        ))
    ));
    assert_execution_proof_bookkeeping_unchanged(&store, &bookkeeping);
}
