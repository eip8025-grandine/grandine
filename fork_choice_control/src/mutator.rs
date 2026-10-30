// `Mutator::run` is executed in a background thread and performs all mutations on a uniquely owned
// copy of `Store` as an alternative to locking.
//
// Some of the earlier designs used `RwLock`s, but they caused all sorts of trouble. Switching from
// a read lock to a write lock must be done carefully to not introduce deadlocks or race conditions.
// `parking_lot` implements upgradable `RwLock`s, but they deadlock when 2 threads try to upgrade
// simultaneously (the other option would be to make one of them successfully lock, but no one seems
// to have proposed that).
//
// There is a number of alternate designs possible. This is just the first one that worked and
// fulfilled our requirements (see the comment in the `controller` module).
//
// The mutator's workload could be reduced by moving the handling of ignored and rejected objects to
// tasks as well, but that would complicate code and would most likely not improve performance much
// (in fact, the opposite may be true because `p2p_tx` would have to be cloned for each task).

use core::panic::AssertUnwindSafe;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{
        Arc,
        mpsc::{Receiver, Sender},
    },
    thread::Builder,
    time::Instant,
};

use anyhow::{Error as AnyhowError, Result, anyhow};
use arc_swap::ArcSwap;
use clock::{Tick, TickKind};
use eth2_libp2p::GossipId;
use execution_engine::{
    EngineGetBlobsParams, EngineGetBlobsV1Params, EngineGetBlobsV2Params, ExecutionEngine,
    PayloadStatusV1,
};
use fork_choice_store::{
    AcceptedExecutionPayloadEnvelope, AggregateAndProofAction, ApplyBlockChanges, ApplyTickChanges,
    AttestationAction, AttestationItem, AttestationOrigin, AttestationValidationError,
    AttesterSlashingOrigin, BlobSidecarAction, BlobSidecarOrigin, BlockAction, BlockItem,
    BlockOrigin, ChainLink, DataColumnSidecarAction, DataColumnSidecarOrigin, Error,
    ExecutionPayloadBidAction, ExecutionPayloadBidOrigin, ExecutionPayloadEnvelopeOrigin,
    ExecutionPayloadEnvelopeValidationAction, ExecutionProofAdmission,
    ExecutionProofAdmissionDecline, ExecutionProofCompletion, ExecutionProofCompletionOutcome,
    ExecutionProofOrigin, ExecutionProofPreparation, PayloadAction, PayloadAttestationAction,
    PayloadAttestationItem, PayloadPresence, ProposerPreferencesAction, ProposerPreferencesOrigin,
    StateCacheProcessor, Store, ValidAttestation, ValidPayloadAttestation,
};
use futures::channel::{mpsc::Sender as MultiSender, oneshot::Sender as OneshotSender};
use helper_functions::{accessors, misc, predicates, verifier::NullVerifier};
use itertools::{Either, Itertools as _};
use logging::{
    debug_with_peers, error_with_peers, info_with_peers, trace_with_peers, warn_with_peers,
};
use num_traits::identities::Zero as _;
use prometheus_metrics::Metrics;
use proof_engine::ProofEngine;
use pubkey_cache::PubkeyCache;
use spec_test_utils::BlsSetting;
use ssz::SszHash as _;
use std_ext::ArcExt as _;
use tracing::{Span, instrument};
use typenum::Unsigned as _;
use types::{
    combined::{
        Attestation, BeaconState, DataColumnSidecar, ExecutionPayloadParams, SignedBeaconBlock,
    },
    deneb::containers::{BlobIdentifier, BlobSidecar},
    fulu::{containers::DataColumnIdentifier, primitives::ColumnIndex},
    gloas::containers::PayloadEnvelopeIdentifier,
    nonstandard::{
        PayloadStatus, Phase, RelativeEpoch, ValidationOutcome, ValidationOutcomeWithReason,
    },
    phase0::{
        consts::FAR_FUTURE_EPOCH,
        containers::Checkpoint,
        primitives::{ExecutionBlockHash, H256, Slot, ValidatorIndex},
    },
    preset::Preset,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};

use crate::{
    MutatorIgnoreReason, SidecarsPendingReconstruction,
    block_processor::BlockProcessor,
    events::{DependentRootsBundle, EventChannels},
    messages::{
        AttestationVerifierMessage, MutatorMessage, P2pMessage, PoolMessage, SubnetMessage,
        SyncMessage, ValidatorMessage,
    },
    misc::{
        BlockBlobAvailability, BlockDataColumnAvailability, Delayed, MutatorRejectionReason,
        PendingAggregateAndProof, PendingAttestation, PendingBlobSidecar, PendingBlock,
        PendingChainLink, PendingDataColumnSidecar, PendingExecutionPayloadEnvelope,
        PendingProposerPreferences, ProcessingTimings, ReorgSource, VerifyAggregateAndProofResult,
        VerifyAttestationResult, VerifyPayloadAttestationResult, WaitingForCheckpointState,
    },
    state_at_slot_cache::StateAtSlotCache,
    storage::Storage,
    tasks::{
        AttestationTask, BlobSidecarTask, BlockAttestationsTask, BlockPayloadAttestationsTask,
        BlockTask, CacheDepositSignaturesTask, CheckpointStateTask, DataColumnSidecarTask,
        ExecutionPayloadEnvelopeTask, PayloadAttestationTask, PersistBlobSidecarsTask,
        PersistDataColumnSidecarsTask, PersistExecutionPayloadEnvelopesTask,
        PersistPubkeyCacheTask, PreprocessStateTask, ProposerPreferencesTask, PruneStateCacheTask,
        RetryDataColumnSidecarTask, VerifyExecutionProofTask,
    },
    thread_pool::{Spawn, ThreadPool},
    unbounded_sink::UnboundedSink,
    wait::Wait,
};

const DATA_COLUMN_RETAIN_DURATION_IN_SLOTS: Slot = 2;
const MAX_DELAYED_FUTURE_BLOCKS_PER_SLOT: usize = 16;
const MAX_DELAYED_BLOCKS_UNTIL_PARENT: usize = 64;
// Failed archives keep their blocks in memory, so a persistent failure must not keep them forever.
const MAX_CONSECUTIVE_FAILED_ARCHIVES: u8 = 2;
// Room for requested envelopes waiting for their blocks.
// Forward sync runs many 32-slot batches ahead of the head.
// 64 was too small: envelopes near the head got dropped and sync stalled.
const MAX_DELAYED_REQUESTED_ENVELOPES_UNTIL_BLOCK_IN_EPOCHS: usize = 16;

#[expect(clippy::struct_field_names)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "verifier capture policy is independent of loading and archive task state"
)]
pub struct Mutator<P: Preset, E, W, TS, PS, LS, NS, SS, VS> {
    pubkey_cache: Arc<PubkeyCache>,
    store: Arc<Store<P, Storage<P>>>,
    store_snapshot: Arc<ArcSwap<Store<P, Storage<P>>>>,
    state_cache: Arc<StateCacheProcessor<P>>,
    block_processor: Arc<BlockProcessor<P>>,
    event_channels: Arc<EventChannels<P>>,
    execution_engine: E,
    // Controller-derived verifier policy for all delayed payload retries. Store stays engine-free.
    capture_proof_context: bool,
    delayed_until_blobs: HashMap<H256, PendingBlock<P>>,
    delayed_until_block: HashMap<H256, Delayed<P>>,
    delayed_until_data: HashMap<H256, PendingExecutionPayloadEnvelope<P>>,
    delayed_until_envelope: HashMap<H256, Delayed<P>>,
    delayed_until_slot: BTreeMap<Slot, Delayed<P>>,
    // `Mutator.delayed_until_payload` is needed mainly to run optimistic sync test cases, but the
    // problem it solves can occur in normal operation as well. The execution layer may finish
    // validating the payload before the fork choice store processes the block containing it.
    delayed_until_payload: HashMap<ExecutionBlockHash, Vec<(PayloadStatusV1, Slot)>>,
    delayed_until_state: HashMap<(H256, Slot), Delayed<P>>,
    // The specification doesn't explicitly state it, but `Store.checkpoint_states` is effectively a
    // cache, as its contents can be recomputed at any time using data from other fields.
    //
    // Advancing a `BeaconState` through slots for each attestation independently results in a
    // massive slowdown. A naive implementation (one that matches `consensus-specs` exactly) could
    // avoid this by processing attestations sequentially and mutating `Store.checkpoint_states`
    // after each one. We cannot do this because we want to process attestations in parallel.
    // We previously solved this for attestations in blocks by extracting their targets and lazily
    // computing the checkpoint state for each target. Individual attestations received in quick
    // succession would still perform slot processing independently.
    waiting_for_checkpoint_states: HashMap<Checkpoint, WaitingForCheckpointState<P>>,
    sidecars_pending_reconstruction: SidecarsPendingReconstruction<P>,
    state_at_slot_cache: Arc<StateAtSlotCache<P>>,
    storage: Arc<Storage<P>>,
    thread_pool: ThreadPool<P, E, W>,
    metrics: Option<Arc<Metrics>>,
    finished_loading_from_storage: bool,
    has_pending_archive_tasks: bool,
    is_archiving_finalized: bool,
    consecutive_failed_archives: u8,
    pending_state_cache_prune: Option<bool>,
    mutator_tx: Sender<MutatorMessage<P, W>>,
    mutator_rx: Receiver<MutatorMessage<P, W>>,
    attestation_verifier_tx: TS,
    p2p_tx: PS,
    pool_tx: LS,
    subnet_tx: NS,
    sync_tx: SS,
    validator_tx: VS,
}

impl<P, E, W, TS, PS, LS, NS, SS, VS> Mutator<P, E, W, TS, PS, LS, NS, SS, VS>
where
    P: Preset,
    E: ExecutionEngine<P> + Clone + Send + Sync + 'static,
    W: Wait,
    TS: UnboundedSink<AttestationVerifierMessage<P, W>> + Sync,
    PS: UnboundedSink<P2pMessage<P>>,
    LS: UnboundedSink<PoolMessage<P, W>>,
    NS: UnboundedSink<SubnetMessage<W>>,
    SS: UnboundedSink<SyncMessage<P>>,
    VS: UnboundedSink<ValidatorMessage<P, W>>,
{
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        pubkey_cache: Arc<PubkeyCache>,
        store_snapshot: Arc<ArcSwap<Store<P, Storage<P>>>>,
        state_cache: Arc<StateCacheProcessor<P>>,
        block_processor: Arc<BlockProcessor<P>>,
        event_channels: Arc<EventChannels<P>>,
        execution_engine: E,
        capture_proof_context: bool,
        sidecars_pending_reconstruction: SidecarsPendingReconstruction<P>,
        state_at_slot_cache: Arc<StateAtSlotCache<P>>,
        storage: Arc<Storage<P>>,
        thread_pool: ThreadPool<P, E, W>,
        metrics: Option<Arc<Metrics>>,
        mutator_tx: Sender<MutatorMessage<P, W>>,
        mutator_rx: Receiver<MutatorMessage<P, W>>,
        attestation_verifier_tx: TS,
        p2p_tx: PS,
        pool_tx: LS,
        subnet_tx: NS,
        sync_tx: SS,
        validator_tx: VS,
    ) -> Self {
        Self {
            pubkey_cache,
            store: store_snapshot.load_full(),
            store_snapshot,
            state_cache,
            block_processor,
            event_channels,
            execution_engine,
            capture_proof_context,
            delayed_until_blobs: HashMap::new(),
            delayed_until_block: HashMap::new(),
            delayed_until_data: HashMap::new(),
            delayed_until_envelope: HashMap::new(),
            delayed_until_slot: BTreeMap::new(),
            delayed_until_payload: HashMap::new(),
            delayed_until_state: HashMap::new(),
            waiting_for_checkpoint_states: HashMap::new(),
            sidecars_pending_reconstruction,
            state_at_slot_cache,
            storage,
            thread_pool,
            metrics,
            finished_loading_from_storage: false,
            has_pending_archive_tasks: false,
            is_archiving_finalized: false,
            consecutive_failed_archives: 0,
            pending_state_cache_prune: None,
            mutator_tx,
            mutator_rx,
            attestation_verifier_tx,
            p2p_tx,
            pool_tx,
            subnet_tx,
            sync_tx,
            validator_tx,
        }
    }

    #[expect(clippy::too_many_lines)]
    pub fn run(&mut self) -> Result<()> {
        loop {
            match self
                .mutator_rx
                .recv()
                .expect("sender in Controller is not dropped until mutator thread exits")
            {
                MutatorMessage::Tick { wait_group, tick } => self.handle_tick(&wait_group, tick)?,
                MutatorMessage::BackSyncStatus {
                    wait_group,
                    is_back_synced,
                } => self.handle_back_sync_status(wait_group, is_back_synced),
                MutatorMessage::Block {
                    wait_group,
                    result,
                    origin,
                    processing_timings,
                    block_root,
                    tracing_span,
                } => self.handle_block(
                    wait_group,
                    result,
                    origin,
                    processing_timings,
                    block_root,
                    tracing_span,
                )?,
                MutatorMessage::AggregateAndProof { wait_group, result } => {
                    self.handle_aggregate_and_proof(&wait_group, result)?
                }
                MutatorMessage::AggregateAndProofBatch {
                    wait_group,
                    results,
                } => self.handle_aggregate_and_proof_batch(&wait_group, results)?,
                MutatorMessage::Attestation { wait_group, result } => {
                    self.handle_attestation(&wait_group, result)?
                }
                MutatorMessage::AttestationBatch {
                    wait_group,
                    results,
                } => self.handle_attestation_batch(&wait_group, results)?,
                MutatorMessage::BlockAttestations {
                    wait_group,
                    from_test_block,
                    results,
                } => self.handle_block_attestations(&wait_group, from_test_block, results)?,
                MutatorMessage::BlockPayloadAttestations {
                    wait_group,
                    results,
                } => self.handle_block_payload_attestations(&wait_group, results),
                MutatorMessage::AttesterSlashing {
                    wait_group,
                    result,
                    origin,
                } => self.handle_attester_slashing(&wait_group, result, origin)?,
                MutatorMessage::BlobSidecar {
                    wait_group,
                    result,
                    origin,
                    blob_identifier,
                    block_seen,
                    submission_time,
                } => self.handle_blob_sidecar(
                    wait_group,
                    result,
                    origin,
                    blob_identifier,
                    block_seen,
                    submission_time,
                ),
                MutatorMessage::CheckpointState {
                    wait_group,
                    checkpoint,
                    checkpoint_state,
                } => self.handle_checkpoint_state(&wait_group, checkpoint, checkpoint_state)?,
                MutatorMessage::DataColumnSidecar {
                    wait_group,
                    result,
                    origin,
                    data_column_identifier,
                    block_seen,
                    submission_time,
                } => self.handle_data_column_sidecar(
                    wait_group,
                    result,
                    origin,
                    data_column_identifier,
                    block_seen,
                    submission_time,
                ),
                MutatorMessage::FinishedPersistingBlobSidecars {
                    wait_group,
                    persisted_blob_ids,
                } => {
                    self.handle_finish_persisting_blob_sidecars(wait_group, persisted_blob_ids);
                }
                MutatorMessage::FinishedPersistingDataColumnSidecars {
                    wait_group,
                    persisted_data_column_ids,
                    slot,
                } => {
                    self.handle_finish_persisting_data_column_sidecars(
                        wait_group,
                        persisted_data_column_ids,
                        slot,
                    );
                }
                MutatorMessage::FinishedPersistingExecutionPayloadEnvelopes {
                    wait_group,
                    persisted_block_roots,
                } => {
                    self.handle_finish_persisting_execution_payload_envelopes(
                        wait_group,
                        persisted_block_roots,
                    );
                }
                MutatorMessage::FinishedArchivingFinalized {
                    wait_group,
                    new_anchor_index,
                    saved,
                } => {
                    self.handle_finish_archiving_finalized(&wait_group, new_anchor_index, saved)?
                }
                MutatorMessage::ExecutionPayloadEnvelope {
                    wait_group,
                    result,
                    origin,
                    payload_envelope_identifier,
                    seen_before_deadline,
                    processing_timings,
                    tracing_span,
                } => self.handle_execution_payload_envelope(
                    wait_group,
                    result,
                    origin,
                    payload_envelope_identifier,
                    seen_before_deadline,
                    processing_timings,
                    tracing_span,
                ),
                MutatorMessage::PayloadBid { result, origin } => {
                    self.handle_payload_bid(result, origin)
                }
                MutatorMessage::ExecutionProofPrepared {
                    result,
                    proof_engine,
                    origin,
                } => self.handle_prepared_execution_proof(result, proof_engine, origin),
                MutatorMessage::ExecutionProofCompleted { completion, origin } => {
                    self.handle_completed_execution_proof(completion, origin)
                }
                MutatorMessage::ExecutionProof { result, origin } => {
                    self.handle_execution_proof(result, origin)
                }
                MutatorMessage::PayloadAttestation { wait_group, result } => {
                    self.handle_payload_attestation(&wait_group, result)
                }
                MutatorMessage::PayloadAttestationBatch {
                    wait_group,
                    results,
                } => self.handle_payload_attestation_batch(&wait_group, results),
                MutatorMessage::ProposerPreferences {
                    wait_group,
                    result,
                    origin,
                } => self.handle_proposer_preferences(&wait_group, result, origin),
                MutatorMessage::PreprocessedBeaconState { state } => {
                    self.prepare_execution_payload_for_next_slot(&state);
                }
                MutatorMessage::NotifiedForkChoiceUpdate {
                    wait_group,
                    head_execution_block_hash,
                    payload_status,
                } => self.handle_notified_forkchoice_update_result(
                    &wait_group,
                    head_execution_block_hash,
                    payload_status,
                ),
                MutatorMessage::NotifiedNewPayload {
                    wait_group,
                    beacon_block_root,
                    execution_block_hash,
                    payload_status,
                } => self.handle_notified_new_payload(
                    &wait_group,
                    beacon_block_root,
                    execution_block_hash,
                    payload_status,
                ),
                MutatorMessage::OverrideFinalizedCheckpoint {
                    wait_group,
                    checkpoint,
                } => {
                    self.store_mut().override_finalized_checkpoint(checkpoint);
                    self.update_store_snapshot();
                    drop(wait_group);
                }
                MutatorMessage::Stop { save_to_storage } => {
                    break self.handle_stop(save_to_storage);
                }
                MutatorMessage::StoreSamplingColumns { sampling_columns } => {
                    self.handle_store_sampling_columns(sampling_columns)
                }
                MutatorMessage::ReconstructedMissingColumns {
                    wait_group,
                    block_root,
                    block,
                    data_column_sidecars,
                } => self.handle_reconstructed_missing_columns(
                    &wait_group,
                    block_root,
                    &block,
                    data_column_sidecars,
                ),
            }
        }
    }

    pub fn process_unfinalized_blocks(
        &mut self,
        mut blocks: impl DoubleEndedIterator<Item = Result<Arc<SignedBeaconBlock<P>>>>,
    ) -> Result<()> {
        let wait_group = W::default();

        let Some(last_block) = blocks.next_back().transpose()? else {
            self.finished_loading_from_storage = true;
            return Ok(());
        };

        let head_slot = self
            .storage
            .checkpoint_state_slot(&*self.store.finalized_validators())?
            .unwrap_or_else(|| last_block.message().slot());

        self.handle_tick(&wait_group, Tick::start_of_slot(head_slot))?;

        for result in blocks.chain(core::iter::once(Ok(last_block))) {
            let block = result?;
            let origin = BlockOrigin::Persisted;
            let processing_timings = ProcessingTimings::new();
            let block_root = block.message().hash_tree_root();

            // There is no point in spawning `BlockTask`s to validate persisted blocks.
            // State transitions within a single fork must be performed sequentially.
            // Other validations may be performed in parallel, but they take very little time.
            let result = self
                .block_processor
                .validate_block(
                    &self.store,
                    BlockItem::verified(block),
                    origin.state_root_policy(),
                    origin.data_availability_policy(),
                    &self.execution_engine,
                    NullVerifier,
                )
                .into();

            self.handle_block(
                wait_group.clone(),
                result,
                origin,
                processing_timings,
                block_root,
                tracing::debug_span!("handle_unfinalized_block"),
            )?;
        }

        self.finished_loading_from_storage = true;

        Ok(())
    }

    #[expect(clippy::too_many_lines)]
    fn handle_tick(&mut self, wait_group: &W, tick: Tick) -> Result<()> {
        if tick.epoch::<P>() > self.store.current_epoch() {
            let checkpoint = self.store.unrealized_justified_checkpoint();

            if !self.store.contains_checkpoint_state(checkpoint) {
                debug_with_peers!(
                    "tick waiting for checkpoint state \
                     (tick: {tick:?}, checkpoint: {checkpoint:?})",
                );

                let waiting = self
                    .waiting_for_checkpoint_states
                    .entry(checkpoint)
                    .or_default();

                let new = waiting.is_empty();

                waiting.ticks.push(tick);

                if new {
                    self.spawn_checkpoint_state_task(wait_group.clone(), checkpoint);
                }

                return Ok(());
            }
        }

        if tick.is_start_of_epoch::<P>() {
            self.execution_engine.exchange_capabilities();
        }

        // Query the execution engine for the current status of the head
        // if it is still optimistic 1 second before the next interval.
        if tick.is_end_of_interval() {
            let head = self.store.head();

            if head.is_optimistic() {
                let mut params = None;

                if let Some(body) = head.block.message().body().with_blob_kzg_commitments() {
                    let versioned_hashes = body
                        .blob_kzg_commitments()
                        .iter()
                        .copied()
                        .map(misc::kzg_commitment_to_versioned_hash)
                        .collect();

                    let execution_payload_opt = if head.block.phase() >= Phase::Gloas {
                        // TODO(Gloas): review if this is still needed: notify new payload should only happen after validating payload envelope

                        self.store
                            .cached_execution_payload_envelope_by_root(head.block_root)
                            .map(|envelope| {
                                params = Some(ExecutionPayloadParams::Gloas {
                                    versioned_hashes,
                                    parent_beacon_block_root: head.block.message().parent_root(),
                                    execution_requests: envelope.message.execution_requests.clone(),
                                });

                                envelope.message.payload.clone().into()
                            })
                    } else {
                        head.block
                            .as_ref()
                            .clone()
                            .execution_payload()
                            .inspect(|_| {
                                params = if let Some(body) = body.with_execution_requests() {
                                    Some(ExecutionPayloadParams::Electra {
                                        versioned_hashes,
                                        parent_beacon_block_root: head
                                            .block
                                            .message()
                                            .parent_root(),
                                        execution_requests: body.execution_requests().clone(),
                                    })
                                } else {
                                    Some(ExecutionPayloadParams::Deneb {
                                        versioned_hashes,
                                        parent_beacon_block_root: head
                                            .block
                                            .message()
                                            .parent_root(),
                                    })
                                };
                            })
                    };

                    if let Some(execution_payload) = execution_payload_opt {
                        self.execution_engine.notify_new_payload(
                            head.block_root,
                            execution_payload,
                            params,
                            None,
                        )?;
                    }
                }
            }
        }

        let old_head_root = self.store.head().block_root;
        let head_was_optimistic = self.store.head_node_payload_status().is_optimistic();

        let Some(changes) = self.store_mut().apply_tick(tick)? else {
            return Ok(());
        };

        // schedule state cache prune task on a new slot, but not at the beginning of the slot
        if changes.is_slot_updated() {
            // preserve unfinalized fork tips if not finalized or epoch did not change
            self.pending_state_cache_prune =
                Some(!changes.is_finalized_checkpoint_updated() || !changes.is_epoch_updated());
        } else if let Some(preserve_unfinalized_fork_tips) = self.pending_state_cache_prune.take() {
            self.spawn_state_cache_prune_task(preserve_unfinalized_fork_tips, wait_group.clone());
        }

        if changes.is_finalized_checkpoint_updated() {
            self.has_pending_archive_tasks = true;
        } else if self.has_pending_archive_tasks && tick.kind == TickKind::Aggregate {
            self.has_pending_archive_tasks = false;

            self.archive_finalized(wait_group)?;
            self.prune_delayed_until_payload();
            self.persist_pubkey_cache(wait_group);
            self.prune_delayed_after_finalization();

            let finalized_slot = self.store.finalized_slot();

            self.event_channels.prune_after_finalization(finalized_slot);

            if self.store.head().block.phase().is_peerdas_activated() {
                self.try_spawn_persist_data_columns_task(finalized_slot, wait_group.clone());
            }
        } else if changes.is_slot_updated()
            && self.store.head().block.phase().is_peerdas_activated()
        {
            self.try_spawn_persist_data_columns_task(
                self.store
                    .head()
                    .slot()
                    .saturating_sub(DATA_COLUMN_RETAIN_DURATION_IN_SLOTS),
                wait_group.clone(),
            )
        }

        self.update_store_snapshot();

        self.send_to_validator(ValidatorMessage::Tick(wait_group.clone(), tick));
        self.send_to_pool(PoolMessage::Tick(tick));

        if changes.is_slot_updated() {
            let slot = tick.slot;

            debug_with_peers!("retrying objects delayed until slot {slot}");

            for delayed in self.take_delayed_until_slot(slot) {
                self.retry_delayed(delayed, wait_group);
            }

            self.send_to_pool(PoolMessage::Slot(slot));
            self.send_to_p2p(P2pMessage::Slot(slot));
            self.send_to_subnet_service(SubnetMessage::Slot(wait_group.clone(), slot));
        }

        if changes.is_finalized_checkpoint_updated() {
            self.notify_about_finalized_checkpoint();
        }

        if let ApplyTickChanges::Reorganized { old_head, .. } = changes {
            self.notify_about_reorganization(wait_group.clone(), &old_head, ReorgSource::Tick);
            self.spawn_preprocess_head_state_for_next_slot_task();
        } else {
            self.send_head_events_if_head_node_became_valid(old_head_root, head_was_optimistic);

            if self.store.tick().kind == TickKind::Attest {
                self.spawn_preprocess_head_state_for_next_slot_task();
            }
        }

        if self.store.is_forward_synced() && misc::slots_since_epoch_start::<P>(tick.slot) == 0 {
            if tick.kind == TickKind::AttestFourth {
                self.prune_old_records()?;
            }

            if let Some(metrics) = self.metrics.as_ref()
                && let Err(error) = Self::track_epoch_transition_metrics(
                    &self.store.head().state(&self.store),
                    metrics,
                )
            {
                debug_with_peers!("unable to track epoch transition metrics: {error:?}")
            }
        }

        if tick.is_last_tick::<P>(self.store.chain_config()) {
            self.prepare_execution_payload_for_head(self.store.head().block_root);
            self.track_collection_metrics();
        }

        Ok(())
    }

    fn handle_back_sync_status(&mut self, wait_group: W, is_back_synced: bool) {
        if self.store.is_back_synced() != is_back_synced {
            self.store_mut().set_back_synced(is_back_synced);
            self.update_store_snapshot();
        }

        drop(wait_group);
    }

    fn spawn_state_cache_prune_task(&self, preserve_unfinalized_fork_tips: bool, wait_group: W) {
        self.spawn(PruneStateCacheTask {
            store_snapshot: self.owned_store(),
            preserve_unfinalized_fork_tips,
            wait_group,
        });
    }

    fn try_spawn_persist_data_columns_task(&mut self, slot: Slot, wait_group: W) {
        if self.storage.prune_storage_enabled() {
            return self.store_mut().prune_data_columns(slot);
        }

        self.spawn(PersistDataColumnSidecarsTask {
            slot,
            store_snapshot: self.owned_store(),
            storage: self.storage.clone_arc(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            metrics: self.metrics.clone(),
        });
    }

    #[expect(clippy::cognitive_complexity)]
    #[expect(clippy::too_many_lines)]
    #[instrument(
        skip_all,
        parent = &tracing_span,
        level = "debug",
        fields(
            block_root = ?block_root,
        ),
    )]
    fn handle_block(
        &mut self,
        wait_group: W,
        result: Box<Result<BlockAction<P>>>,
        origin: BlockOrigin,
        processing_timings: ProcessingTimings,
        block_root: H256,
        tracing_span: Span,
    ) -> Result<()> {
        match *result {
            Ok(BlockAction::Accept(mut chain_link, attester_slashing_results)) => {
                let block_root = chain_link.block_root;
                let parent_root = chain_link.parent_root();

                if origin.should_send_gossip_event() {
                    self.event_channels
                        .send_block_gossip_event(chain_link.slot(), block_root);
                }

                if let Some(delayed) = self.delayed_until_block.get_mut(&block_root)
                    && let Some((payload_status, _)) = delayed.payload_status.take()
                {
                    debug_with_peers!(
                        "applying delayed payload status \
                            (payload_status: {payload_status:?}, beacon_block_root: {block_root:?})",
                    );

                    if let Some(valid_hash) = payload_status.latest_valid_hash
                        && let Some(parent) = self.store.chain_link(parent_root)
                    {
                        let parent_execution_block_hash = parent.block.execution_block_hash();

                        self.store_mut()
                            .update_chain_payload_statuses(valid_hash, parent_execution_block_hash);

                        self.update_store_snapshot();
                    }

                    if payload_status.status.is_valid() {
                        chain_link.payload_status = PayloadStatus::Valid;
                    }

                    if payload_status.status.is_invalid() && chain_link.block.phase() < Phase::Gloas
                    {
                        self.reject_block(
                            Error::<P>::InvalidExecutionPayload.into(),
                            block_root,
                            origin,
                        );
                        return Ok(());
                    }
                }

                let pending_chain_link = PendingChainLink {
                    chain_link,
                    attester_slashing_results,
                    origin,
                    processing_timings,
                };

                self.accept_block(&wait_group, pending_chain_link)?;
            }
            Ok(BlockAction::Ignore(publishable)) => {
                let (gossip_id, sender) = origin.split();

                // `publishable` means the block is already known. Nothing to refetch.
                if publishable {
                    if let Some(gossip_id) = gossip_id {
                        self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                    }
                } else {
                    debug_with_peers!("block ignored: {block_root:?}");

                    self.send_to_p2p(P2pMessage::IgnoreWithReason(
                        gossip_id,
                        MutatorIgnoreReason::BlockIgnored { block_root },
                    ));
                }

                reply_block_validation_result_to_http_api(
                    sender,
                    Ok(ValidationOutcome::Ignore(publishable)),
                );
            }
            Ok(BlockAction::DelayUntilBlobs(block, state)) => {
                let processing_timings = processing_timings.delayed();

                let pending_block = PendingBlock {
                    block,
                    origin,
                    processing_timings,
                    tracing_span,
                };

                if pending_block.block.item.phase().is_peerdas_activated() {
                    let block_data_column_availability = self.block_data_column_availability(
                        &pending_block.block.item,
                        self.delayed_until_state
                            .get(&(block_root, state.slot()))
                            .iter()
                            .flat_map(|delayed| delayed.data_column_sidecars.iter())
                            .map(|pending| pending.data_column_sidecar.as_ref()),
                    );

                    debug_with_peers!(
                        "availability for block: {:?} with origin: {:?} at slot: {}: {block_data_column_availability:?}",
                        pending_block.block.item.message().hash_tree_root(),
                        pending_block.origin,
                        pending_block.block.item.message().slot(),
                    );

                    match block_data_column_availability {
                        BlockDataColumnAvailability::Complete => {
                            self.retry_block(wait_group, pending_block);
                        }
                        BlockDataColumnAvailability::AnyPending => {
                            self.delay_block_until_blobs(block_root, pending_block);

                            self.take_delayed_until_state(block_root, state.slot())
                                .unwrap_or_default()
                                .data_column_sidecars
                                .into_iter()
                                .for_each(|pending_data_column| {
                                    self.retry_data_column_sidecar(
                                        wait_group.clone(),
                                        pending_data_column,
                                        Some(state.clone_arc()),
                                    );
                                });
                        }
                        BlockDataColumnAvailability::CompleteWithReconstruction {
                            import_block,
                        } => {
                            if let Some(gossip_id) = pending_block.origin.gossip_id() {
                                self.send_to_p2p(P2pMessage::Accept(gossip_id));
                            }

                            let missing_indices = self
                                .store
                                .indices_of_missing_data_columns(&pending_block.block.item);

                            if missing_indices.is_empty() {
                                self.retry_block(wait_group, pending_block);
                            } else {
                                // TODO(peerdas-fulu): NEED REVIEW! if block proposed by itself, therefore all sampling
                                // columns should be arrived soon or later, so no need to trigger reconstruction.
                                if !matches!(pending_block.origin, BlockOrigin::Own)
                                    && !self.store.is_sidecars_construction_started(&block_root)
                                {
                                    let slot = pending_block.block.item.message().slot();

                                    self.store
                                        .mark_sidecar_construction_started(block_root, slot);

                                    if import_block {
                                        for index in missing_indices {
                                            self.mark_sidecar_as_being_reconstructed(
                                                DataColumnIdentifier { block_root, index },
                                                slot,
                                            );
                                        }
                                    }

                                    self.send_to_pool(PoolMessage::ReconstructDataColumns {
                                        wait_group: wait_group.clone(),
                                        block_root,
                                        block: pending_block.block.item.clone_arc(),
                                        slot: pending_block.block.item.message().slot(),
                                        is_from_requested: pending_block.origin.is_requested(),
                                    })
                                }

                                if import_block {
                                    self.retry_block(wait_group, pending_block);
                                } else {
                                    self.delay_block_until_blobs(block_root, pending_block);
                                }
                            }
                        }
                        BlockDataColumnAvailability::Missing(missing_column_indices) => {
                            debug_with_peers!(
                                "block delayed until sufficient data column sidecars are available \
                                 (missing columns: {missing_column_indices:?}, pending block root: {block_root:?})",
                            );

                            if let Some(gossip_id) = pending_block.origin.gossip_id() {
                                self.send_to_p2p(P2pMessage::Accept(gossip_id));
                            }

                            let pending_block = reply_delayed_block_validation_result(
                                pending_block,
                                Ok(ValidationOutcome::Ignore(false)),
                            );

                            if self.store.is_forward_synced()
                                && !self.store.has_requested_blobs_from_el(&block_root)
                                && !self.store.is_sidecars_construction_started(&block_root)
                            {
                                self.store_mut().mark_requested_blobs_from_el(
                                    block_root,
                                    pending_block.block.item.message().slot(),
                                );
                                self.update_store_snapshot();

                                let data_column_identifiers = missing_column_indices
                                    .into_iter()
                                    .map(|index| DataColumnIdentifier { block_root, index })
                                    .collect_vec();

                                self.request_blobs_from_execution_engine(
                                    EngineGetBlobsV2Params {
                                        block_or_sidecar: pending_block
                                            .block
                                            .item
                                            .clone_arc()
                                            .into(),
                                        data_column_identifiers,
                                    }
                                    .into(),
                                );
                            }

                            self.delay_block_until_blobs(block_root, pending_block);
                        }
                        BlockDataColumnAvailability::Irrelevant => {
                            unreachable!("block without blobs should not be delayed until blobs")
                        }
                    }
                } else {
                    let block_blob_availability = self.block_blob_availability(
                        &pending_block.block.item,
                        self.delayed_until_state
                            .get(&(block_root, state.slot()))
                            .iter()
                            .flat_map(|delayed| delayed.blob_sidecars.iter())
                            .map(|pending_blob_sidecar| pending_blob_sidecar.blob_sidecar.as_ref()),
                    );

                    match block_blob_availability {
                        BlockBlobAvailability::Complete => {
                            self.retry_block(wait_group, pending_block);
                        }
                        BlockBlobAvailability::CompleteWithPending => {
                            self.delay_block_until_blobs(block_root, pending_block);

                            self.take_delayed_until_state(block_root, state.slot())
                                .unwrap_or_default()
                                .blob_sidecars
                                .into_iter()
                                .for_each(|pending_blob| {
                                    self.retry_blob_sidecar(
                                        wait_group.clone(),
                                        pending_blob,
                                        Some(state.clone_arc()),
                                    );
                                });
                        }
                        BlockBlobAvailability::Missing(missing_blob_indices) => {
                            debug_with_peers!("block delayed until blobs: {block_root:?}");
                            trace_with_peers!("block delayed until blobs: {pending_block:?}");

                            if let Some(gossip_id) = pending_block.origin.gossip_id() {
                                self.send_to_p2p(P2pMessage::Accept(gossip_id));
                            }

                            let pending_block = reply_delayed_block_validation_result(
                                pending_block,
                                Ok(ValidationOutcome::Ignore(false)),
                            );

                            let blob_identifiers = missing_blob_indices
                                .into_iter()
                                .map(|index| BlobIdentifier { block_root, index })
                                .collect_vec();

                            let peer_id = pending_block.origin.peer_id();

                            self.request_blobs_from_execution_engine(
                                EngineGetBlobsV1Params {
                                    block: pending_block.block.item.clone_arc(),
                                    blob_identifiers,
                                    peer_id,
                                }
                                .into(),
                            );

                            self.delay_block_until_blobs(block_root, pending_block);
                        }
                        BlockBlobAvailability::Irrelevant => {
                            unreachable!("block without blobs should not be delayed until blobs")
                        }
                    }
                }
            }
            Ok(BlockAction::DelayUntilParent(block)) => {
                let processing_timings = processing_timings.delayed();
                let parent_root = block.item.message().parent_root();

                let pending_block = PendingBlock {
                    block,
                    origin,
                    processing_timings,
                    tracing_span,
                };

                if self.store.contains_block(parent_root) {
                    self.retry_block(wait_group, pending_block);
                } else {
                    let pending_block = reply_delayed_block_validation_result(
                        pending_block,
                        Ok(ValidationOutcome::Ignore(false)),
                    );

                    let peer_id = pending_block.origin.peer_id();

                    self.send_to_p2p(P2pMessage::BlockNeeded(parent_root, peer_id));

                    // Spec test runners queue early blocks and redeliver them later.
                    // Parking them here too would import them in a different order.
                    // The order decides which block attestations count as from-block.
                    if matches!(pending_block.origin, BlockOrigin::Test(_)) {
                        debug_with_peers!("test block with unknown parent dropped: {block_root:?}");
                        return Ok(());
                    }

                    trace_with_peers!("attempting to delay block until parent: {pending_block:?}");

                    let gossip_id = pending_block.origin.gossip_id_ref().cloned();

                    if let Err(error) = self.try_delay_block_until_parent(pending_block) {
                        debug_with_peers!("unable to delay block until parent: {error:?}");

                        self.send_to_p2p(P2pMessage::IgnoreWithReason(
                            gossip_id,
                            MutatorIgnoreReason::BlockQueueFull { block_root },
                        ));
                    } else {
                        debug_with_peers!("block delayed until parent: {block_root:?}");
                    }
                }
            }
            Ok(BlockAction::DelayUntilPayload(block)) => {
                let processing_timings = processing_timings.delayed();
                let parent_root = block.item.message().parent_root();

                let pending_block = PendingBlock {
                    block,
                    origin,
                    processing_timings,
                    tracing_span,
                };

                if self.store.is_payload_verified(parent_root) {
                    self.retry_block(wait_group, pending_block);
                } else {
                    let pending_block = reply_delayed_block_validation_result(
                        pending_block,
                        Ok(ValidationOutcome::Ignore(false)),
                    );

                    debug_with_peers!("block delayed until payload: {block_root:?}");
                    trace_with_peers!("block delayed until payload: {pending_block:?}");

                    let peer_id = pending_block.origin.peer_id();

                    self.send_to_p2p(P2pMessage::PayloadEnvelopeNeeded(parent_root, peer_id));

                    self.delay_block_until_payload_envelope(parent_root, pending_block);
                }
            }
            Ok(BlockAction::DelayUntilSlot(block)) => {
                let processing_timings = processing_timings.delayed();
                let slot = block.item.message().slot();

                let pending_block = PendingBlock {
                    block,
                    origin,
                    processing_timings,
                    tracing_span,
                };

                if slot <= self.store.slot() {
                    self.retry_block(wait_group, pending_block);
                } else if matches!(pending_block.origin, BlockOrigin::Test(_)) {
                    // Spec test runners drop blocks from future slots.
                    // They redeliver them explicitly once the slot arrives.
                    // Delaying here would import blocks the runner never does.
                    debug_with_peers!("test block from future slot dropped: {block_root:?}");
                } else {
                    let pending_block = reply_delayed_block_validation_result(
                        pending_block,
                        Ok(ValidationOutcome::Ignore(false)),
                    );

                    let gossip_id = pending_block.origin.gossip_id_ref().cloned();

                    if let Err(error) = self.try_delay_block_until_slot(pending_block) {
                        debug_with_peers!("failed to delay block until slot: {error}");

                        self.send_to_p2p(P2pMessage::IgnoreWithReason(
                            gossip_id,
                            MutatorIgnoreReason::BlockQueueFull { block_root },
                        ));
                    } else {
                        debug_with_peers!("block delayed until slot: {block_root:?}");
                        trace_with_peers!("block delayed until slot");
                    }
                }
            }
            Ok(BlockAction::WaitForJustifiedState(
                chain_link,
                attester_slashing_results,
                checkpoint,
            )) => {
                let processing_timings = processing_timings.delayed();
                let pending_chain_link = PendingChainLink {
                    chain_link,
                    attester_slashing_results,
                    origin,
                    processing_timings,
                };

                if self.store.contains_checkpoint_state(checkpoint) {
                    self.accept_block(&wait_group, pending_chain_link)?;
                } else {
                    debug_with_peers!(
                        "block waiting for checkpoint state \
                         (block_root: {:?}, checkpoint: {checkpoint:?})",
                        pending_chain_link.chain_link.block_root,
                    );

                    trace_with_peers!(
                        "block waiting for checkpoint state \
                         (block_root: {:?}, block: {:?}, checkpoint: {checkpoint:?})",
                        pending_chain_link.chain_link.block_root,
                        pending_chain_link.chain_link.block,
                    );

                    let waiting = self
                        .waiting_for_checkpoint_states
                        .entry(checkpoint)
                        .or_default();

                    let new = waiting.is_empty();

                    waiting.chain_links.push(pending_chain_link);

                    if new {
                        self.spawn_checkpoint_state_task(wait_group, checkpoint);
                    }
                }
            }
            Err(error) => self.reject_block(error, block_root, origin),
        }

        Ok(())
    }

    #[expect(clippy::too_many_lines)]
    fn accept_aggregate_and_proof(
        &mut self,
        wait_group: &W,
        verify_result: VerifyAggregateAndProofResult<P>,
    ) -> Option<ValidAttestation> {
        let VerifyAggregateAndProofResult { result, origin } = verify_result;

        match result {
            Ok(AggregateAndProofAction::Accept {
                aggregate_and_proof,
                attesting_indices,
                is_subset_aggregate,
            }) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["accepted"]);
                }

                trace_with_peers!(
                    "aggregate and proof accepted \
                     (aggregate_and_proof: {aggregate_and_proof:?}, origin: {origin:?})",
                );

                if origin.send_to_validator() {
                    let attestation = Arc::new(aggregate_and_proof.message().aggregate());

                    self.send_to_validator(ValidatorMessage::ValidAttestation(
                        wait_group.clone(),
                        attestation,
                    ));
                }

                let message = aggregate_and_proof.message();

                self.store.observe_gossip_aggregator(
                    message.aggregator_index(),
                    message.aggregate().data().target.epoch,
                );

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    if is_subset_aggregate {
                        self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                    } else {
                        self.send_to_p2p(P2pMessage::Accept(gossip_id));
                    }
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Accept));

                let valid_attestation = ValidAttestation {
                    data: aggregate_and_proof.message().aggregate().data(),
                    attesting_indices,
                    is_from_block: false,
                };

                return Some(valid_attestation);
            }
            Ok(AggregateAndProofAction::Ignore) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["ignored"]);
                }

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Ignore(false)));
            }
            Ok(AggregateAndProofAction::DelayUntilBlock(aggregate_and_proof, block_root)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["delayed_until_block"]);
                }

                let pending_aggregate_and_proof = PendingAggregateAndProof {
                    aggregate_and_proof,
                    origin,
                };

                self.delay_aggregate_and_proof_until_block(
                    wait_group,
                    pending_aggregate_and_proof,
                    block_root,
                );
            }
            Ok(AggregateAndProofAction::DelayUntilPayload(aggregate_and_proof, block_root)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["delayed_until_payload"]);
                }

                let pending_aggregate_and_proof = PendingAggregateAndProof {
                    aggregate_and_proof,
                    origin,
                };

                if self.store.is_payload_verified(block_root) {
                    self.retry_aggregate_and_proof(wait_group.clone(), pending_aggregate_and_proof);
                } else {
                    let peer_id = pending_aggregate_and_proof
                        .origin
                        .gossip_id_ref()
                        .map(|gossip_id| gossip_id.source);
                    self.send_to_p2p(P2pMessage::PayloadEnvelopeNeeded(block_root, peer_id));

                    self.delayed_until_envelope
                        .entry(block_root)
                        .or_default()
                        .aggregates
                        .push(pending_aggregate_and_proof);
                }
            }
            Ok(AggregateAndProofAction::DelayUntilSlot(aggregate_and_proof)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["delayed_until_slot"]);
                }

                let pending_aggregate_and_proof = PendingAggregateAndProof {
                    aggregate_and_proof,
                    origin,
                };

                self.delay_aggregate_and_proof_until_slot(wait_group, pending_aggregate_and_proof);
            }
            Ok(AggregateAndProofAction::WaitForTargetState(aggregate_and_proof)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["delayed_until_state"]);
                }

                let checkpoint = aggregate_and_proof.message().aggregate().data().target;

                let pending_aggregate_and_proof = PendingAggregateAndProof {
                    aggregate_and_proof,
                    origin,
                };

                if self.store.contains_checkpoint_state(checkpoint) {
                    self.retry_aggregate_and_proof(wait_group.clone(), pending_aggregate_and_proof);
                } else {
                    let waiting = self
                        .waiting_for_checkpoint_states
                        .entry(checkpoint)
                        .or_default();

                    let new = waiting.is_empty();

                    waiting.aggregates.push(pending_aggregate_and_proof);

                    if new {
                        self.spawn_checkpoint_state_task(wait_group.clone(), checkpoint);
                    }
                }
            }
            Err(error) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_aggregate_and_proof(&["rejected"]);
                }

                let downcasted_error = error.downcast_ref::<Error<P>>();

                if matches!(
                    downcasted_error,
                    Some(Error::AggregatorNotInCommittee { .. }),
                ) || matches!(downcasted_error, Some(Error::ValidatorNotAggregator { .. }))
                {
                    debug_with_peers!(
                        "aggregate and proof rejected (error: {error}, origin: {origin:?})"
                    );
                } else {
                    warn_with_peers!(
                        "aggregate and proof rejected (error: {error}, origin: {origin:?})"
                    );
                }

                let (gossip_id, sender) = origin.split();

                if gossip_id.is_some() {
                    self.send_to_p2p(P2pMessage::Reject(
                        gossip_id,
                        MutatorRejectionReason::InvalidAggregateAndProof,
                    ));
                }

                reply_to_http_api(sender, Err(error));
            }
        }

        None
    }

    fn handle_aggregate_and_proof(
        &mut self,
        wait_group: &W,
        verify_result: VerifyAggregateAndProofResult<P>,
    ) -> Result<()> {
        let accepted = self
            .accept_aggregate_and_proof(wait_group, verify_result)
            .into_iter()
            .collect_vec();

        self.apply_attestations(wait_group, accepted, ReorgSource::AggregateAndProof)
    }

    fn handle_aggregate_and_proof_batch(
        &mut self,
        wait_group: &W,
        results: Vec<VerifyAggregateAndProofResult<P>>,
    ) -> Result<()> {
        let mut accepted = Vec::with_capacity(results.len());

        for result in results {
            if let Some(valid_attestation) = self.accept_aggregate_and_proof(wait_group, result) {
                accepted.push(valid_attestation);
            }
        }

        self.apply_attestations(wait_group, accepted, ReorgSource::AggregateAndProof)
    }

    #[expect(clippy::too_many_lines)]
    fn accept_attestation(
        &mut self,
        wait_group: &W,
        result: VerifyAttestationResult<P>,
    ) -> Option<ValidAttestation> {
        match result {
            Ok(AttestationAction::Accept {
                attestation,
                attesting_indices,
            }) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["accepted"]);
                }

                trace_with_peers!("attestation accepted (attestation: {attestation:?})");

                if attestation.origin.should_generate_event() {
                    if let Attestation::Single(single_attestation) = attestation.item.as_ref() {
                        self.event_channels
                            .send_single_attestation_event(*single_attestation);
                    } else {
                        self.event_channels
                            .send_attestation_event(attestation.item.clone_arc());
                    }
                }

                if attestation.origin.send_to_validator() {
                    let attestation = attestation.item.clone_arc();

                    self.send_to_validator(ValidatorMessage::ValidAttestation(
                        wait_group.clone(),
                        attestation,
                    ));
                }

                let is_from_block = attestation.origin.is_from_block();
                let is_singular = attestation.origin.must_be_singular();

                let AttestationItem {
                    item: attestation,
                    origin,
                    ..
                } = attestation;

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Accept(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Accept));

                let valid_attestation = ValidAttestation {
                    data: attestation.data(),
                    attesting_indices,
                    is_from_block,
                };

                if is_singular {
                    let target_epoch = valid_attestation.data.target.epoch;

                    for &validator_index in &valid_attestation.attesting_indices {
                        self.store
                            .observe_gossip_attester(validator_index, target_epoch);
                    }
                }

                return Some(valid_attestation);
            }
            Ok(AttestationAction::Ignore(attestation)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["ignored"]);
                }

                let (gossip_id, sender) = attestation.origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Ignore(false)));
            }
            Ok(AttestationAction::DelayUntilBlock(attestation, block_root)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["delayed_until_block"]);
                }

                self.delay_attestation_until_block(wait_group, attestation, block_root);
            }
            Ok(AttestationAction::DelayUntilPayload(attestation, block_root)) => {
                // Spec test runners drop attestations for payloads that aren't verified yet.
                // Unlike early messages, they never redeliver them.
                // Applying them once the payload arrives would count votes the runner never does.
                if matches!(attestation.origin, AttestationOrigin::Test(_)) {
                    debug_with_peers!("test attestation for unverified payload dropped");
                    return None;
                }

                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["delayed_until_payload"]);
                }

                self.delay_attestation_until_payload(wait_group, attestation, block_root);
            }
            Ok(AttestationAction::DelayUntilSlot(attestation)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["delayed_until_slot"]);
                }

                self.delay_attestation_until_slot(wait_group, attestation);
            }
            Ok(AttestationAction::WaitForTargetState(attestation)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["delayed_until_state"]);
                }

                let checkpoint = attestation.data().target;

                if self.store.contains_checkpoint_state(checkpoint) {
                    self.retry_attestation(wait_group.clone(), attestation);
                } else {
                    let waiting = self
                        .waiting_for_checkpoint_states
                        .entry(checkpoint)
                        .or_default();

                    let new = waiting.is_empty();

                    waiting.attestations.push(attestation);

                    if new {
                        self.spawn_checkpoint_state_task(wait_group.clone(), checkpoint);
                    }
                }
            }
            Err(error) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_attestation(&["rejected"]);
                }

                let source = error.to_string();
                warn_with_peers!("attestation rejected (error: {error:?})");

                let attestation = error.attestation();
                let (gossip_id, sender) = attestation.origin.split();

                if gossip_id.is_some() {
                    self.send_to_p2p(P2pMessage::Reject(
                        gossip_id,
                        MutatorRejectionReason::InvalidAttestation,
                    ));
                }

                reply_to_http_api(sender, Err(anyhow!(source)));
            }
        }

        None
    }

    fn handle_attestation(
        &mut self,
        wait_group: &W,
        result: VerifyAttestationResult<P>,
    ) -> Result<()> {
        let accepted = self
            .accept_attestation(wait_group, result)
            .into_iter()
            .collect_vec();

        self.apply_attestations(wait_group, accepted, ReorgSource::Attestation)
    }

    fn handle_attestation_batch(
        &mut self,
        wait_group: &W,
        results: Vec<VerifyAttestationResult<P>>,
    ) -> Result<()> {
        let mut accepted = Vec::with_capacity(results.len());

        for result in results {
            if let Some(valid_attestation) = self.accept_attestation(wait_group, result) {
                accepted.push(valid_attestation);
            }
        }

        self.apply_attestations(wait_group, accepted, ReorgSource::Attestation)
    }

    fn handle_block_attestations(
        &mut self,
        wait_group: &W,
        from_test_block: bool,
        results: Vec<
            Result<AttestationAction<P, GossipId>, AttestationValidationError<P, GossipId>>,
        >,
    ) -> Result<()> {
        let accepted = results
            .into_iter()
            .filter_map(|result| match result {
                Ok(AttestationAction::Accept {
                    attestation,
                    attesting_indices,
                }) => Some(ValidAttestation {
                    data: attestation.data(),
                    attesting_indices,
                    is_from_block: true,
                }),
                Ok(AttestationAction::Ignore(_)) => None,
                Ok(AttestationAction::DelayUntilBlock(mut attestation, block_root)) => {
                    // Spec test runners retry these as plain attestations.
                    // They lose the from-block exemption from the target epoch check.
                    // Old ones are then dropped instead of counted.
                    if from_test_block {
                        attestation.origin = AttestationOrigin::Test(BlsSetting::Ignored);
                    }

                    self.delay_attestation_until_block(wait_group, attestation, block_root);
                    None
                }
                Ok(AttestationAction::DelayUntilPayload(attestation, block_root)) => {
                    // Spec test runners drop full votes from blocks for unverified payloads.
                    // Delaying and later processing them would count votes the runner never does.
                    if !from_test_block {
                        self.delay_attestation_until_payload(wait_group, attestation, block_root);
                    }

                    None
                }
                Ok(AttestationAction::DelayUntilSlot(attestation)) => {
                    self.delay_attestation_until_slot(wait_group, attestation);
                    None
                }
                Ok(AttestationAction::WaitForTargetState(pending_attestation)) => {
                    let checkpoint = pending_attestation.data().target;

                    if self.store.contains_checkpoint_state(checkpoint) {
                        self.retry_attestation(wait_group.clone(), pending_attestation)
                    } else {
                        let waiting = self
                            .waiting_for_checkpoint_states
                            .entry(checkpoint)
                            .or_default();

                        let new = waiting.is_empty();

                        waiting.attestations.push(pending_attestation);

                        if new {
                            self.spawn_checkpoint_state_task(wait_group.clone(), checkpoint);
                        }
                    }

                    None
                }
                Err(error) => {
                    warn_with_peers!("block attestation rejected (error: {error})");
                    None
                }
            })
            .collect_vec();

        self.apply_attestations(wait_group, accepted, ReorgSource::BlockAttestation)
    }

    fn handle_block_payload_attestations(
        &mut self,
        wait_group: &W,
        results: Vec<VerifyPayloadAttestationResult<P>>,
    ) {
        let accepted = results
            .into_iter()
            .filter_map(|result| match result {
                Ok(PayloadAttestationAction::Accept {
                    payload_attestation,
                    attesting_indices_positions,
                }) => Some(ValidPayloadAttestation {
                    data: payload_attestation.data(),
                    attesting_indices_positions,
                    is_from_block: true,
                }),
                Ok(PayloadAttestationAction::Ignore(_)) => None,
                Ok(PayloadAttestationAction::DelayUntilBlock(payload_attestation, block_root)) => {
                    self.delay_payload_attestation_until_block(
                        wait_group,
                        payload_attestation,
                        block_root,
                    );
                    None
                }
                Err(error) => {
                    warn_with_peers!("block payload attestation rejected (error: {error})");
                    None
                }
            })
            .collect_vec();

        self.apply_payload_attestations(wait_group, accepted);
    }

    // Attestations are applied in bulk because every call to `Store::apply_attestation_batch`
    // propagates balance differences and recomputes the head across the whole unfinalized chain.
    // That work is proportional to the number of unfinalized blocks, so doing it once per
    // attestation instead of once per batch is what makes the mutator fall behind when finality
    // is delayed.
    fn apply_attestations(
        &mut self,
        wait_group: &W,
        valid_attestations: Vec<ValidAttestation>,
        reorg_source: ReorgSource,
    ) -> Result<()> {
        if valid_attestations.is_empty() {
            return Ok(());
        }

        let old_head_root = self.store.head().block_root;
        let head_was_optimistic = self.store.head_node_payload_status().is_optimistic();

        let old_head = self
            .store_mut()
            .apply_attestation_batch(valid_attestations)?;

        self.update_store_snapshot();

        if let Some(old_head) = old_head {
            self.notify_about_reorganization(wait_group.clone(), &old_head, reorg_source);

            self.spawn_preprocess_head_state_for_next_slot_task();
        } else {
            self.send_head_events_if_head_node_became_valid(old_head_root, head_was_optimistic);
        }

        Ok(())
    }

    fn apply_payload_attestations(
        &mut self,
        wait_group: &W,
        valid_payload_attestations: Vec<ValidPayloadAttestation>,
    ) {
        if valid_payload_attestations.is_empty() {
            return;
        }

        let old_head_root = self.store.head().block_root;
        let head_was_optimistic = self.store.head_node_payload_status().is_optimistic();

        let old_head = self
            .store_mut()
            .apply_payload_attestation_batch(valid_payload_attestations);

        self.update_store_snapshot();

        if let Some(old_head) = old_head {
            self.notify_about_reorganization(
                wait_group.clone(),
                &old_head,
                ReorgSource::PayloadAttestation,
            );

            self.spawn_preprocess_head_state_for_next_slot_task();
        } else {
            self.send_head_events_if_head_node_became_valid(old_head_root, head_was_optimistic);
        }
    }

    fn handle_attester_slashing(
        &mut self,
        wait_group: &W,
        result: Result<Vec<ValidatorIndex>>,
        origin: AttesterSlashingOrigin,
    ) -> Result<()> {
        match result {
            Ok(slashable_indices) => {
                let old_head_root = self.store.head().block_root;
                let head_was_optimistic = self.store.head_node_payload_status().is_optimistic();

                let old_head = self
                    .store_mut()
                    .apply_attester_slashing(slashable_indices)?;

                self.update_store_snapshot();

                if let Some(old_head) = old_head {
                    self.notify_about_reorganization(
                        wait_group.clone(),
                        &old_head,
                        ReorgSource::AttesterSlashing,
                    );

                    self.spawn_preprocess_head_state_for_next_slot_task();
                } else {
                    self.send_head_events_if_head_node_became_valid(
                        old_head_root,
                        head_was_optimistic,
                    );
                }
            }
            Err(error) => {
                debug_with_peers!("attester slashing rejected (error: {error}, origin: {origin:?})")
            }
        }

        Ok(())
    }

    #[expect(clippy::too_many_lines)]
    fn handle_blob_sidecar(
        &mut self,
        wait_group: W,
        result: Result<BlobSidecarAction<P>>,
        origin: BlobSidecarOrigin,
        blob_identifier: BlobIdentifier,
        block_seen: bool,
        submission_time: Instant,
    ) {
        match result {
            Ok(BlobSidecarAction::Accept(blob_sidecar)) => {
                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Accept(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Accept));

                self.accept_blob_sidecar(&wait_group, &blob_sidecar);
            }
            Ok(BlobSidecarAction::Ignore(publishable)) => {
                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Ignore(publishable)));
            }
            Ok(BlobSidecarAction::DelayUntilState(blob_sidecar, block_root)) => {
                let slot = blob_sidecar.signed_block_header.message.slot;

                let pending_blob_sidecar = PendingBlobSidecar {
                    blob_sidecar,
                    block_seen,
                    origin,
                    submission_time,
                };

                if let Some(state) =
                    self.state_cache
                        .existing_state_at_slot(&self.store, block_root, slot)
                {
                    self.retry_blob_sidecar(wait_group, pending_blob_sidecar, Some(state));
                } else {
                    debug_with_peers!(
                        "blob sidecar delayed until state at same slot is ready \
                         (block_root: {block_root:?}, slot: {slot})",
                    );
                    trace_with_peers!(
                        "blob sidecar delayed until state at same slot is ready \
                         (blob_sidecar: {:?}, block_root: {block_root:?}, slot: {slot})",
                        pending_blob_sidecar.blob_sidecar,
                    );

                    let peer_id = pending_blob_sidecar.origin.peer_id();

                    let pending_blob_sidecar = reply_delayed_blob_sidecar_validation_result(
                        pending_blob_sidecar,
                        Ok(ValidationOutcome::Ignore(false)),
                    );

                    self.delay_blob_sidecar_until_state(pending_blob_sidecar, block_root);

                    // During block validation the necessary beacon state should have been built
                    // and stored in state cache despite block being delayed due to incomplete data availability.
                    // If there is a delayed until blobs block and no corresponding state in state cache,
                    // it means cache got pruned and it needs to rebuild necessary beacon state.
                    if let Some(delayed_block) = self.take_delayed_until_blobs(block_root) {
                        self.retry_block(wait_group, delayed_block);
                    } else {
                        self.send_to_p2p(P2pMessage::BlockNeeded(block_root, peer_id));
                    }
                }
            }
            Ok(BlobSidecarAction::DelayUntilParent(blob_sidecar)) => {
                let parent_root = blob_sidecar.signed_block_header.message.parent_root;

                let pending_blob_sidecar = PendingBlobSidecar {
                    blob_sidecar,
                    block_seen,
                    origin,
                    submission_time,
                };

                if self.store.contains_block(parent_root) {
                    self.retry_blob_sidecar(wait_group, pending_blob_sidecar, None);
                } else {
                    let peer_id = pending_blob_sidecar.origin.peer_id();

                    self.send_to_p2p(P2pMessage::BlockNeeded(parent_root, peer_id));

                    let pending_blob_sidecar = reply_delayed_blob_sidecar_validation_result(
                        pending_blob_sidecar,
                        Ok(ValidationOutcome::Ignore(false)),
                    );

                    let gossip_id = pending_blob_sidecar.origin.gossip_id_ref().cloned();

                    if let Err(error) =
                        self.try_delay_blob_sidecar_until_parent(pending_blob_sidecar)
                    {
                        debug_with_peers!(
                            "unable to delay blob sidecar until block parent: {parent_root:?} {error:?}"
                        );

                        self.send_to_p2p(P2pMessage::IgnoreWithReason(
                            gossip_id,
                            MutatorIgnoreReason::BlobQueueFull { blob_identifier },
                        ));
                    } else {
                        debug_with_peers!(
                            "blob sidecar delayed until block parent: {parent_root:?}"
                        );
                    }
                }
            }
            Ok(BlobSidecarAction::DelayUntilSlot(blob_sidecar)) => {
                let slot = blob_sidecar.signed_block_header.message.slot;

                let pending_blob_sidecar = PendingBlobSidecar {
                    blob_sidecar,
                    block_seen,
                    origin,
                    submission_time,
                };

                if slot <= self.store.slot() {
                    self.retry_blob_sidecar(wait_group, pending_blob_sidecar, None);
                } else {
                    let pending_blob_sidecar = reply_delayed_blob_sidecar_validation_result(
                        pending_blob_sidecar,
                        Ok(ValidationOutcome::Ignore(false)),
                    );

                    let gossip_id = pending_blob_sidecar.origin.gossip_id_ref().cloned();

                    if let Err(error) = self.try_delay_blob_sidecar_until_slot(pending_blob_sidecar)
                    {
                        debug_with_peers!("failed to delay blob sidecar until slot: {error}");

                        self.send_to_p2p(P2pMessage::IgnoreWithReason(
                            gossip_id,
                            MutatorIgnoreReason::BlobQueueFull { blob_identifier },
                        ));
                    } else {
                        debug_with_peers!("blob sidecar delayed until slot: {slot}");
                    }
                }
            }
            Err(error) => {
                warn_with_peers!("blob sidecar rejected (error: {error}, origin: {origin:?})");

                let (gossip_id, sender) = origin.split();

                self.send_to_p2p(P2pMessage::Reject(
                    gossip_id,
                    MutatorRejectionReason::InvalidBlobSidecar { blob_identifier },
                ));

                reply_to_http_api(sender, Err(error));
            }
        }
    }

    #[expect(clippy::too_many_lines)]
    fn handle_data_column_sidecar(
        &mut self,
        wait_group: W,
        result: Result<DataColumnSidecarAction<P>>,
        origin: DataColumnSidecarOrigin,
        data_column_identifier: DataColumnIdentifier,
        block_seen: bool,
        submission_time: Instant,
    ) {
        match result {
            Ok(DataColumnSidecarAction::Accept(data_column_sidecar)) => {
                if origin.is_from_el() {
                    self.send_to_p2p(P2pMessage::PublishDataColumnSidecar(
                        data_column_sidecar.clone_arc(),
                    ));
                }

                if self
                    .store
                    .accepted_data_column_sidecar(&data_column_sidecar)
                {
                    let (_, sender) = origin.split();

                    reply_to_http_api(sender, Ok(ValidationOutcome::Accept));
                } else {
                    let block_root = data_column_sidecar.beacon_block_root();

                    if self.store.is_forward_synced()
                        && !matches!(
                            origin,
                            DataColumnSidecarOrigin::Own | DataColumnSidecarOrigin::ExecutionLayer
                        )
                        && !self.store.has_requested_blobs_from_el(&block_root)
                        && !self.store.is_sidecars_construction_started(&block_root)
                    {
                        // resolve through the block since post-Gloas sidecar carries no commitments
                        let block_or_sidecar = match self.store.block(block_root) {
                            Some(block) => block.value.clone_arc().into(),
                            None => data_column_sidecar.clone_arc().into(),
                        };

                        self.store_mut()
                            .mark_requested_blobs_from_el(block_root, data_column_sidecar.slot());
                        self.update_store_snapshot();

                        let data_column_identifiers = self
                            .store
                            .sampling_columns()
                            .iter()
                            .map(|index| DataColumnIdentifier {
                                block_root,
                                index: *index,
                            })
                            .collect::<Vec<_>>();

                        self.request_blobs_from_execution_engine(
                            EngineGetBlobsV2Params {
                                block_or_sidecar,
                                data_column_identifiers,
                            }
                            .into(),
                        )
                    }

                    let origin =
                        self.accept_data_column_sidecar(&wait_group, &data_column_sidecar, origin);

                    let (gossip_id, sender) = origin.split();

                    if let Some(gossip_id) = gossip_id {
                        self.send_to_p2p(P2pMessage::Accept(gossip_id));
                    }

                    reply_to_http_api(sender, Ok(ValidationOutcome::Accept));
                }
            }
            Ok(DataColumnSidecarAction::Ignore(publishable)) => {
                debug_with_peers!(
                    "data column sidecar ignored (identifier: {data_column_identifier:?})"
                );

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Ignore(publishable)));
            }
            Ok(DataColumnSidecarAction::DelayUntilState(data_column_sidecar, block_root)) => {
                let slot = data_column_sidecar.slot();

                let pending_data_column_sidecar = PendingDataColumnSidecar {
                    data_column_sidecar,
                    block_seen,
                    origin,
                    submission_time,
                };

                if let Some(state) =
                    self.state_cache
                        .existing_state_at_slot(&self.store, block_root, slot)
                {
                    self.retry_data_column_sidecar(
                        wait_group,
                        pending_data_column_sidecar,
                        Some(state),
                    );
                } else {
                    debug_with_peers!(
                        "data column sidecar delayed until state at same slot is ready \
                        (identifier: {data_column_identifier:?}, slot: {slot})",
                    );

                    let peer_id = pending_data_column_sidecar.origin.peer_id();

                    let pending_data_column_sidecar =
                        reply_delayed_data_column_sidecar_validation_result(
                            pending_data_column_sidecar,
                            Ok(ValidationOutcome::Ignore(false)),
                        );

                    self.delay_data_column_sidecar_until_state(
                        pending_data_column_sidecar,
                        block_root,
                    );

                    // During block validation the necessary beacon state should have been built
                    // and stored in state cache despite block being delayed due to incomplete data availability.
                    // If there is a delayed until blobs block and no corresponding state in state cache,
                    // it means cache got pruned and it needs to rebuild necessary beacon state.
                    if let Some(delayed_block) = self.take_delayed_until_blobs(block_root) {
                        self.retry_block(wait_group, delayed_block);
                    } else {
                        self.send_to_p2p(P2pMessage::BlockNeeded(block_root, peer_id));
                    }
                }
            }
            Ok(DataColumnSidecarAction::DelayUntilParent(data_column_sidecar)) => {
                // Delay until parent block imported only for Fulu data column sidecar
                let Some(parent_root) = data_column_sidecar
                    .pre_gloas()
                    .map(|sidecar| sidecar.signed_block_header.message.parent_root)
                else {
                    return;
                };

                let pending_data_column_sidecar = PendingDataColumnSidecar {
                    data_column_sidecar,
                    block_seen,
                    origin,
                    submission_time,
                };

                if self.store.contains_block_and_data_available(parent_root) {
                    self.retry_data_column_sidecar(wait_group, pending_data_column_sidecar, None);
                } else {
                    let peer_id = pending_data_column_sidecar.origin.peer_id();
                    let gossip_id = pending_data_column_sidecar.origin.gossip_id_ref().cloned();

                    self.send_to_p2p(P2pMessage::BlockNeeded(parent_root, peer_id));

                    let pending_data_column_sidecar =
                        reply_delayed_data_column_sidecar_validation_result(
                            pending_data_column_sidecar,
                            Ok(ValidationOutcome::Ignore(false)),
                        );

                    if let Err(error) =
                        self.try_delay_data_column_sidecar_until_parent(pending_data_column_sidecar)
                    {
                        debug_with_peers!(
                            "failed to delay data column sidecar until parent: {error}"
                        );

                        self.send_to_p2p(P2pMessage::IgnoreWithReason(
                            gossip_id,
                            MutatorIgnoreReason::DataColumnQueueFull {
                                data_column_identifier,
                            },
                        ));
                    } else {
                        debug_with_peers!(
                            "data column sidecar delayed until block parent: \
                            {parent_root:?}, identifier: {data_column_identifier:?}",
                        );
                    }
                }
            }
            Ok(DataColumnSidecarAction::DelayUntilSlot(data_column_sidecar)) => {
                let slot = data_column_sidecar.slot();

                let pending_data_column_sidecar = PendingDataColumnSidecar {
                    data_column_sidecar,
                    block_seen,
                    origin,
                    submission_time,
                };

                if slot <= self.store.slot() {
                    self.retry_data_column_sidecar(wait_group, pending_data_column_sidecar, None);
                } else {
                    let pending_data_column_sidecar =
                        reply_delayed_data_column_sidecar_validation_result(
                            pending_data_column_sidecar,
                            Ok(ValidationOutcome::Ignore(false)),
                        );

                    let gossip_id = pending_data_column_sidecar.origin.gossip_id_ref().cloned();
                    let data_column_identifier = DataColumnIdentifier::from(
                        pending_data_column_sidecar.data_column_sidecar.as_ref(),
                    );

                    if let Err(error) =
                        self.try_delay_data_column_sidecar_until_slot(pending_data_column_sidecar)
                    {
                        debug_with_peers!(
                            "failed to delay data column sidecar until slot: {error}"
                        );

                        self.send_to_p2p(P2pMessage::IgnoreWithReason(
                            gossip_id,
                            MutatorIgnoreReason::DataColumnQueueFull {
                                data_column_identifier,
                            },
                        ));
                    } else {
                        debug_with_peers!("data column sidecar delayed until slot: {slot}");
                    }
                }
            }
            Err(error) => {
                warn_with_peers!(
                    "data column sidecar rejected (error: {error}, origin: {origin:?})"
                );

                let (gossip_id, sender) = origin.split();

                self.send_to_p2p(P2pMessage::Reject(
                    gossip_id,
                    MutatorRejectionReason::InvalidDataColumnSidecar {
                        data_column_identifier,
                    },
                ));

                reply_to_http_api(sender, Err(error));
            }
        }
    }

    #[expect(clippy::too_many_lines)]
    #[expect(clippy::too_many_arguments)]
    fn handle_execution_payload_envelope(
        &mut self,
        wait_group: W,
        result: Result<ExecutionPayloadEnvelopeValidationAction<P>>,
        origin: ExecutionPayloadEnvelopeOrigin,
        payload_envelope_identifier: PayloadEnvelopeIdentifier,
        seen_before_deadline: bool,
        processing_timings: ProcessingTimings,
        tracing_span: Span,
    ) {
        match result {
            Ok(ExecutionPayloadEnvelopeValidationAction::Accept(accepted)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_execution_payload_envelope(&["accepted"]);
                }

                let beacon_block_root = accepted.beacon_block_root();
                let slot = accepted.slot();
                let builder_index = accepted.builder_index();
                let block_hash = accepted.payload_block_hash();
                let should_send_gossip_event = origin.should_send_gossip_event();
                let should_generate_event = origin.should_generate_event();

                if self.store.is_forward_synced() {
                    debug_with_peers!(
                        "execution payload envelope accepted (\
                            block root: {beacon_block_root:?}, \
                            slot: {slot}, \
                            seen before deadline: {seen_before_deadline} \
                        )",
                    );
                } else {
                    debug_with_peers!(
                        "execution payload envelope accepted (\
                            block root: {beacon_block_root:?}, \
                            slot: {slot} \
                        )",
                    );
                }

                if should_generate_event {
                    self.event_channels
                        .send_execution_payload_available_event(slot, beacon_block_root);
                }

                if should_send_gossip_event {
                    self.event_channels.send_execution_payload_gossip_event(
                        slot,
                        builder_index,
                        block_hash,
                        beacon_block_root,
                    );
                }

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Accept(gossip_id));
                }

                reply_payload_envelope_validation_result_to_http_api(
                    sender,
                    Ok(ValidationOutcome::Accept),
                );

                self.accept_execution_payload_envelope(&wait_group, accepted, seen_before_deadline);

                if should_generate_event
                    && let Some(chain_link) = self.store.chain_link(beacon_block_root)
                {
                    self.event_channels.send_execution_payload_event(
                        slot,
                        builder_index,
                        block_hash,
                        beacon_block_root,
                        chain_link.is_optimistic(),
                    );

                    // Emit a second `head_v2` event reflecting the head's payload
                    // status transitioning from empty to full once its envelope is
                    // available.
                    // The head stays optimistic until the execution engine rules on the payload.
                    // Post-Gloas head events go out regardless, like everywhere else.
                    // The events are sent again once the verdict validates the payload.
                    // See `Mutator::handle_potential_head_change`.
                    let head = self.store.head();

                    if head.block_root == beacon_block_root {
                        let head = head.clone();
                        let payload_status = self.store.head_payload_status();
                        let execution_optimistic =
                            self.store.head_node_payload_status().is_optimistic();

                        match self.calculate_dependent_roots(&head) {
                            Ok(dependent_roots) => self.event_channels.send_head_v2_event(
                                &head,
                                payload_status,
                                dependent_roots,
                                execution_optimistic,
                            ),
                            Err(error) => {
                                warn_with_peers!(
                                    "unable to calculate dependent roots for head event: {error}"
                                )
                            }
                        }
                    }
                }
            }
            Ok(ExecutionPayloadEnvelopeValidationAction::Ignore(publishable)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_execution_payload_envelope(&["ignored"]);
                }

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_payload_envelope_validation_result_to_http_api(
                    sender,
                    Ok(ValidationOutcome::Ignore(publishable)),
                );
            }
            Ok(ExecutionPayloadEnvelopeValidationAction::DelayUntilBeaconBlock(
                execution_payload_envelope,
                beacon_block_root,
            )) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_execution_payload_envelope(&["delayed_until_block"]);
                }

                let processing_timings = processing_timings.delayed();
                let pending_envelope = reply_delayed_payload_envelope_validation_result(
                    PendingExecutionPayloadEnvelope {
                        execution_payload_envelope,
                        origin,
                        seen_before_deadline,
                        processing_timings,
                        tracing_span,
                    },
                    Ok(ValidationOutcome::Ignore(false)),
                );

                let gossip_id = pending_envelope.origin.gossip_id_ref().cloned();

                if let Err(error) = self.try_delay_execution_payload_envelope_until_block(
                    wait_group,
                    pending_envelope,
                    beacon_block_root,
                ) {
                    debug_with_peers!(
                        "unable to delay execution payload envelope until block \
                         (beacon_block_root: {beacon_block_root:?}): {error:?}"
                    );

                    self.send_to_p2p(P2pMessage::IgnoreWithReason(
                        gossip_id,
                        MutatorIgnoreReason::ExecutionPayloadEnvelopeQueueFull {
                            payload_envelope_identifier,
                        },
                    ));
                }
            }
            Ok(ExecutionPayloadEnvelopeValidationAction::DelayUntilState(
                execution_payload_envelope,
                beacon_block_root,
            )) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_execution_payload_envelope(&["delayed_until_state"]);
                }

                let slot = execution_payload_envelope.slot();
                let processing_timings = processing_timings.delayed();
                let pending_envelope = PendingExecutionPayloadEnvelope {
                    execution_payload_envelope,
                    origin,
                    seen_before_deadline,
                    processing_timings,
                    tracing_span,
                };

                if let Some(_state) =
                    self.state_cache
                        .existing_state_at_slot(&self.store, beacon_block_root, slot)
                {
                    self.retry_execution_payload_envelope(wait_group, pending_envelope);
                } else {
                    debug_with_peers!(
                        "execution payload envelope delayed until state at same slot is ready \
                         (block_root: {beacon_block_root:?}, slot: {slot})",
                    );

                    let pending_envelope = reply_delayed_payload_envelope_validation_result(
                        pending_envelope,
                        Ok(ValidationOutcome::Ignore(false)),
                    );

                    self.delayed_until_state
                        .entry((beacon_block_root, slot))
                        .or_default()
                        .execution_payload_envelopes
                        .push(pending_envelope);
                }
            }
            Ok(ExecutionPayloadEnvelopeValidationAction::DelayUntilData(
                execution_payload_envelope,
                block,
            )) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_execution_payload_envelope(&["delayed_until_data"]);
                }

                let slot = execution_payload_envelope.slot();
                let block_root = execution_payload_envelope.block_root();
                let processing_timings = processing_timings.delayed();
                let pending_payload_envelope = PendingExecutionPayloadEnvelope {
                    execution_payload_envelope,
                    origin,
                    seen_before_deadline,
                    processing_timings,
                    tracing_span,
                };

                let envelope_data_column_availability = self.block_data_column_availability(
                    &block,
                    self.delayed_until_state
                        .get(&(block_root, slot))
                        .iter()
                        .flat_map(|delayed| delayed.data_column_sidecars.iter())
                        .map(|pending| pending.data_column_sidecar.as_ref()),
                );

                debug_with_peers!(
                    "data availability for block: {:?} with origin: {:?} at slot: {}: {envelope_data_column_availability:?}",
                    block_root,
                    pending_payload_envelope.origin,
                    slot,
                );

                match envelope_data_column_availability {
                    BlockDataColumnAvailability::Complete => {
                        self.retry_execution_payload_envelope(wait_group, pending_payload_envelope);
                    }
                    BlockDataColumnAvailability::AnyPending => {
                        let pending_payload_envelope =
                            reply_delayed_payload_envelope_validation_result(
                                pending_payload_envelope,
                                Ok(ValidationOutcome::Ignore(false)),
                            );

                        self.delay_execution_payload_envelope_until_data(
                            block_root,
                            pending_payload_envelope,
                        );

                        self.take_delayed_until_state(block_root, slot)
                            .unwrap_or_default()
                            .data_column_sidecars
                            .into_iter()
                            .for_each(|pending_data_column| {
                                self.retry_data_column_sidecar(
                                    wait_group.clone(),
                                    pending_data_column,
                                    None,
                                );
                            });
                    }
                    BlockDataColumnAvailability::CompleteWithReconstruction {
                        import_block: import_envelope,
                    } => {
                        if let Some(gossip_id) = pending_payload_envelope.origin.gossip_id() {
                            self.send_to_p2p(P2pMessage::Accept(gossip_id));
                        }

                        let missing_indices = self.store.indices_of_missing_data_columns(&block);

                        if missing_indices.is_empty() {
                            self.retry_execution_payload_envelope(
                                wait_group,
                                pending_payload_envelope,
                            );
                        } else {
                            if !matches!(
                                pending_payload_envelope.origin,
                                ExecutionPayloadEnvelopeOrigin::Own
                            ) && !self.store.is_sidecars_construction_started(&block_root)
                            {
                                self.store
                                    .mark_sidecar_construction_started(block_root, slot);

                                if import_envelope {
                                    for index in missing_indices {
                                        self.mark_sidecar_as_being_reconstructed(
                                            DataColumnIdentifier { block_root, index },
                                            slot,
                                        );
                                    }
                                }

                                self.send_to_pool(PoolMessage::ReconstructDataColumns {
                                    wait_group: wait_group.clone(),
                                    block_root,
                                    block,
                                    slot,
                                    is_from_requested: pending_payload_envelope
                                        .origin
                                        .is_requested(),
                                })
                            }

                            if import_envelope {
                                self.retry_execution_payload_envelope(
                                    wait_group,
                                    pending_payload_envelope,
                                );
                            } else {
                                let pending_payload_envelope =
                                    reply_delayed_payload_envelope_validation_result(
                                        pending_payload_envelope,
                                        Ok(ValidationOutcome::Ignore(false)),
                                    );

                                self.delay_execution_payload_envelope_until_data(
                                    block_root,
                                    pending_payload_envelope,
                                );
                            }
                        }
                    }
                    BlockDataColumnAvailability::Missing(missing_column_indices) => {
                        debug_with_peers!(
                            "payload envelope delayed until sufficient data column sidecars are available \
                             (missing columns: {missing_column_indices:?}, block root: {block_root:?})",
                        );

                        if let Some(gossip_id) = pending_payload_envelope.origin.gossip_id() {
                            self.send_to_p2p(P2pMessage::Accept(gossip_id));
                        }

                        let pending_payload_envelope =
                            reply_delayed_payload_envelope_validation_result(
                                pending_payload_envelope,
                                Ok(ValidationOutcome::Ignore(false)),
                            );

                        if self.store.is_forward_synced()
                            && !self.store.has_requested_blobs_from_el(&block_root)
                            && !self.store.is_sidecars_construction_started(&block_root)
                        {
                            self.store_mut()
                                .mark_requested_blobs_from_el(block_root, slot);
                            self.update_store_snapshot();

                            let data_column_identifiers = missing_column_indices
                                .into_iter()
                                .map(|index| DataColumnIdentifier { block_root, index })
                                .collect_vec();

                            self.request_blobs_from_execution_engine(
                                EngineGetBlobsV2Params {
                                    block_or_sidecar: block.into(),
                                    data_column_identifiers,
                                }
                                .into(),
                            );
                        }

                        self.delay_execution_payload_envelope_until_data(
                            block_root,
                            pending_payload_envelope,
                        );
                    }
                    BlockDataColumnAvailability::Irrelevant => {
                        unreachable!(
                            "envelope of block without blobs should not be delayed until data"
                        )
                    }
                }
            }
            Err(error) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_execution_payload_envelope(&["rejected"]);
                }

                let source = error.to_string();
                warn_with_peers!("execution payload envelope rejected (error: {error:?})");

                let (gossip_id, sender) = origin.split();

                self.send_to_p2p(P2pMessage::Reject(
                    gossip_id,
                    MutatorRejectionReason::InvalidExecutionPayloadEnvelope {
                        payload_envelope_identifier,
                    },
                ));

                reply_payload_envelope_validation_result_to_http_api(sender, Err(anyhow!(source)));
            }
        }
    }

    fn handle_payload_bid(
        &mut self,
        result: Result<ExecutionPayloadBidAction<P>>,
        origin: ExecutionPayloadBidOrigin,
    ) {
        match result {
            Ok(ExecutionPayloadBidAction::Accept(payload_bid)) => {
                trace_with_peers!("payload bid accepted (payload_bid: {payload_bid:?})");

                self.event_channels.send_execution_payload_bid_event(
                    self.store.head().block.phase(),
                    payload_bid.clone_arc(),
                );

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Accept(gossip_id));
                }

                reply_execution_payload_bid_validation_result_to_http_api(
                    sender,
                    Ok(ValidationOutcomeWithReason::Accept),
                );

                self.store_mut().apply_execution_payload_bid(payload_bid);
                self.update_store_snapshot();
            }
            Ok(ExecutionPayloadBidAction::Ignore(message)) => {
                debug_with_peers!("payload bid ignored (reason: {message})");

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_execution_payload_bid_validation_result_to_http_api(
                    sender,
                    Ok(ValidationOutcomeWithReason::Ignore(message)),
                );
            }
            Err(error) => {
                let source = error.to_string();
                warn_with_peers!("payload bid rejected (error: {error:?})",);

                let (gossip_id, sender) = origin.split();

                if gossip_id.is_some() {
                    self.send_to_p2p(P2pMessage::Reject(
                        gossip_id,
                        MutatorRejectionReason::InvalidPayloadBid,
                    ));
                }

                reply_execution_payload_bid_validation_result_to_http_api(
                    sender,
                    Err(anyhow!(source)),
                );
            }
        }
    }

    fn handle_prepared_execution_proof(
        &mut self,
        result: Result<ExecutionProofPreparation>,
        proof_engine: Arc<dyn ProofEngine>,
        origin: ExecutionProofOrigin,
    ) {
        let prepared = match result {
            Ok(ExecutionProofPreparation::Prepared(prepared)) => prepared,
            Ok(ExecutionProofPreparation::Ignore(reason)) => {
                self.handle_execution_proof(
                    Ok(ValidationOutcomeWithReason::Ignore(reason)),
                    origin,
                );
                return;
            }
            Err(error) => {
                // Preparation tasks allow only typed peer-invalid envelope errors here.
                self.handle_execution_proof(Err(error), origin);
                return;
            }
        };

        let beacon_block_root = prepared.signed_message().beacon_block_root;
        let proof_type = prepared.signed_message().proof_type;
        let validator_index = prepared.validator_index();

        match self.store_mut().admit_execution_proof(prepared) {
            ExecutionProofAdmission::Declined(reason) => {
                if reason == ExecutionProofAdmissionDecline::AlreadyVerified {
                    trace_with_peers!(
                        "execution proof ignored (block_root: {beacon_block_root:?}, proof_type: {proof_type}, validator_index: {validator_index}, outcome: IGNORE, reason: {reason:?})",
                    );
                }
                debug_with_peers!("execution proof admission declined (reason: {reason:?})");
                self.handle_execution_proof(
                    Ok(ValidationOutcomeWithReason::Ignore(
                        "execution proof admission declined",
                    )),
                    origin,
                );
            }
            ExecutionProofAdmission::Admitted(admitted) => {
                // Publish BOTH Seen writes before any verifier can enter. Live
                // admission, not the snapshot, remains the authority to dispatch.
                self.update_store_snapshot();
                let task = VerifyExecutionProofTask {
                    admitted,
                    proof_engine,
                    mutator_tx: self.owned_mutator_tx(),
                    origin,
                };
                if let Err(task) = self.thread_pool.try_spawn_execution_proof(task) {
                    let VerifyExecutionProofTask {
                        admitted, origin, ..
                    } = *task;
                    self.handle_completed_execution_proof(admitted.into_local_fault(), origin);
                }
            }
        }
    }

    fn handle_completed_execution_proof(
        &mut self,
        completion: ExecutionProofCompletion,
        origin: ExecutionProofOrigin,
    ) {
        let beacon_block_root = completion.envelope().beacon_block_root;
        let proof_type = completion.envelope().proof_type;
        let validator_index = completion.validator_index();

        let result = match self.store_mut().complete_execution_proof(completion) {
            ExecutionProofCompletionOutcome::Accept => {
                self.update_store_snapshot();
                trace_with_peers!(
                    "execution proof accepted (block_root: {beacon_block_root:?}, proof_type: {proof_type}, validator_index: {validator_index})",
                );
                Ok(ValidationOutcomeWithReason::Accept)
            }
            ExecutionProofCompletionOutcome::Reject => {
                trace_with_peers!(
                    "execution proof rejected (block_root: {beacon_block_root:?}, proof_type: {proof_type}, validator_index: {validator_index}, outcome: REJECT, reason: invalid execution proof)",
                );
                Err(anyhow!("invalid execution proof"))
            }
            ExecutionProofCompletionOutcome::LocalFault => Ok(ValidationOutcomeWithReason::Ignore(
                "local execution proof verification failure",
            )),
            ExecutionProofCompletionOutcome::Discarded(reason) => {
                trace_with_peers!(
                    "execution proof ignored (block_root: {beacon_block_root:?}, proof_type: {proof_type}, validator_index: {validator_index}, outcome: IGNORE, reason: {reason:?})",
                );
                debug_with_peers!("execution proof completion discarded (reason: {reason:?})");
                Ok(ValidationOutcomeWithReason::Ignore(
                    "execution proof completion is no longer applicable or needed",
                ))
            }
        };
        self.handle_execution_proof(result, origin);
    }

    fn handle_execution_proof(
        &self,
        result: Result<ValidationOutcomeWithReason>,
        origin: ExecutionProofOrigin,
    ) {
        match result {
            Ok(ValidationOutcomeWithReason::Accept) => {
                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Accept(gossip_id));
                }

                reply_execution_proof_validation_result_to_http_api(
                    sender,
                    Ok(ValidationOutcomeWithReason::Accept),
                );
            }
            Ok(ValidationOutcomeWithReason::Ignore(message)) => {
                debug_with_peers!("execution proof ignored (reason: {message})");

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_execution_proof_validation_result_to_http_api(
                    sender,
                    Ok(ValidationOutcomeWithReason::Ignore(message)),
                );
            }
            Err(error) => {
                let source = error.to_string();
                warn_with_peers!("execution proof rejected (error: {error:?})",);

                let (gossip_id, sender) = origin.split();

                if gossip_id.is_some() {
                    self.send_to_p2p(P2pMessage::Reject(
                        gossip_id,
                        MutatorRejectionReason::InvalidExecutionProof,
                    ));
                }

                reply_execution_proof_validation_result_to_http_api(sender, Err(anyhow!(source)));
            }
        }
    }

    fn accept_payload_attestation(
        &mut self,
        wait_group: &W,
        result: VerifyPayloadAttestationResult<P>,
    ) -> Option<ValidPayloadAttestation> {
        match result {
            Ok(PayloadAttestationAction::Accept {
                payload_attestation,
                attesting_indices_positions,
            }) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_payload_attestation(&["accepted"]);
                }

                trace_with_peers!(
                    "payload attestation accepted (payload_attestation: {payload_attestation:?})"
                );

                let PayloadAttestationItem {
                    item: payload_attestation,
                    origin,
                    ..
                } = payload_attestation;
                let data = payload_attestation.data();
                let is_from_block = origin.is_from_block();

                if let Some(payload_attestation_message) = payload_attestation.message() {
                    if origin.should_generate_event() {
                        self.event_channels.send_payload_attestation_event(
                            self.store.head().block.phase(),
                            payload_attestation_message,
                        );
                    }

                    if origin.send_to_validator() {
                        self.send_to_validator(ValidatorMessage::ValidPayloadAttestation(
                            wait_group.clone(),
                            payload_attestation_message.clone_arc(),
                        ));
                    }
                }

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Accept(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Accept));

                let valid_payload_attestation = ValidPayloadAttestation {
                    data,
                    attesting_indices_positions,
                    is_from_block,
                };

                return Some(valid_payload_attestation);
            }
            Ok(PayloadAttestationAction::Ignore(payload_attestation)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_payload_attestation(&["ignored"]);
                }

                let (gossip_id, sender) = payload_attestation.origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Ignore(false)));
            }
            Ok(PayloadAttestationAction::DelayUntilBlock(payload_attestation, block_root)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_payload_attestation(&["delayed_until_block"]);
                }

                let peer_id = payload_attestation.origin.peer_id();
                self.send_to_p2p(P2pMessage::PayloadEnvelopeNeeded(block_root, peer_id));

                self.delay_payload_attestation_until_block(
                    wait_group,
                    payload_attestation,
                    block_root,
                );
            }
            Err(error) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_payload_attestation(&["rejected"]);
                }

                let source = error.to_string();
                warn_with_peers!("payload attestation rejected (error: {error:?})",);

                let payload_attestation = error.payload_attestation();
                let (gossip_id, sender) = payload_attestation.origin.split();

                if gossip_id.is_some() {
                    self.send_to_p2p(P2pMessage::Reject(
                        gossip_id,
                        MutatorRejectionReason::InvalidPayloadAttestation,
                    ));
                }

                reply_to_http_api(sender, Err(anyhow!(source)));
            }
        }

        None
    }

    fn handle_payload_attestation(
        &mut self,
        wait_group: &W,
        result: VerifyPayloadAttestationResult<P>,
    ) {
        let accepted = self
            .accept_payload_attestation(wait_group, result)
            .into_iter()
            .collect_vec();

        self.apply_payload_attestations(wait_group, accepted);
    }

    fn handle_payload_attestation_batch(
        &mut self,
        wait_group: &W,
        results: Vec<VerifyPayloadAttestationResult<P>>,
    ) {
        let mut accepted = Vec::with_capacity(results.len());

        for result in results {
            if let Some(valid_payload_attestation) =
                self.accept_payload_attestation(wait_group, result)
            {
                accepted.push(valid_payload_attestation);
            }
        }

        self.apply_payload_attestations(wait_group, accepted);
    }

    fn handle_proposer_preferences(
        &mut self,
        wait_group: &W,
        result: Result<ProposerPreferencesAction>,
        origin: ProposerPreferencesOrigin,
    ) {
        match result {
            Ok(ProposerPreferencesAction::Accept(signed_preferences)) => {
                let phase = self
                    .store
                    .chain_config()
                    .phase_at_slot::<P>(signed_preferences.message.proposal_slot);

                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_proposer_preferences(&["accepted"]);
                }

                trace_with_peers!(
                    "proposer preferences accepted (validator_index: {}, proposal_slot: {})",
                    signed_preferences.message.validator_index,
                    signed_preferences.message.proposal_slot
                );

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Accept(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Accept));

                self.event_channels
                    .send_proposer_preferences_event(phase, signed_preferences.clone_arc());

                self.store_mut()
                    .apply_proposer_preferences(signed_preferences);

                self.update_store_snapshot();
            }
            Ok(ProposerPreferencesAction::Ignore(publishable)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_proposer_preferences(&["ignored"]);
                }

                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_to_http_api(sender, Ok(ValidationOutcome::Ignore(publishable)));
            }
            Ok(ProposerPreferencesAction::DelayUntilBlock(signed_preferences)) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_proposer_preferences(&["delayed_until_block"]);
                }

                let dependent_root = signed_preferences.message.dependent_root;

                self.delay_proposer_preferences_until_block(
                    wait_group.clone(),
                    PendingProposerPreferences {
                        signed_preferences,
                        origin,
                    },
                    dependent_root,
                );
            }
            Err(error) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.register_mutator_proposer_preferences(&["rejected"]);
                }

                warn_with_peers!("proposer preferences rejected (error: {error:?})");

                let (gossip_id, sender) = origin.split();

                if gossip_id.is_some() {
                    self.send_to_p2p(P2pMessage::Reject(
                        gossip_id,
                        MutatorRejectionReason::InvalidProposerPreferences,
                    ));
                }

                reply_to_http_api(sender, Err(anyhow!(error)));
            }
        }
    }

    fn handle_checkpoint_state(
        &mut self,
        wait_group: &W,
        checkpoint: Checkpoint,
        checkpoint_state: Option<Arc<BeaconState<P>>>,
    ) -> Result<()> {
        let Some(state) = checkpoint_state else {
            // The data required to compute the checkpoint state has been pruned.
            // The state and any objects waiting for it are no longer needed.
            // The objects waiting for it should have been pruned as well.
            // No further action is necessary.
            return Ok(());
        };

        let Some(waiting) = self.waiting_for_checkpoint_states.remove(&checkpoint) else {
            // The corresponding element in `Mutator.waiting_for_checkpoint_states` has been pruned.
            return Ok(());
        };

        self.store_mut().insert_checkpoint_state(checkpoint, state);

        // `Mutator::accept_block` also updates the snapshot, but only if the block isn't orphaned.
        self.update_store_snapshot();

        let WaitingForCheckpointState {
            ticks,
            chain_links,
            aggregates,
            attestations,
        } = waiting;

        for tick in ticks {
            self.retry_tick(wait_group, tick)?;
        }

        for pending_chain_link in chain_links {
            self.accept_block(wait_group, pending_chain_link)?;
        }

        for pending_aggregate_and_proof in aggregates {
            self.retry_aggregate_and_proof(wait_group.clone(), pending_aggregate_and_proof);
        }

        // This spawns a separate task for each attestation.
        // Retrying them in batches did not improve performance during initial development.
        for pending_attestation in attestations {
            self.retry_attestation(wait_group.clone(), pending_attestation);
        }

        Ok(())
    }

    fn handle_finish_persisting_blob_sidecars(
        &mut self,
        wait_group: W,
        persisted_blob_ids: Vec<BlobIdentifier>,
    ) {
        self.store_mut().mark_persisted_blobs(persisted_blob_ids);

        self.update_store_snapshot();

        if self.store.has_unpersisted_blob_sidecars() {
            self.spawn(PersistBlobSidecarsTask {
                store_snapshot: self.owned_store(),
                storage: self.storage.clone_arc(),
                mutator_tx: self.owned_mutator_tx(),
                wait_group,
                metrics: self.metrics.clone(),
            });
        }
    }

    fn handle_finish_persisting_data_column_sidecars(
        &mut self,
        _wait_group: W,
        persisted_data_column_ids: Vec<DataColumnIdentifier>,
        slot: Slot,
    ) {
        self.store_mut()
            .mark_persisted_data_columns(persisted_data_column_ids);

        self.store_mut().prune_persisted_data_columns(slot);

        self.update_store_snapshot();
    }

    fn handle_finish_archiving_finalized(
        &mut self,
        wait_group: &W,
        new_anchor_index: usize,
        saved: bool,
    ) -> Result<()> {
        self.is_archiving_finalized = false;

        if !saved {
            self.consecutive_failed_archives = self.consecutive_failed_archives.saturating_add(1);

            // The blocks stay for the next finalization to retry.
            if self.consecutive_failed_archives < MAX_CONSECUTIVE_FAILED_ARCHIVES {
                return Ok(());
            }

            error_with_peers!(
                "dropping finalized blocks that failed to be archived \
                 {MAX_CONSECUTIVE_FAILED_ARCHIVES} times in a row",
            );
        }

        self.consecutive_failed_archives = 0;

        self.store_mut().archive_finalized(new_anchor_index);
        self.update_store_snapshot();
        self.archive_finalized(wait_group)
    }

    fn handle_finish_persisting_execution_payload_envelopes(
        &mut self,
        wait_group: W,
        persisted_block_roots: Vec<H256>,
    ) {
        self.store_mut()
            .mark_persisted_envelopes(persisted_block_roots);

        self.update_store_snapshot();

        if self.store.has_unpersisted_envelopes() {
            self.spawn(PersistExecutionPayloadEnvelopesTask {
                store_snapshot: self.owned_store(),
                storage: self.storage.clone_arc(),
                mutator_tx: self.owned_mutator_tx(),
                wait_group,
                metrics: self.metrics.clone(),
            });
        }
    }

    fn handle_reconstructed_missing_columns(
        &mut self,
        wait_group: &W,
        block_root: H256,
        block: &Arc<SignedBeaconBlock<P>>,
        mut data_column_sidecars: Vec<Arc<DataColumnSidecar<P>>>,
    ) {
        let missing_indices = self.store.indices_of_missing_data_columns(block);
        if missing_indices.is_empty() {
            return;
        }

        // > The following data column sidecars, where they exist, MUST be sent in (slot, column_index) order.
        data_column_sidecars.sort_by_key(|sidecar| (sidecar.slot(), sidecar.index()));

        debug_with_peers!(
            "storing data column sidecars from reconstruction (block: {block_root:?}, columns: {missing_indices:?})",
        );

        for data_column_sidecar in data_column_sidecars {
            if missing_indices.contains(&data_column_sidecar.index()) {
                self.accept_data_column_sidecar(
                    wait_group,
                    &data_column_sidecar,
                    DataColumnSidecarOrigin::Own,
                );
            }

            if self.store.is_forward_synced() {
                self.send_to_p2p(P2pMessage::PublishDataColumnSidecar(data_column_sidecar));
            }
        }
    }

    fn handle_notified_forkchoice_update_result(
        &mut self,
        wait_group: &W,
        head_execution_block_hash: ExecutionBlockHash,
        payload_status: PayloadStatusV1,
    ) {
        // INVALID condemns the head payload, same as from `engine_newPayload`.
        // `latest_valid_hash` alone only validates its ancestors.
        // Post-Gloas the hash may be an ancestor's payload if the head is empty.
        // The lookup finds the block that carries it.
        if payload_status.status.is_invalid()
            && let Some(chain_link) = self
                .store
                .unfinalized_chain_link_by_execution_block_hash(head_execution_block_hash)
        {
            let beacon_block_root = chain_link.block_root;

            self.handle_notified_new_payload(
                wait_group,
                beacon_block_root,
                head_execution_block_hash,
                payload_status,
            );

            return;
        }

        let Some(latest_valid_hash) = payload_status.latest_valid_hash else {
            return;
        };

        let old_head = self.store.head().clone();
        let head_was_optimistic = self.store.head_node_payload_status().is_optimistic();

        self.store_mut()
            .update_chain_payload_statuses(latest_valid_hash, None);
        self.update_store_snapshot();

        self.handle_potential_head_change(wait_group, &old_head, head_was_optimistic);
    }

    fn handle_notified_new_payload(
        &mut self,
        wait_group: &W,
        beacon_block_root: H256,
        execution_block_hash: ExecutionBlockHash,
        payload_status: PayloadStatusV1,
    ) {
        if !self.store.contains_block(beacon_block_root) {
            self.delay_payload_status_until_block(beacon_block_root, payload_status);

            return;
        }

        let old_head = self.store.head().clone();
        let head_was_optimistic = self.store.head_node_payload_status().is_optimistic();
        let latest_valid_hash = payload_status.latest_valid_hash;

        let payload_action = if let Some(valid_hash) = latest_valid_hash {
            self.store_mut()
                .update_chain_payload_statuses(valid_hash, Some(execution_block_hash))
        } else {
            PayloadAction::Accept
        };

        let status = payload_status.status;

        if status.is_valid() {
            // According to the [Engine API specification], if the payload is valid,
            // `latest_valid_hash` must equal `execution_block_hash`.
            //
            // [Engine API specification]: https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#payload-validation
            if latest_valid_hash != Some(execution_block_hash) {
                warn_with_peers!(
                    "execution engine returned inconsistent response \
                     (execution_block_hash: {execution_block_hash:?}, \
                     payload_status: {payload_status:?})",
                );
            }

            // The call to `Store::update_chain_payload_statuses` above will set the payload
            // statuses of the block and its ancestors to `PayloadStatus::Valid`.
        } else if status.is_invalid() {
            self.store_mut()
                .invalidate_payload_and_descendant_payloads(beacon_block_root);
        } else {
            return;
        }

        match payload_action {
            PayloadAction::Accept => {}
            PayloadAction::DelayUntilBlock(hash) => {
                if !hash.is_zero() {
                    self.delayed_until_payload
                        .entry(hash)
                        .or_default()
                        .push((payload_status, self.store.slot()));
                }
            }
        }

        self.update_store_snapshot();

        // Do not send API events about optimistic blocks.
        // Vouch treats all head events as non-optimistic.
        if let Some(chain_link) = self
            .store
            .unfinalized_chain_link_by_execution_block_hash(execution_block_hash)
            && chain_link.is_valid()
            && !chain_link.is_post_gloas()
        {
            self.event_channels.send_block_event(
                chain_link.slot(),
                chain_link.block_root,
                false,
                None,
            );
        }

        self.handle_potential_head_change(wait_group, &old_head, head_was_optimistic);
    }

    fn handle_potential_head_change(
        &self,
        wait_group: &W,
        old_head: &ChainLink<P>,
        head_was_optimistic: bool,
    ) {
        let head = self.store.head();
        let head_changed = head.block_root != old_head.block_root;

        // Do not send API events about optimistic blocks.
        // Vouch treats all head events as non-optimistic.
        // Post-Gloas head events go out regardless, so they are sent again here
        // to tell clients the head is no longer optimistic.
        if self.head_node_became_valid(old_head.block_root, head_was_optimistic) {
            self.send_head_events(head);

            // Post-Gloas the validator polls payload statuses itself.
            // The call to `Store::notify_about_reorganization` below sends
            // a `ValidatorMessage::Head` message if the head changed.
            if !head.is_post_gloas() {
                self.send_to_validator(ValidatorMessage::Head(wait_group.clone(), head.clone()));
            }
        }

        if head_changed {
            self.notify_about_reorganization(
                wait_group.clone(),
                old_head,
                ReorgSource::PayloadResponse,
            );

            self.spawn_preprocess_head_state_for_next_slot_task();
        }
    }

    // Post-Gloas fork choice can move the head between the nodes of one block.
    // That is no reorg, but the head can stop being optimistic:
    // its full node rests on its own unvalidated payload, its empty node on a valid one.
    // Head events go out again then, like in `handle_potential_head_change`.
    // They also send a chain reorg event held back while the head was optimistic.
    fn send_head_events_if_head_node_became_valid(
        &self,
        old_head_root: H256,
        head_was_optimistic: bool,
    ) {
        if self.head_node_became_valid(old_head_root, head_was_optimistic) {
            self.send_head_events(self.store.head());
        }
    }

    // Whether the head block stayed the same and the payload its node rests on became valid.
    // `head_was_optimistic` is about the payload the head rests on.
    // Post-Gloas that depends on the node fork choice resolves the head to.
    fn head_node_became_valid(&self, old_head_root: H256, head_was_optimistic: bool) -> bool {
        self.store.head().block_root == old_head_root
            && head_was_optimistic
            && self.store.head_node_payload_status().is_valid()
    }

    fn handle_stop(&self, save_to_storage: bool) -> Result<()> {
        // Send messages to services directly (i.e. not using wrapper methods)
        // to ensure the messages are sent unconditionally
        AttestationVerifierMessage::Stop.send(&self.attestation_verifier_tx);
        P2pMessage::Stop.send(&self.p2p_tx);
        PoolMessage::Stop.send(&self.pool_tx);
        SubnetMessage::Stop.send(&self.subnet_tx);
        ValidatorMessage::Stop.send(&self.validator_tx);

        self.execution_engine.stop();

        if save_to_storage {
            let slots = self.storage.append(
                self.store.unfinalized_canonical_chain(),
                self.store.finalized().iter(),
                &self.store,
            )?;

            info_with_peers!(
                "chain saved (finalized blocks: {}, unfinalized blocks: {})",
                slots.finalized.len(),
                slots.unfinalized.len(),
            );

            debug_with_peers!("appended block slots: {slots:?}");
        }

        Ok(())
    }

    fn handle_store_sampling_columns(&mut self, sampling_columns: HashSet<ColumnIndex>) {
        debug_with_peers!(
            "storing index of column sidecars to sample: {sampling_columns:?} \
            for further data availability check",
        );

        self.store_mut().store_sampling_columns(sampling_columns);
        self.update_store_snapshot();
    }

    #[expect(clippy::cognitive_complexity)]
    #[expect(clippy::too_many_lines)]
    #[instrument(level = "debug", skip_all)]
    fn accept_block(
        &mut self,
        wait_group: &W,
        pending_chain_link: PendingChainLink<P>,
    ) -> Result<()> {
        let PendingChainLink {
            chain_link,
            attester_slashing_results,
            origin,
            processing_timings,
        } = pending_chain_link;

        let processing_timings = processing_timings.processing();
        let block_root = chain_link.block_root;
        let block = &chain_link.block;

        // Check if the block is already present in the store.
        // This is done here primarily to avoid spawning redundant `BlockAttestationsTask`s.
        if self.store.contains_block(block_root) {
            let (gossip_id, sender) = origin.split();

            if let Some(gossip_id) = gossip_id {
                self.send_to_p2p(P2pMessage::Ignore(gossip_id));
            }

            reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Ignore(true)));

            return Ok(());
        }

        // A block may become orphaned while being processed.
        // The fork choice store is not designed to accommodate blocks like that.
        if block.message().slot() <= self.store.finalized_slot() {
            debug_with_peers!(
                "block became orphaned while being processed \
                 (block_root: {block_root:?}, \
                  origin: {origin:?}, finalized slot: {})",
                self.store.finalized_slot(),
            );
            trace_with_peers!(
                "block became orphaned while being processed \
                 (block_root: {block_root:?}, block: {block:?}, \
                  origin: {origin:?}, finalized slot: {})",
                self.store.finalized_slot(),
            );

            let (gossip_id, sender) = origin.split();

            if let Some(gossip_id) = gossip_id {
                self.send_to_p2p(P2pMessage::Ignore(gossip_id));
            }

            reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Ignore(false)));

            return Ok(());
        }

        // The block's parent may have been orphaned while the block was being processed or waiting
        // in a delay queue. The fork choice store is not designed to insert blocks with missing parents.
        let parent_root = chain_link.parent_root();
        if !self.store.contains_block(parent_root) {
            debug_with_peers!(
                "block's parent was orphaned while block was being processed \
                 (block_root: {block_root:?}, parent_root: {parent_root:?}, \
                  origin: {origin:?})",
            );

            let (gossip_id, sender) = origin.split();

            if let Some(gossip_id) = gossip_id {
                self.send_to_p2p(P2pMessage::Ignore(gossip_id));
            }

            reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Ignore(false)));

            return Ok(());
        }

        debug_with_peers!("block accepted (block_root: {block_root:?}, origin: {origin:?})");
        trace_with_peers!(
            "block accepted (block_root: {block_root:?}, block: {block:?}, origin: {origin:?})"
        );

        let block_slot = chain_link.slot();

        if let Some(existing_link) = self.store.chain_link_before_or_at(block_slot)
            && block_slot == existing_link.slot()
        {
            warn_with_peers!(
                "the store accepted a new block at slot {block_slot}, \
                    although it already contains one at the same slot on the canonical chain \
                    (existing canonical block: {:?}, new block: {:?})",
                existing_link.block,
                chain_link.block,
            );
        }

        let block = block.clone_arc();
        let is_post_gloas = chain_link.is_post_gloas();
        let is_valid = chain_link.is_valid();
        let post_state = chain_link.state.clone();
        let changes = self.store_mut().apply_block(chain_link)?;

        // Verify the deposit signatures now, a block at a time.
        // The Gloas fork transition would otherwise verify the whole queue at once.
        if !is_post_gloas
            && self.store.chain_config().gloas_fork_epoch != FAR_FUTURE_EPOCH
            && let Some(state) = post_state
        {
            self.spawn(CacheDepositSignaturesTask {
                config: self.store.owned_chain_config(),
                pubkey_cache: self.pubkey_cache.clone_arc(),
                state,
                wait_group: wait_group.clone(),
                metrics: self.metrics.clone(),
            });
        }
        let insertion_time = Instant::now();

        let unfinalized_states_in_memory = self.store.store_config().unfinalized_states_in_memory;
        let head_slot = self.store.head().slot();

        let block_epoch = misc::compute_epoch_at_slot::<P>(block_slot);
        let parent_epoch = self
            .store
            .chain_link(block.message().parent_root())
            .map(|chain_link| misc::compute_epoch_at_slot::<P>(chain_link.slot()));

        if parent_epoch
            .map(|epoch| epoch < block_epoch)
            .unwrap_or(true)
        {
            if !changes.is_finalized_checkpoint_updated() {
                self.spawn_state_cache_prune_task(true, wait_group.clone());
            }

            info_with_peers!("unloading old beacon states (head slot: {head_slot})");

            let unloaded = self
                .store_mut()
                .unload_old_states(unfinalized_states_in_memory);

            let store = self.owned_store();
            let storage = self.storage.clone_arc();
            let wait_group = wait_group.clone();

            if !unloaded.is_empty() {
                Builder::new()
                .name("store-unloader".to_owned())
                .spawn(move || {
                    let finalized_validators = store.finalized_validators();

                    debug_with_peers!("persisting unloaded old beacon states…");

                    let states_with_block_roots = unloaded
                        .iter()
                        .map(|chain_link| (chain_link.state(&store), chain_link.block_root));

                    match storage.append_states(states_with_block_roots, &*finalized_validators) {
                        Ok(slots) => {
                            debug_with_peers!(
                                "unloaded old beacon states persisted \
                                 (state slots: {slots:?})",
                            )
                        }
                        Err(error) => {
                            error_with_peers!("persisting unloaded old beacon states to storage failed: {error:?}")
                        }
                    }

                    drop(wait_group);
                })?;
            }
        }

        let ProcessingTimings {
            delay_duration,
            submission_time,
            ..
        } = processing_timings;

        let insertion_duration = insertion_time.duration_since(submission_time);
        let processing_duration = insertion_duration.saturating_sub(delay_duration);

        features::log!(
            LogBlockProcessingTime,
            "block {block_root:?} inserted in {insertion_duration:?}, \
            processed in {processing_duration:?}",
        );

        if let Some(metrics) = self.metrics.as_ref() {
            metrics
                .block_insertion_times
                .observe(insertion_duration.as_secs_f64());

            metrics
                .block_processing_times
                .observe(processing_duration.as_secs_f64());
        }

        if let Some(hash) = block.execution_block_hash()
            && let Some(payload_statuses) = self.delayed_until_payload.remove(&hash)
        {
            for (payload_status, _) in payload_statuses {
                self.handle_notified_new_payload(wait_group, block_root, hash, payload_status);
            }
        }

        let from_test_block = matches!(origin, BlockOrigin::Test(_));

        // TODO(Grandine Team): Performing the validation here results in the block being added to the
        //                      fork choice store even though it is already known to be invalid.
        //                      The validation should be in `Store::validate_block`,
        //                      but that makes it harder to retry payload statuses.
        //                      That is also why the message sending and task spawning was moved here.
        //                      One possible solution is to check `Mutator.delayed_until_payload` in
        //                      this method before calling `Store::apply_block`.
        // > - If `execution_payload` verification of block's parent by an execution node is *not*
        // >   complete:
        // >   - [REJECT] The block's parent (defined by `block.parent_root`) passes all validation
        // >     (excluding execution node verification of the `block.body.execution_payload`).
        // > - otherwise:
        // >   - [IGNORE] The block's parent (defined by `block.parent_root`) passes all validation
        // >     (including execution node verification of the `block.body.execution_payload`).
        // > Changes in Gloas:
        // > - If `execution_payload` verification of block's execution payload parent by an execution node **is complete**:
        // >   - [REJECT] The block's execution payload parent (defined by `bid.parent_block_hash`) passes all validation.
        if let Some(body) = block.message().body().with_payload_bid() {
            let parent_block_hash = body
                .signed_execution_payload_bid()
                .message
                .parent_block_hash;

            // Request payload envelope if fork choice hasn't accepted yet.
            if !origin.is_own() && !self.store.is_payload_verified(block_root) {
                let peer_id = origin.peer_id();
                self.send_to_p2p(P2pMessage::PayloadEnvelopeNeeded(block_root, peer_id));
            }

            // Only check in unfinalized path
            if self
                .store
                .unfinalized_chain_link_by_execution_block_hash(parent_block_hash)
                .is_some_and(ChainLink::is_invalid)
            {
                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Ignore(gossip_id));
                }

                reply_block_validation_result_to_http_api(
                    sender,
                    Ok(ValidationOutcome::Ignore(false)),
                );
            } else {
                let (gossip_id, sender) = origin.split();

                if let Some(gossip_id) = gossip_id {
                    self.send_to_p2p(P2pMessage::Accept(gossip_id));
                }

                reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Accept));
            }
        } else if self
            .store
            .chain_link(block_root)
            .is_some_and(ChainLink::is_invalid)
        {
            let (gossip_id, sender) = origin.split();

            if let Some(gossip_id) = gossip_id {
                self.send_to_p2p(P2pMessage::Ignore(gossip_id));
            }

            reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Ignore(false)));
        } else {
            let (gossip_id, sender) = origin.split();

            if let Some(gossip_id) = gossip_id {
                self.send_to_p2p(P2pMessage::Accept(gossip_id));
            }

            reply_block_validation_result_to_http_api(sender, Ok(ValidationOutcome::Accept));
        }

        self.maybe_spawn_block_attestations_task(wait_group, block_root, &block, from_test_block);
        self.maybe_spawn_block_payload_attestations_task(wait_group, block_root, &block);

        if changes.is_finalized_checkpoint_updated() {
            self.has_pending_archive_tasks = false;

            self.archive_finalized(wait_group)?;
            self.prune_delayed_until_payload();
            self.persist_pubkey_cache(wait_group);
            self.spawn_state_cache_prune_task(false, wait_group.clone());

            let finalized_slot = self.store.finalized_slot();

            self.event_channels.prune_after_finalization(finalized_slot);

            if block.phase().is_peerdas_activated() {
                self.try_spawn_persist_data_columns_task(finalized_slot, wait_group.clone());
            }
        }

        let slashable_indices = attester_slashing_results
            .into_iter()
            .flat_map(|result| {
                let origin = AttesterSlashingOrigin::Block;

                result
                    .map_err(|error| {
                        debug_with_peers!(
                            "attester slashing rejected (error: {error}, origin: {origin:?})"
                        )
                    })
                    .unwrap_or_default()
            })
            .collect_vec();

        if !slashable_indices.is_empty() {
            self.store_mut()
                .apply_attester_slashing(slashable_indices)?;
        }

        // The snapshot should be updated before spawning tasks to retry delayed objects or
        // notifying other components to ensure that they cannot observe the store in an
        // inconsistent state.
        self.update_store_snapshot();

        // Pre-Gloas, do not send API events about optimistic blocks.
        // Clients treat all head events as non-optimistic.
        // Post-Gloas they go out regardless, flagged like head events.
        // A new block has no payload of its own yet.
        // It is optimistic if the payload it rests on is.
        if is_valid || is_post_gloas {
            let execution_optimistic = self
                .store
                .node_payload_status(block_root, false)
                .is_some_and(PayloadStatus::is_optimistic);

            self.event_channels.send_block_event(
                block_slot,
                block_root,
                execution_optimistic,
                block.message().payload_bid(),
            );
        }

        if let Some(objects) = self.take_delayed_until_block(block_root) {
            debug_with_peers!("retrying objects delayed until block {block_root:?}");
            debug_with_peers!(
                "retrying {} pending data column sidecars after block {block_root:?} imported",
                objects.data_column_sidecars.len(),
            );
            self.retry_delayed(objects, wait_group);
        }

        if changes.is_finalized_checkpoint_updated() {
            self.notify_about_finalized_checkpoint();
            self.prune_delayed_after_finalization();
        }

        match changes {
            ApplyBlockChanges::CanonicalChainExtended { .. } => {
                let new_head = self.store.head().clone();

                if let Some(metrics) = self.metrics.as_ref() {
                    Self::track_head_metrics(&new_head, metrics);
                }

                self.send_to_p2p(P2pMessage::HeadChanged(new_head.block_root));

                if new_head.is_valid() || new_head.is_post_gloas() {
                    self.send_head_events(&new_head);

                    self.send_to_validator(ValidatorMessage::Head(
                        wait_group.clone(),
                        new_head.clone(),
                    ));
                }

                // After Gloas, notify FCU should only be called when payload is processed or block produced
                if self.store.phase() < Phase::Gloas {
                    self.notify_forkchoice_updated(&new_head);
                }

                // Keep the old FCU call in post-Gloas phases to help
                // with recovering from temporary EL problems
                self.notify_forkchoice_updated(&new_head);

                self.maybe_spawn_preprocess_head_state_for_current_slot_task(block_slot);
                self.spawn_preprocess_head_state_for_next_slot_task();
            }
            ApplyBlockChanges::Reorganized { old_head, .. } => {
                self.notify_about_reorganization(wait_group.clone(), &old_head, ReorgSource::Block);
                self.maybe_spawn_preprocess_head_state_for_current_slot_task(block_slot);
                self.spawn_preprocess_head_state_for_next_slot_task();
            }
            ApplyBlockChanges::AlternateChainExtended { .. } => {}
        }

        let post_processing_duration = insertion_time.elapsed();

        features::log!(
            LogBlockProcessingTime,
            "block {block_root:?} post-processed in {post_processing_duration:?}",
        );

        if let Some(metrics) = self.metrics.as_ref() {
            metrics
                .block_post_processing_times
                .observe(post_processing_duration.as_secs_f64());
        }

        Ok(())
    }

    fn reject_block(&mut self, error: AnyhowError, block_root: H256, origin: BlockOrigin) {
        warn_with_peers!(
            "block rejected (error: {error:#}, block root: {block_root:?}, origin: {origin:?})"
        );

        // A bad signature condemns this copy, not the root.
        // Remembering the root would turn away the genuine block and its descendants.
        let condemns_root = !matches!(
            error.downcast_ref(),
            Some(Error::<P>::BlockWithoutValidProposerSignature { .. }),
        );

        let rejection_reason = if condemns_root {
            MutatorRejectionReason::InvalidBlock
        } else {
            MutatorRejectionReason::InvalidBlockSignature { block_root }
        };

        let sender = match origin {
            BlockOrigin::Gossip(gossip_id) => {
                self.send_to_p2p(P2pMessage::Reject(Some(gossip_id), rejection_reason));

                None
            }
            BlockOrigin::Api(sender) => sender,
            BlockOrigin::Requested(peer_id) => {
                if let Some(peer_id) = peer_id {
                    // During block sync (and especially during non-finality events)
                    // it's important to drop peers that send invalid blocks
                    self.send_to_p2p(P2pMessage::PenalizePeer(peer_id, rejection_reason));
                }

                None
            }
            BlockOrigin::Own | BlockOrigin::Persisted => None,
            BlockOrigin::Test(_) => {
                self.send_to_p2p(P2pMessage::Reject(None, rejection_reason));

                None
            }
        };

        if condemns_root {
            self.store_mut().register_rejected_block(block_root);
            self.update_store_snapshot();
        }

        reply_block_validation_result_to_http_api(sender, Err(error));
    }

    fn accept_execution_payload_envelope(
        &mut self,
        wait_group: &W,
        accepted: AcceptedExecutionPayloadEnvelope<P>,
        is_before_deadline: bool,
    ) {
        let beacon_block_root = accepted.beacon_block_root();
        let execution_block_hash = accepted.payload_block_hash();

        self.store_mut()
            .apply_execution_payload_envelope(accepted, is_before_deadline);

        self.update_store_snapshot();

        // `notify_new_payload` is called during the envelope validation, so the payload status
        // may arrive before the payload is even handled in the mutator
        if let Some(payload_statuses) = self.delayed_until_payload.remove(&execution_block_hash) {
            for (payload_status, _) in payload_statuses {
                self.handle_notified_new_payload(
                    wait_group,
                    beacon_block_root,
                    execution_block_hash,
                    payload_status,
                );
            }
        }

        self.notify_forkchoice_updated(self.store.head());

        if self.store.head().block_root == beacon_block_root {
            self.prepare_execution_payload_for_head(beacon_block_root);
        }

        self.send_to_validator(ValidatorMessage::PayloadStatusUpdated(
            wait_group.clone(),
            self.store.head().clone(),
        ));

        if let Some(delayed) = self.take_delayed_until_envelope(beacon_block_root) {
            self.retry_delayed(delayed, wait_group);
        }

        if !self.storage.prune_storage_enabled() {
            self.spawn(PersistExecutionPayloadEnvelopesTask {
                store_snapshot: self.owned_store(),
                storage: self.storage.clone_arc(),
                mutator_tx: self.owned_mutator_tx(),
                wait_group: wait_group.clone(),
                metrics: self.metrics.clone(),
            });
        }
    }

    fn accept_blob_sidecar(&mut self, wait_group: &W, blob_sidecar: &Arc<BlobSidecar<P>>) {
        let block_root = blob_sidecar.signed_block_header.message.hash_tree_root();

        self.store_mut()
            .apply_blob_sidecar(blob_sidecar.clone_arc());

        self.update_store_snapshot();

        if let Some(pending_block) = self.take_delayed_until_blobs(block_root) {
            self.retry_block(wait_group.clone(), pending_block);
        }

        self.event_channels
            .send_blob_sidecar_event(block_root, blob_sidecar);

        if !self.storage.prune_storage_enabled() {
            self.spawn(PersistBlobSidecarsTask {
                store_snapshot: self.owned_store(),
                storage: self.storage.clone_arc(),
                mutator_tx: self.owned_mutator_tx(),
                wait_group: wait_group.clone(),
                metrics: self.metrics.clone(),
            });
        }
    }

    fn accept_data_column_sidecar(
        &mut self,
        wait_group: &W,
        data_column_sidecar: &Arc<DataColumnSidecar<P>>,
        origin: DataColumnSidecarOrigin,
    ) -> DataColumnSidecarOrigin {
        let block_root = data_column_sidecar.beacon_block_root();

        self.store_mut()
            .apply_data_column_sidecar(data_column_sidecar.clone_arc());

        self.update_store_snapshot();

        let accepted_data_columns = self
            .store
            .accepted_data_column_sidecars_count(data_column_sidecar);
        let reconstruction_or_early_import_available = self
            .store
            .is_reconstruction_or_early_import_available_for(&block_root, accepted_data_columns);

        let all_sampling_columns_available =
            accepted_data_columns >= self.store.sampling_columns_count();
        let should_retry_block =
            reconstruction_or_early_import_available || all_sampling_columns_available;

        debug_with_peers!(
            "accepted data column sidecar: {block_root:?}, index: {}, slot: {}, \
            accepted data columns: {accepted_data_columns}, sampling columns count: {}, \
            reconstruction or early import available: {reconstruction_or_early_import_available}, \
            should_retry_block: {should_retry_block}, \
            reconstruction started: {}, origin: {origin:?}",
            data_column_sidecar.index(),
            data_column_sidecar.slot(),
            self.store.sampling_columns_count(),
            self.store.is_sidecars_construction_started(&block_root),
        );

        // During syncing, if we retry everytime when receiving a sidecar, this might spamming the
        // queue, leading to delaying other data column sidecar tasks
        if should_retry_block && let Some(pending_block) = self.take_delayed_until_blobs(block_root)
        {
            self.retry_block(wait_group.clone(), pending_block);
        }

        let identifier: DataColumnIdentifier = data_column_sidecar.as_ref().into();

        if let Some((_, (_, sender))) = self
            .sidecars_pending_reconstruction
            .remove_sync(&identifier)
            && sender.receiver_count() > 0
            && let Err(error) = sender.send(data_column_sidecar.clone_arc())
        {
            debug_with_peers!(
                "unable to send reconstructed data column sidecar to pending requests: \
                {identifier:?}, error: {error:?}",
            )
        }

        // Once all sampling columns are available, retry pending payload envelope.
        if all_sampling_columns_available
            && let Some(pending_payload_envelope) = self.take_delayed_until_data(block_root)
        {
            self.retry_execution_payload_envelope(wait_group.clone(), pending_payload_envelope);
        }

        self.event_channels
            .send_data_column_sidecar_event(block_root, data_column_sidecar);

        origin
    }

    fn notify_about_finalized_checkpoint(&self) {
        let finalized_checkpoint = self.store.finalized_checkpoint();
        let justified_checkpoint = self.store.justified_checkpoint();
        let head = self.store.head();

        info_with_peers!(
            "new finalized checkpoint \
             (epoch: {}, root: {:?}, head slot: {}, head root: {:?})",
            finalized_checkpoint.epoch,
            finalized_checkpoint.root,
            head.slot(),
            head.block_root,
        );

        self.send_to_p2p(P2pMessage::FinalizedCheckpoint(finalized_checkpoint));
        self.send_to_validator(ValidatorMessage::FinalizedCheckpoint(finalized_checkpoint));

        if let Some(metrics) = self.metrics.as_ref() {
            let state = head.state(&self.store);
            let previous_justified_checkpoint = state.previous_justified_checkpoint();

            metrics.set_beacon_current_justified_epoch(justified_checkpoint.epoch);
            metrics.set_beacon_finalized_epoch(finalized_checkpoint.epoch);
            metrics.set_beacon_previous_justified_epoch(previous_justified_checkpoint.epoch);
        }

        self.event_channels.send_finalized_checkpoint_event(
            head.block_root,
            finalized_checkpoint,
            self.store.head_node_payload_status().is_optimistic(),
        );
    }

    fn notify_about_reorganization(
        &self,
        wait_group: W,
        old_head: &ChainLink<P>,
        reorg_source: ReorgSource,
    ) {
        let new_head = self.store.head().clone();

        self.event_channels.send_chain_reorg_event(
            &self.store,
            &new_head,
            old_head,
            self.store.head_node_payload_status(),
        );

        if let Some(metrics) = self.metrics.as_ref() {
            metrics.beacon_reorgs_total.inc();
        }

        info_with_peers!(
            "chain reorganized (old head: {:?}, new head: {:?}), cause: {reorg_source:?}",
            old_head.block_root,
            new_head.block_root,
        );

        if let Some(metrics) = self.metrics.as_ref() {
            Self::track_head_metrics(&new_head, metrics);
        }

        self.send_to_p2p(P2pMessage::HeadChanged(new_head.block_root));

        if new_head.is_valid() || new_head.is_post_gloas() {
            // Do not send API events about optimistic blocks.
            // Vouch treats all head events as non-optimistic.
            self.send_head_events(&new_head);

            self.send_to_validator(ValidatorMessage::Head(wait_group, new_head.clone()));
        }

        self.notify_forkchoice_updated(&new_head);
    }

    fn request_blobs_from_execution_engine(&self, params: EngineGetBlobsParams<P>) {
        self.execution_engine.get_blobs(params);
    }

    fn notify_forkchoice_updated(&self, new_head: &ChainLink<P>) {
        let store = &self.store;

        let new_head_state = new_head.state(store);

        let Some(state) = new_head_state.post_bellatrix() else {
            return;
        };

        if !predicates::is_merge_transition_complete(state) {
            return;
        }

        let safe_block_hash = store.safe_execution_payload_hash();
        let finalized_block_hash = store.finalized_execution_payload_hash();

        let head_block_hash = if let Some(post_gloas_state) = new_head_state.post_gloas() {
            // Match the branch the current-slot proposer will build on.
            if store.should_build_on_full(store.slot()) {
                post_gloas_state.latest_execution_payload_bid().block_hash
            } else {
                post_gloas_state.latest_block_hash()
            }
        } else {
            state.latest_execution_payload_header().block_hash()
        };

        if store.phase() >= Phase::Gloas {
            let head_root = new_head.block_root;

            debug_with_peers!(
                "fork choice head at slot {}: {head_root:?} (\
                    block hash: {head_block_hash:?}, \
                    payload status: {:?}, \
                    payload verified: {}, \
                    payload timely: {}, \
                    build on full: {}\
                )",
                new_head.slot(),
                PayloadPresence::from(store.head_payload_status()),
                store.is_payload_verified(head_root),
                store.is_payload_present_timely(head_root),
                store.should_build_on_full(store.slot()),
            );
        }

        self.execution_engine.notify_forkchoice_updated(
            head_block_hash,
            safe_block_hash,
            finalized_block_hash,
            Either::Left(new_head.block.phase()),
            None,
        );
    }

    fn send_head_events(&self, head: &ChainLink<P>) {
        match self.calculate_dependent_roots(head) {
            Ok(dependent_roots) => {
                let head_node_payload_status = self.store.head_node_payload_status();
                let execution_optimistic = head_node_payload_status.is_optimistic();

                self.event_channels.send_head_event(
                    head,
                    dependent_roots,
                    head_node_payload_status,
                );

                self.event_channels.send_head_v2_event(
                    head,
                    self.store.head_payload_status(),
                    dependent_roots,
                    execution_optimistic,
                );
            }
            Err(error) => {
                warn_with_peers!("unable to calculate dependent roots for head events: {error}")
            }
        }
    }

    // This may even involve a DB lookup so it would be best
    // if we can avoid making it if no event listeners are present
    fn calculate_dependent_roots(&self, head: &ChainLink<P>) -> Result<DependentRootsBundle> {
        let state = head.state(&self.store);
        let current_epoch = accessors::get_current_epoch(&state);
        let previous_epoch = accessors::get_previous_epoch(&state);

        let current_duty_dependent_root =
            self.storage
                .dependent_root(&self.store, &state, current_epoch)?;

        let previous_duty_dependent_root =
            self.storage
                .dependent_root(&self.store, &state, previous_epoch)?;

        Ok(DependentRootsBundle {
            current_duty_dependent_root,
            previous_duty_dependent_root,
        })
    }

    fn delay_block_until_blobs(&mut self, beacon_block_root: H256, pending_block: PendingBlock<P>) {
        self.store_mut()
            .delay_block_at_slot(pending_block.block.item.message().slot(), beacon_block_root);
        self.update_store_snapshot();

        self.delayed_until_blobs
            .insert(beacon_block_root, pending_block);
    }

    fn total_unverified_delayed_block_until_parent(&self) -> usize {
        self.delayed_until_block
            .values()
            .map(|delayed| delayed.unverified_blocks.len())
            .sum::<usize>()
    }

    fn try_delay_block_until_parent(&mut self, pending_block: PendingBlock<P>) -> Result<()> {
        // Blocks produced by the application itself should never be delayed.
        assert!(!matches!(pending_block.origin, BlockOrigin::Own));

        let parent_root = pending_block.block.item.message().parent_root();

        if pending_block.block.base_signature_status.is_verified() {
            self.delayed_until_block
                .entry(parent_root)
                .or_default()
                .blocks
                .push(pending_block);
        } else if self.total_unverified_delayed_block_until_parent()
            < MAX_DELAYED_BLOCKS_UNTIL_PARENT
        {
            self.delayed_until_block
                .entry(parent_root)
                .or_default()
                .unverified_blocks
                .push(pending_block);
        } else {
            return Err(Error::<P>::DelayedUntilParentQueueFull.into());
        }

        Ok(())
    }

    fn delay_block_until_payload_envelope(
        &mut self,
        parent_root: H256,
        pending_block: PendingBlock<P>,
    ) {
        self.delayed_until_envelope
            .entry(parent_root)
            .or_default()
            .blocks
            .push(pending_block);
    }

    fn delay_aggregate_and_proof_until_block(
        &mut self,
        wait_group: &W,
        pending_aggregate_and_proof: PendingAggregateAndProof<P>,
        block_root: H256,
    ) {
        if self.store.contains_block(block_root) {
            self.retry_aggregate_and_proof(wait_group.clone(), pending_aggregate_and_proof);
        } else {
            trace_with_peers!(
                "aggregate and proof delayed until block \
                 (pending_aggregate_and_proof: {pending_aggregate_and_proof:?}, \
                  block_root: {block_root:?})",
            );

            let peer_id = pending_aggregate_and_proof
                .origin
                .gossip_id_ref()
                .map(|gossip_id| gossip_id.source);

            self.send_to_p2p(P2pMessage::BlockNeeded(block_root, peer_id));

            self.delayed_until_block
                .entry(block_root)
                .or_default()
                .aggregates
                .push(pending_aggregate_and_proof);
        }
    }

    fn delay_attestation_until_block(
        &mut self,
        wait_group: &W,
        pending_attestation: PendingAttestation<P>,
        block_root: H256,
    ) {
        if self.store.contains_block(block_root) {
            self.retry_attestation(wait_group.clone(), pending_attestation);
        } else {
            trace_with_peers!(
                "attestation delayed until block \
                 (pending_attestation: {pending_attestation:?}, block_root: {block_root:?})",
            );

            let peer_id = pending_attestation
                .origin
                .gossip_id_ref()
                .map(|gossid_id| gossid_id.source);

            self.send_to_p2p(P2pMessage::BlockNeeded(block_root, peer_id));

            // Attestations produced by the application itself should never be delayed.
            assert!(!matches!(
                pending_attestation.origin,
                AttestationOrigin::Own(_),
            ));

            self.delayed_until_block
                .entry(block_root)
                .or_default()
                .attestations
                .push(pending_attestation);
        }
    }

    fn delay_attestation_until_payload(
        &mut self,
        wait_group: &W,
        attestation: PendingAttestation<P>,
        block_root: H256,
    ) {
        if self.store.is_payload_verified(block_root) {
            self.retry_attestation(wait_group.clone(), attestation);
        } else {
            let peer_id = attestation
                .origin
                .gossip_id_ref()
                .map(|gossip_id| gossip_id.source);
            self.send_to_p2p(P2pMessage::PayloadEnvelopeNeeded(block_root, peer_id));

            self.delayed_until_envelope
                .entry(block_root)
                .or_default()
                .attestations
                .push(attestation);
        }
    }

    fn try_delay_execution_payload_envelope_until_block(
        &mut self,
        wait_group: W,
        pending_execution_payload_envelope: PendingExecutionPayloadEnvelope<P>,
        beacon_block_root: H256,
    ) -> Result<()> {
        if self.store.contains_block(beacon_block_root) {
            self.retry_execution_payload_envelope(wait_group, pending_execution_payload_envelope);
            return Ok(());
        }

        let evicted = make_room_for_delayed_execution_payload_envelope(
            &mut self.delayed_until_block,
            &pending_execution_payload_envelope,
        )?;

        if let Some((evicted_block_root, evicted)) = evicted {
            let evicted_slot = evicted.execution_payload_envelope.slot();
            let slot = pending_execution_payload_envelope
                .execution_payload_envelope
                .slot();

            debug_with_peers!(
                "evicted execution payload envelope delayed until block \
                 (beacon_block_root: {evicted_block_root:?}, slot: {evicted_slot}) \
                 to make room for envelope at slot {slot}"
            );

            self.send_to_p2p(P2pMessage::IgnoreWithReason(
                evicted.origin.gossip_id(),
                MutatorIgnoreReason::ExecutionPayloadEnvelopeQueueFull {
                    payload_envelope_identifier: evicted.execution_payload_envelope.as_ref().into(),
                },
            ));
        }

        trace_with_peers!(
            "execution payload envelope delayed until block \
             (beacon_block_root: {beacon_block_root:?})",
        );

        let peer_id = pending_execution_payload_envelope
            .origin
            .gossip_id_ref()
            .map(|gossip_id| gossip_id.source);
        self.send_to_p2p(P2pMessage::BlockNeeded(beacon_block_root, peer_id));

        self.delayed_until_block
            .entry(beacon_block_root)
            .or_default()
            .execution_payload_envelopes
            .push(pending_execution_payload_envelope);

        Ok(())
    }

    fn delay_execution_payload_envelope_until_data(
        &mut self,
        beacon_block_root: H256,
        pending_execution_payload_envelope: PendingExecutionPayloadEnvelope<P>,
    ) {
        self.delayed_until_data
            .insert(beacon_block_root, pending_execution_payload_envelope);
    }

    fn delay_proposer_preferences_until_block(
        &mut self,
        wait_group: W,
        pending_proposer_preferences: PendingProposerPreferences,
        block_root: H256,
    ) {
        if self.store.contains_block(block_root) {
            self.retry_proposer_preferences(wait_group, pending_proposer_preferences);
        } else {
            trace_with_peers!(
                "proposer preferences delayed until checkpoint block (block_root: {block_root:?})",
            );

            let peer_id = pending_proposer_preferences
                .origin
                .gossip_id_ref()
                .map(|gossip_id| gossip_id.source);

            self.send_to_p2p(P2pMessage::BlockNeeded(block_root, peer_id));

            self.delayed_until_block
                .entry(block_root)
                .or_default()
                .proposer_preferences
                .push(pending_proposer_preferences);
        }
    }

    fn retry_proposer_preferences(&self, wait_group: W, pending: PendingProposerPreferences) {
        trace_with_peers!("retrying delayed proposer preferences");

        self.spawn(ProposerPreferencesTask {
            store_snapshot: self.owned_store(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            signed_preferences: pending.signed_preferences,
            origin: pending.origin,
        });
    }

    fn delay_payload_attestation_until_block(
        &mut self,
        wait_group: &W,
        pending_payload_attestation: PayloadAttestationItem<P>,
        block_root: H256,
    ) {
        if self.store.contains_block(block_root) {
            self.retry_payload_attestation(wait_group.clone(), pending_payload_attestation);
        } else {
            trace_with_peers!(
                "payload attestation delayed until block \
                 (pending_payload_attestation: {pending_payload_attestation:?}, block_root: {block_root:?})",
            );

            let peer_id = pending_payload_attestation
                .origin
                .gossip_id_ref()
                .map(|gossid_id| gossid_id.source);

            self.send_to_p2p(P2pMessage::BlockNeeded(block_root, peer_id));

            self.delayed_until_block
                .entry(block_root)
                .or_default()
                .payload_attestations
                .push(pending_payload_attestation);
        }
    }

    fn delay_payload_status_until_block(
        &mut self,
        beacon_block_root: H256,
        payload_status: PayloadStatusV1,
    ) {
        debug_with_peers!(
            "payload status handling delayed until block \
             (payload_status: {payload_status:?}, beacon_block_root: {beacon_block_root:?})",
        );

        let pending_payload_status = (payload_status, self.store.head().slot());

        self.delayed_until_block
            .entry(beacon_block_root)
            .or_default()
            .payload_status = Some(pending_payload_status);
    }

    fn try_delay_block_until_slot(&mut self, pending_block: PendingBlock<P>) -> Result<()> {
        // Requested blocks can also be delayed until a slot if the slot isn't updated on time.
        // Blocks produced by the application itself should never be delayed.
        assert!(!matches!(pending_block.origin, BlockOrigin::Own));

        let slot = pending_block.block.item.message().slot();
        let entry = self.delayed_until_slot.entry(slot).or_default();

        if entry.blocks.len() < MAX_DELAYED_FUTURE_BLOCKS_PER_SLOT {
            entry.blocks.push(pending_block);
        } else {
            return Err(Error::<P>::BlockSlotQueueFull { slot }.into());
        }

        Ok(())
    }

    fn delay_aggregate_and_proof_until_slot(
        &mut self,
        wait_group: &W,
        pending_aggregate_and_proof: PendingAggregateAndProof<P>,
    ) {
        let slot = pending_aggregate_and_proof
            .aggregate_and_proof
            .message()
            .aggregate()
            .data()
            .slot;

        if slot <= self.store.slot() {
            self.retry_aggregate_and_proof(wait_group.clone(), pending_aggregate_and_proof);
        } else {
            trace_with_peers!(
                "aggregate and proof delayed until slot: {pending_aggregate_and_proof:?}"
            );

            self.delayed_until_slot
                .entry(slot)
                .or_default()
                .aggregates
                .push(pending_aggregate_and_proof);
        }
    }

    fn delay_attestation_until_slot(
        &mut self,
        wait_group: &W,
        pending_attestation: PendingAttestation<P>,
    ) {
        let slot = pending_attestation.slot();

        if slot <= self.store.slot() {
            self.retry_attestation(wait_group.clone(), pending_attestation);
        } else {
            trace_with_peers!("attestation delayed until slot: {pending_attestation:?}");

            // Attestations produced by the application itself should never be delayed.
            // Attestations included in blocks should never be delayed until a slot
            // because at least one slot must have passed since they were published.
            assert!(!matches!(
                pending_attestation.origin,
                AttestationOrigin::Own(_) | AttestationOrigin::Block(_),
            ));

            self.delayed_until_slot
                .entry(pending_attestation.slot())
                .or_default()
                .attestations
                .push(pending_attestation);
        }
    }

    fn delay_blob_sidecar_until_state(
        &mut self,
        pending_blob_sidecar: PendingBlobSidecar<P>,
        block_root: H256,
    ) {
        let slot = pending_blob_sidecar
            .blob_sidecar
            .signed_block_header
            .message
            .slot;

        self.delayed_until_state
            .entry((block_root, slot))
            .or_default()
            .blob_sidecars
            .push(pending_blob_sidecar);
    }

    fn try_delay_blob_sidecar_until_parent(
        &mut self,
        pending_blob_sidecar: PendingBlobSidecar<P>,
    ) -> Result<()> {
        let parent_root = pending_blob_sidecar
            .blob_sidecar
            .signed_block_header
            .message
            .parent_root;

        let epoch = misc::compute_epoch_at_slot::<P>(
            pending_blob_sidecar
                .blob_sidecar
                .signed_block_header
                .message
                .slot,
        );

        let max_delayed_blobs_until_parent = MAX_DELAYED_BLOCKS_UNTIL_PARENT.saturating_mul(
            usize::try_from(self.store.chain_config().max_blobs_per_block(epoch))?,
        );

        let total_delayed_blobs_until_parent = self
            .delayed_until_block
            .values()
            .map(|delayed| delayed.blob_sidecars.len())
            .sum::<usize>();

        if total_delayed_blobs_until_parent < max_delayed_blobs_until_parent {
            self.delayed_until_block
                .entry(parent_root)
                .or_default()
                .blob_sidecars
                .push(pending_blob_sidecar);
        } else {
            return Err(Error::<P>::DelayedUntilParentQueueFull.into());
        }

        Ok(())
    }

    fn try_delay_blob_sidecar_until_slot(
        &mut self,
        pending_blob_sidecar: PendingBlobSidecar<P>,
    ) -> Result<()> {
        let slot = pending_blob_sidecar
            .blob_sidecar
            .signed_block_header
            .message
            .slot;

        let epoch = misc::compute_epoch_at_slot::<P>(slot);

        let max_blobs_per_slot = MAX_DELAYED_FUTURE_BLOCKS_PER_SLOT.saturating_mul(
            usize::try_from(self.store.chain_config().max_blobs_per_block(epoch))?,
        );

        let entry = self.delayed_until_slot.entry(slot).or_default();

        if entry.blob_sidecars.len() < max_blobs_per_slot {
            entry.blob_sidecars.push(pending_blob_sidecar);
        } else {
            return Err(Error::<P>::BlobSidecarSlotQueueFull { slot }.into());
        }

        Ok(())
    }

    fn delay_data_column_sidecar_until_state(
        &mut self,
        pending_data_column_sidecar: PendingDataColumnSidecar<P>,
        block_root: H256,
    ) {
        let slot = pending_data_column_sidecar.data_column_sidecar.slot();

        self.delayed_until_state
            .entry((block_root, slot))
            .or_default()
            .data_column_sidecars
            .push(pending_data_column_sidecar);
    }

    fn try_delay_data_column_sidecar_until_parent(
        &mut self,
        pending_data_column_sidecar: PendingDataColumnSidecar<P>,
    ) -> Result<()> {
        let Some(parent_root) = pending_data_column_sidecar
            .data_column_sidecar
            .pre_gloas()
            .map(|sidecar| sidecar.signed_block_header.message.parent_root)
        else {
            return Ok(());
        };

        let total_delayed_data_columns_until_parent = self
            .delayed_until_block
            .values()
            .map(|delayed| delayed.data_column_sidecars.len())
            .sum::<usize>();

        let max_data_columns_per_parent =
            MAX_DELAYED_BLOCKS_UNTIL_PARENT.saturating_mul(P::NumberOfColumns::USIZE);

        if total_delayed_data_columns_until_parent < max_data_columns_per_parent {
            self.delayed_until_block
                .entry(parent_root)
                .or_default()
                .data_column_sidecars
                .push(pending_data_column_sidecar);
        } else {
            return Err(Error::<P>::DelayedUntilParentQueueFull.into());
        }

        Ok(())
    }

    fn try_delay_data_column_sidecar_until_slot(
        &mut self,
        pending_data_column_sidecar: PendingDataColumnSidecar<P>,
    ) -> Result<()> {
        let slot = pending_data_column_sidecar.data_column_sidecar.slot();
        let entry = self.delayed_until_slot.entry(slot).or_default();

        let max_data_columns_per_slot =
            MAX_DELAYED_FUTURE_BLOCKS_PER_SLOT.saturating_mul(P::NumberOfColumns::USIZE);

        if entry.data_column_sidecars.len() < max_data_columns_per_slot {
            entry.data_column_sidecars.push(pending_data_column_sidecar);
        } else {
            return Err(Error::<P>::DataColumnSidecarSlotQueueFull { slot }.into());
        }

        Ok(())
    }

    fn take_delayed_until_blobs(&mut self, block_root: H256) -> Option<PendingBlock<P>> {
        self.delayed_until_blobs.remove(&block_root)
    }

    fn take_delayed_until_block(&mut self, block_root: H256) -> Option<Delayed<P>> {
        self.delayed_until_block.remove(&block_root)
    }

    fn take_delayed_until_slot(
        &mut self,
        slot: Slot,
    ) -> impl Iterator<Item = Delayed<P>> + use<P, E, W, TS, PS, LS, NS, SS, VS> {
        match slot.checked_add(1) {
            Some(next_slot) => {
                let later = self.delayed_until_slot.split_off(&next_slot);
                core::mem::replace(&mut self.delayed_until_slot, later)
            }
            None => core::mem::take(&mut self.delayed_until_slot),
        }
        .into_values()
    }

    fn take_delayed_until_state(&mut self, block_root: H256, slot: Slot) -> Option<Delayed<P>> {
        self.delayed_until_state.remove(&(block_root, slot))
    }

    fn take_delayed_until_data(
        &mut self,
        block_root: H256,
    ) -> Option<PendingExecutionPayloadEnvelope<P>> {
        self.delayed_until_data.remove(&block_root)
    }

    fn take_delayed_until_envelope(&mut self, beacon_block_root: H256) -> Option<Delayed<P>> {
        self.delayed_until_envelope.remove(&beacon_block_root)
    }

    // `wait_group` is a reference not just to pass Clippy lints but for correctness as well.
    // The referenced value must not be dropped before the current message is handled.
    fn retry_delayed(&self, delayed: Delayed<P>, wait_group: &W) {
        let Delayed {
            blocks,
            unverified_blocks,
            // Delayed payload status update is applied before accepting block,
            // so a bit earlier than the other delayed items.
            payload_status: _,
            aggregates,
            attestations,
            execution_payload_envelopes,
            payload_attestations,
            blob_sidecars,
            data_column_sidecars,
            proposer_preferences,
        } = delayed;

        for pending_block in blocks {
            self.retry_block(wait_group.clone(), pending_block);
        }

        for pending_block in unverified_blocks {
            self.retry_block(wait_group.clone(), pending_block);
        }

        for pending_aggregate_and_proof in aggregates {
            self.retry_aggregate_and_proof(wait_group.clone(), pending_aggregate_and_proof);
        }

        for pending_attestation in attestations {
            self.retry_attestation(wait_group.clone(), pending_attestation);
        }

        for pending_execution_payload_envelope in execution_payload_envelopes {
            self.retry_execution_payload_envelope(
                wait_group.clone(),
                pending_execution_payload_envelope,
            );
        }

        for pending_payload_attestation in payload_attestations {
            self.retry_payload_attestation(wait_group.clone(), pending_payload_attestation);
        }

        for pending_blob_sidecar in blob_sidecars {
            self.retry_blob_sidecar(wait_group.clone(), pending_blob_sidecar, None);
        }

        for pending_data_column_sidecar in data_column_sidecars {
            self.retry_data_column_sidecar(wait_group.clone(), pending_data_column_sidecar, None);
        }

        for pending_proposer_preferences in proposer_preferences {
            self.retry_proposer_preferences(wait_group.clone(), pending_proposer_preferences);
        }
    }

    #[instrument(skip_all, level = "debug", parent = &pending_block.tracing_span)]
    fn retry_block(&self, wait_group: W, pending_block: PendingBlock<P>) {
        debug_with_peers!(
            "retrying delayed block: {:?}",
            pending_block.block.item.message().hash_tree_root(),
        );

        let PendingBlock {
            block,
            origin,
            processing_timings,
            tracing_span,
        } = pending_block;

        let processing_timings = processing_timings.processing();

        self.spawn(BlockTask {
            store_snapshot: self.owned_store(),
            block_processor: self.block_processor.clone_arc(),
            execution_engine: self.execution_engine.clone(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            block,
            origin,
            processing_timings,
            metrics: self.metrics.clone(),
            tracing_span,
        });
    }

    fn retry_attestation(&self, wait_group: W, attestation: PendingAttestation<P>) {
        trace_with_peers!("retrying delayed attestation: {attestation:?}");

        if attestation.verify_signatures() {
            self.send_to_attestation_verifier(AttestationVerifierMessage::Attestation {
                wait_group,
                attestation,
            });
        } else {
            self.spawn(AttestationTask {
                store_snapshot: self.owned_store(),
                mutator_tx: self.owned_mutator_tx(),
                wait_group,
                attestation,
                metrics: self.metrics.clone(),
            });
        }
    }

    fn retry_execution_payload_envelope(
        &self,
        wait_group: W,
        pending_execution_payload_envelope: PendingExecutionPayloadEnvelope<P>,
    ) {
        trace_with_peers!("retrying delayed execution payload envelope");

        let PendingExecutionPayloadEnvelope {
            execution_payload_envelope,
            origin,
            seen_before_deadline,
            processing_timings,
            tracing_span,
        } = pending_execution_payload_envelope;

        self.spawn(ExecutionPayloadEnvelopeTask {
            store_snapshot: self.owned_store(),
            mutator_tx: self.owned_mutator_tx(),
            execution_engine: self.execution_engine.clone(),
            capture_proof_context: self.capture_proof_context,
            wait_group,
            execution_payload_envelope,
            origin,
            seen_before_deadline,
            processing_timings,
            metrics: self.metrics.clone(),
            tracing_span,
        });
    }

    fn retry_payload_attestation(
        &self,
        wait_group: W,
        payload_attestation: PayloadAttestationItem<P>,
    ) {
        trace_with_peers!("retrying delayed payload attestation: {payload_attestation:?}");

        self.spawn(PayloadAttestationTask {
            store_snapshot: self.owned_store(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            payload_attestation,
            metrics: self.metrics.clone(),
        });
    }

    fn retry_tick(&mut self, wait_group: &W, tick: Tick) -> Result<()> {
        debug_with_peers!("retrying delayed tick: {tick:?}");

        self.handle_tick(wait_group, tick)
    }

    fn retry_aggregate_and_proof(
        &self,
        wait_group: W,
        pending_aggregate_and_proof: PendingAggregateAndProof<P>,
    ) {
        trace_with_peers!("retrying delayed aggregate and proof: {pending_aggregate_and_proof:?}");

        let PendingAggregateAndProof {
            aggregate_and_proof,
            origin,
        } = pending_aggregate_and_proof;

        self.send_to_attestation_verifier(AttestationVerifierMessage::AggregateAndProof {
            wait_group,
            aggregate_and_proof,
            origin,
        });
    }

    fn retry_blob_sidecar(
        &self,
        wait_group: W,
        pending_blob_sidecar: PendingBlobSidecar<P>,
        state: Option<Arc<BeaconState<P>>>,
    ) {
        trace_with_peers!("retrying delayed blob sidecar: {pending_blob_sidecar:?}");

        let PendingBlobSidecar {
            blob_sidecar,
            block_seen,
            origin,
            submission_time,
        } = pending_blob_sidecar;

        self.spawn(BlobSidecarTask {
            store_snapshot: self.owned_store(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            blob_sidecar,
            state,
            block_seen,
            origin,
            submission_time,
            metrics: self.metrics.clone(),
        });
    }

    fn retry_data_column_sidecar(
        &self,
        wait_group: W,
        pending_data_column_sidecar: PendingDataColumnSidecar<P>,
        state: Option<Arc<BeaconState<P>>>,
    ) {
        trace_with_peers!("retrying delayed data column sidecar: {pending_data_column_sidecar:?}");

        let PendingDataColumnSidecar {
            data_column_sidecar,
            block_seen,
            origin,
            submission_time,
        } = pending_data_column_sidecar;

        // disable block presence validation if block has been imported early with reconstruction promise
        let validate_block_presence = !self
            .sidecars_pending_reconstruction
            .contains_sync::<DataColumnIdentifier>(&data_column_sidecar.as_ref().into());

        self.spawn(RetryDataColumnSidecarTask {
            task: DataColumnSidecarTask {
                store_snapshot: self.owned_store(),
                mutator_tx: self.owned_mutator_tx(),
                wait_group,
                data_column_sidecar,
                state,
                block_seen,
                origin,
                submission_time,
                validate_block_presence,
                metrics: self.metrics.clone(),
            },
        });
    }

    fn prune_delayed_until_blobs(&mut self) -> Vec<GossipId> {
        let finalized_slot = self.store.finalized_slot();

        let mut gossip_ids = vec![];

        self.delayed_until_blobs.retain(|_, pending_block| {
            if pending_block.block.item.message().slot() > finalized_slot {
                return true;
            }

            if let Some(gossip_id) = pending_block.origin.gossip_id() {
                gossip_ids.push(gossip_id);
            }

            false
        });

        gossip_ids
    }

    fn prune_delayed_after_finalization(&mut self) {
        let delayed = self.prune_delayed_until_block();
        let delayed_until_envelope = self.prune_delayed_until_envelope();
        let delayed_until_blobs = self.prune_delayed_until_blobs();
        let delayed_until_data = self.prune_delayed_until_data();
        let waiting = self.prune_waiting_for_checkpoint_states();

        for gossip_id in delayed
            .into_iter()
            .chain(delayed_until_envelope)
            .chain(delayed_until_blobs)
            .chain(delayed_until_data)
            .chain(waiting)
        {
            self.send_to_p2p(P2pMessage::Ignore(gossip_id));
        }
    }

    // Some objects may be delayed until a block that is itself delayed.
    // If the latter is pruned, objects depending on it could be pruned as well.
    // We don't bother doing this. It's tricky to implement and might not even be worth it.
    //
    // It may be possible to prune delayed objects in a background thread.
    // We don't bother doing that either.
    #[expect(clippy::too_many_lines)]
    fn prune_delayed_until_block(&mut self) -> Vec<GossipId> {
        let finalized_slot = self.store.finalized_slot();
        let previous_epoch = self.store.previous_epoch();

        let mut gossip_ids = vec![];

        self.delayed_until_block.retain(|_, delayed| {
            let Delayed {
                blocks,
                unverified_blocks,
                payload_status,
                aggregates,
                attestations,
                execution_payload_envelopes,
                payload_attestations,
                blob_sidecars,
                data_column_sidecars,
                proposer_preferences,
            } = delayed;

            gossip_ids.extend(
                blocks
                    .extract_if(.., |pending| {
                        // The parent of a delayed block cannot be in a finalized slot.
                        pending.block.item.message().slot().saturating_sub(1) <= finalized_slot
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            gossip_ids.extend(
                unverified_blocks
                    .extract_if(.., |pending| {
                        // The parent of a delayed block cannot be in a finalized slot.
                        pending.block.item.message().slot().saturating_sub(1) <= finalized_slot
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            if let Some((_, slot)) = payload_status
                && *slot <= finalized_slot
            {
                payload_status.take();
            }

            gossip_ids.extend(
                aggregates
                    .extract_if(.., |pending| {
                        let epoch = pending
                            .aggregate_and_proof
                            .message()
                            .aggregate()
                            .data()
                            .target
                            .epoch;

                        epoch < previous_epoch
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            gossip_ids.extend(
                attestations
                    .extract_if(.., |pending| {
                        let epoch = pending.data().target.epoch;

                        epoch < previous_epoch
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            gossip_ids.extend(
                execution_payload_envelopes
                    .extract_if(.., |pending| {
                        pending
                            .execution_payload_envelope
                            .message
                            .payload
                            .slot_number
                            .saturating_sub(1)
                            <= finalized_slot
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            gossip_ids.extend(
                payload_attestations
                    .extract_if(.., |pending| {
                        pending.data().slot.saturating_sub(1) <= finalized_slot
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            // TODO(feature/deneb): Does the condition and comment apply to blob sidecars?
            gossip_ids.extend(
                blob_sidecars
                    .extract_if(.., |pending| {
                        // The parent of a delayed block cannot be in a finalized slot.
                        pending
                            .blob_sidecar
                            .signed_block_header
                            .message
                            .slot
                            .saturating_sub(1)
                            <= finalized_slot
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            gossip_ids.extend(
                data_column_sidecars
                    .extract_if(.., |pending| {
                        // The parent of a delayed block cannot be in a finalized slot.
                        pending.data_column_sidecar.slot().saturating_sub(1) <= finalized_slot
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            gossip_ids.extend(
                proposer_preferences
                    .extract_if(.., |pending| {
                        pending.signed_preferences.message.proposal_slot <= finalized_slot
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            !delayed.is_empty()
        });

        gossip_ids
    }

    fn prune_delayed_until_envelope(&mut self) -> Vec<GossipId> {
        let finalized_slot = self.store.finalized_slot();
        let previous_epoch = self.store.previous_epoch();

        let mut gossip_ids = vec![];

        self.delayed_until_envelope.retain(|_, delayed| {
            let Delayed {
                aggregates,
                attestations,
                blocks,
                ..
            } = delayed;

            gossip_ids.extend(
                aggregates
                    .extract_if(.., |pending| {
                        let epoch = pending
                            .aggregate_and_proof
                            .message()
                            .aggregate()
                            .data()
                            .target
                            .epoch;

                        epoch < previous_epoch
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            gossip_ids.extend(
                attestations
                    .extract_if(.., |pending| {
                        let epoch = pending.data().target.epoch;

                        epoch < previous_epoch
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            gossip_ids.extend(
                blocks
                    .extract_if(.., |pending| {
                        // The parent of a delayed block cannot be in a finalized slot.
                        pending.block.item.message().slot().saturating_sub(1) <= finalized_slot
                    })
                    .filter_map(|pending| pending.origin.gossip_id()),
            );

            !delayed.is_empty()
        });

        gossip_ids
    }

    fn prune_delayed_until_data(&mut self) -> Vec<GossipId> {
        let finalized_slot = self.store.finalized_slot();

        let mut gossip_ids = vec![];

        self.delayed_until_data
            .retain(|_, pending_payload_envelope| {
                if pending_payload_envelope.execution_payload_envelope.slot() > finalized_slot {
                    return true;
                }

                if let Some(gossip_id) = pending_payload_envelope.origin.gossip_id_ref() {
                    gossip_ids.push(gossip_id.clone());
                }

                false
            });

        gossip_ids
    }

    fn prune_delayed_until_payload(&mut self) {
        let finalized_slot = self.store.finalized_slot();

        self.delayed_until_payload.retain(|_, statuses| {
            statuses.retain(|(_, slot)| *slot > finalized_slot);
            !statuses.is_empty()
        });
    }

    fn prune_waiting_for_checkpoint_states(&mut self) -> Vec<GossipId> {
        let finalized_epoch = self.store.finalized_epoch();

        self.waiting_for_checkpoint_states
            .extract_if(|target, _| target.epoch < finalized_epoch)
            .flat_map(|(_, waiting)| {
                let WaitingForCheckpointState {
                    ticks: _,
                    chain_links,
                    aggregates,
                    attestations,
                } = waiting;

                let chain_link_ids = chain_links
                    .into_iter()
                    .filter_map(|pending| pending.origin.gossip_id());

                let aggregate_ids = aggregates
                    .into_iter()
                    .filter_map(|pending| pending.origin.gossip_id());

                let attestation_ids = attestations
                    .into_iter()
                    .filter_map(|pending| pending.origin.gossip_id());

                chain_link_ids.chain(aggregate_ids).chain(attestation_ids)
            })
            .collect()
    }

    // Attestations in blocks must be processed just like gossiped ones.
    // The docstring for `on_attestation` in the Fork Choice specification says:
    // > Run ``on_attestation`` upon receiving a new ``attestation`` from either within a
    // > block or directly on the wire.
    //
    // Also see <https://github.com/ethereum/consensus-specs/issues/1887#issuecomment-643522589>.
    fn maybe_spawn_block_attestations_task(
        &self,
        wait_group: &W,
        block_root: H256,
        block: &Arc<SignedBeaconBlock<P>>,
        from_test_block: bool,
    ) {
        // `BlockAttestationsTask`s have a surprisingly large amount of overhead.
        // Avoid spawning them if possible.
        if block.message().body().attestations_len().is_zero() {
            return;
        }

        self.spawn(BlockAttestationsTask {
            store_snapshot: self.owned_store(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group: wait_group.clone(),
            block_root,
            block: block.clone_arc(),
            from_test_block,
            metrics: self.metrics.clone(),
        });
    }

    fn maybe_spawn_block_payload_attestations_task(
        &self,
        wait_group: &W,
        block_root: H256,
        block: &Arc<SignedBeaconBlock<P>>,
    ) {
        // `BlockPayloadAttestationsTask`s have a surprisingly large amount of overhead.
        // Avoid spawning them if possible.
        let Some(body) = block.message().body().with_payload_attestations() else {
            return;
        };

        if body.payload_attestations().is_empty() {
            return;
        }

        self.spawn(BlockPayloadAttestationsTask {
            store_snapshot: self.owned_store(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group: wait_group.clone(),
            block_root,
            block: block.clone_arc(),
            metrics: self.metrics.clone(),
        });
    }

    fn prepare_execution_payload_for_head(&self, head_block_root: H256) {
        let store = &self.store;

        if let Some(state) = self.state_cache.existing_state_at_slot(
            store,
            head_block_root,
            store.slot().saturating_add(1),
        ) {
            self.prepare_execution_payload_for_next_slot(&state);
        }
    }

    fn prepare_execution_payload_for_next_slot(&self, next_slot_state: &BeaconState<P>) {
        let Some(state) = next_slot_state.post_bellatrix() else {
            return;
        };

        if !self.store.is_forward_synced() || !predicates::is_merge_transition_complete(state) {
            return;
        }

        let safe_block_hash = self.store.safe_execution_payload_hash();
        let finalized_block_hash = self.store.finalized_execution_payload_hash();

        self.send_to_validator(ValidatorMessage::PrepareExecutionPayload(
            state.slot(),
            safe_block_hash,
            finalized_block_hash,
        ));
    }

    fn spawn_checkpoint_state_task(&self, wait_group: W, checkpoint: Checkpoint) {
        self.spawn(CheckpointStateTask {
            store_snapshot: self.owned_store(),
            state_cache: self.state_cache.clone_arc(),
            mutator_tx: self.owned_mutator_tx(),
            wait_group,
            checkpoint,
            pubkey_cache: self.pubkey_cache.clone_arc(),
            metrics: self.metrics.clone(),
        });
    }

    fn maybe_spawn_preprocess_head_state_for_current_slot_task(&self, block_slot: Slot) {
        if !self.store.is_forward_synced() {
            return;
        }

        let current_tick = self.store.tick();

        if current_tick.slot == block_slot.saturating_add(1)
            && current_tick.is_before_attesting_interval()
        {
            debug_with_peers!(
                "spawn preprocess state task for current slot: {block_slot}: {current_tick:?}"
            );

            self.spawn(PreprocessStateTask {
                store_snapshot: self.owned_store(),
                state_cache: self.state_cache.clone_arc(),
                mutator_tx: self.owned_mutator_tx(),
                head_block_root: self.store.head().block_root,
                next_slot: self.store.slot(),
                pubkey_cache: self.pubkey_cache.clone_arc(),
                metrics: self.metrics.clone(),
            })
        }
    }

    fn spawn_preprocess_head_state_for_next_slot_task(&self) {
        if !self.store.is_forward_synced() {
            return;
        }

        self.spawn(PreprocessStateTask {
            store_snapshot: self.owned_store(),
            state_cache: self.state_cache.clone_arc(),
            mutator_tx: self.owned_mutator_tx(),
            head_block_root: self.store.head().block_root,
            next_slot: self.store.slot().saturating_add(1),
            pubkey_cache: self.pubkey_cache.clone_arc(),
            metrics: self.metrics.clone(),
        })
    }

    fn spawn_pubkey_cache_persist_task(
        &self,
        pubkey_cache: Arc<PubkeyCache>,
        wait_group: W,
        state: Arc<BeaconState<P>>,
    ) {
        self.spawn(PersistPubkeyCacheTask {
            pubkey_cache,
            state,
            wait_group,
            metrics: self.metrics.clone(),
        })
    }

    fn archive_finalized(&mut self, wait_group: &W) -> Result<()> {
        if self.is_archiving_finalized {
            return Ok(());
        }

        if let Some(latest_archivable_index) = self.store.latest_archivable_index() {
            debug_with_peers!("archiving finalized blocks and anchor state…");

            let state_at_slot_cache = self.state_at_slot_cache.clone_arc();
            let store = self.owned_store();
            let storage = self.storage.clone_arc();
            let sync_tx = self.sync_tx.clone();
            let mutator_tx = self.owned_mutator_tx();
            let wait_group = wait_group.clone();
            let finished_loading_from_storage = self.finished_loading_from_storage;

            // The blocks stay in the store until they are in storage, so queries never miss them.
            let archived = self.store.archivable_finalized(latest_archivable_index);

            let last_finalized_slot = self.store.last_finalized().slot();

            Builder::new()
                .name("store-archiver".to_owned())
                .spawn(move || {
                    // Storage writes are transactional and a panic counts as a failed save, so the
                    // blocks stay in the store and the next archive writes them again.
                    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                        debug_with_peers!("saving finalized blocks and anchor state…");

                        let saved = match storage.append(core::iter::empty(), archived.iter(), &store) {
                            Ok(slots) => {
                                if let Some(chain_link) = archived.back() {
                                    let finalized_block = chain_link.block.clone_arc();
                                    let anchor_epoch = misc::compute_epoch_at_slot::<P>(chain_link.slot());

                                    for candidate in &archived {
                                        let candidate_slot = candidate.slot();
                                        let candidate_epoch = misc::compute_epoch_at_slot::<P>(candidate_slot);

                                        let is_last_block = candidate_slot.saturating_add(1) == chain_link.slot();
                                        let is_first_block = candidate_epoch == anchor_epoch.saturating_sub(1)
                                            && misc::is_epoch_start::<P>(candidate_slot);

                                        // preload first and the last block of previous epoch into state_at_slot_cache
                                        // to handle some of the beacon API use cases
                                        if is_first_block || is_last_block {
                                            debug_with_peers!(
                                                "preloading state_at_slot_cache with chain_link: \
                                                slot: {candidate_slot}, epoch: {candidate_epoch}, \
                                                is_first_block: {is_first_block}, is_last_block: {is_last_block}",
                                            );

                                            if let Err(error) = state_at_slot_cache
                                                .get_or_try_init(candidate.slot(), || {
                                                    Ok(Some(candidate.state(&store)))
                                                })
                                            {
                                                debug_with_peers!(
                                                    "failed to preload state_at_slot_cache with \
                                                    a chainlink: {error:?}",
                                                );
                                            }
                                        }
                                    }

                                    if finished_loading_from_storage {
                                        SyncMessage::Finalized(finalized_block).send(&sync_tx);
                                    }
                                }

                                debug_with_peers!(
                                    "finalized blocks and anchor state saved \
                                     (appended block slots: {slots:?})",
                                );

                                true
                            }
                            Err(error) => {
                                error_with_peers!("saving to storage failed: {error:?}");
                                false
                            }
                        };

                        debug_with_peers!("removing unfinalized blocks");

                        if !storage.archive_storage_enabled() {
                            match storage.prune_unfinalized_blocks(last_finalized_slot) {
                                Ok(slots) => {
                                    debug_with_peers!(
                                        "unfinalized block pruning complete: pruned slots: {slots:?}"
                                    );
                                }
                                Err(error) => {
                                    error_with_peers!("unfinalized block pruning failed: {error:?}")
                                }
                            }
                        }

                        saved
                    }));

                    let saved = result.unwrap_or_else(|payload| {
                        panics::log(payload);
                        false
                    });

                    MutatorMessage::FinishedArchivingFinalized {
                        wait_group,
                        new_anchor_index: latest_archivable_index,
                        saved,
                    }
                    .send(&mutator_tx);
                })?;

            self.is_archiving_finalized = true;
        }

        Ok(())
    }

    fn prune_old_records(&self) -> Result<()> {
        if self.storage.archive_storage_enabled() {
            return Ok(());
        }

        let storage = self.storage.clone_arc();
        let data_up_to_epoch = self
            .store
            .min_checked_data_availability_epoch(self.store.slot());
        let data_up_to_slot = misc::compute_start_slot_at_epoch::<P>(data_up_to_epoch);
        let blocks_up_to_epoch = self.store.min_checked_block_availability_epoch();
        let blocks_up_to_slot = misc::compute_start_slot_at_epoch::<P>(blocks_up_to_epoch);
        let data_phase = self
            .store
            .chain_config()
            .phase_at_slot::<P>(data_up_to_slot);

        Builder::new()
            .name("old-data-pruner".to_owned())
            .spawn(move || {
                if data_phase.is_peerdas_activated() {
                    debug_with_peers!("pruning old data column sidecars from storage up to slot {data_up_to_slot}…");

                    match storage.prune_old_data_column_sidecars(data_up_to_slot) {
                        Ok(()) => {
                            debug_with_peers!(
                                "pruned old data column sidecars from storage up to slot {data_up_to_slot}"
                            );
                        }
                        Err(error) => {
                            error_with_peers!("pruning old data column sidecars from storage failed: {error:?}")
                        }
                    }
                } else {
                    debug_with_peers!("pruning old blob sidecars from storage up to slot {data_up_to_slot}…");

                    match storage.prune_old_blob_sidecars(data_up_to_slot) {
                        Ok(()) => {
                            debug_with_peers!(
                                "pruned old blob sidecars from storage up to slot {data_up_to_slot}"
                            );
                        }
                        Err(error) => {
                            error_with_peers!("pruning old blob sidecars from storage failed: {error:?}")
                        }
                    }
                }

                debug_with_peers!("pruning old execution payload envelopes from storage up to slot {blocks_up_to_slot}…");

                match storage.prune_old_execution_payload_envelopes(blocks_up_to_slot) {
                    Ok(()) => {
                        debug_with_peers!(
                            "pruned old execution payload envelopes from storage up to slot {blocks_up_to_slot}"
                        );
                    }
                    Err(error) => {
                        error_with_peers!("pruning old execution payload envelopes from storage failed: {error:?}")
                    }
                }

                debug_with_peers!("pruning old blocks and states from storage up to slot {blocks_up_to_slot}…");

                match storage.prune_old_blocks_and_states(blocks_up_to_slot) {
                    Ok(()) => {
                        debug_with_peers!(
                            "pruned old blocks and states from storage up to slot {blocks_up_to_slot}"
                        );
                    }
                    Err(error) => {
                        error_with_peers!("pruning old blocks and states from storage failed: {error:?}")
                    }
                }

                debug_with_peers!("pruning old state roots from storage up to slot {blocks_up_to_slot}…");

                match storage.prune_old_state_roots(blocks_up_to_slot) {
                    Ok(()) => {
                        debug_with_peers!(
                            "pruned old state roots from storage up to slot {blocks_up_to_slot}"
                        );
                    }
                    Err(error) => {
                        error_with_peers!("pruning old state roots from storage failed: {error:?}")
                    }
                }
            })?;

        Ok(())
    }

    fn persist_pubkey_cache(&self, wait_group: &W) {
        let store = &self.store;
        let chain_link = store.last_finalized();

        self.spawn_pubkey_cache_persist_task(
            self.pubkey_cache.clone_arc(),
            wait_group.clone(),
            chain_link.state(store),
        );
    }

    // This method should only be called when `Mutator.store` is in a consistent state.
    fn update_store_snapshot(&self) {
        // `ArcSwap::rcu` is not necessary here because there is only one thread mutating the store.
        self.store_snapshot.store(self.owned_store());
    }

    fn spawn(&self, task: impl Spawn<P, E, W>) {
        self.thread_pool.spawn(task);
    }

    fn store_mut(&mut self) -> &mut Store<P, Storage<P>> {
        self.store.make_mut()
    }

    // This uses `Mutator.store` instead of `Mutator.store_snapshot` for better performance.
    // `ArcSwap::load` and `ArcSwap::load_full` are surprisingly slow, to the point where it's
    // faster to clone a `Store` with all the `Arc`s inside it and allocate another `Arc`.
    //
    // As a result, this method should only be called when `Mutator.store` is in a consistent state.
    fn owned_store(&self) -> Arc<Store<P, Storage<P>>> {
        self.store.clone_arc()
    }

    fn owned_mutator_tx(&self) -> Sender<MutatorMessage<P, W>> {
        self.mutator_tx.clone()
    }

    fn send_to_attestation_verifier(&self, message: AttestationVerifierMessage<P, W>) {
        if self.finished_loading_from_storage {
            message.send(&self.attestation_verifier_tx);
        }
    }

    fn send_to_p2p(&self, message: P2pMessage<P>) {
        if self.finished_loading_from_storage {
            message.send(&self.p2p_tx);
        }
    }

    fn mark_sidecar_as_being_reconstructed(
        &self,
        data_column_identifier: DataColumnIdentifier,
        slot: Slot,
    ) {
        self.sidecars_pending_reconstruction.upsert_sync(
            data_column_identifier,
            (slot, tokio::sync::broadcast::channel(1).0),
        );
    }

    fn send_to_pool(&self, message: PoolMessage<P, W>) {
        if self.finished_loading_from_storage {
            message.send(&self.pool_tx);
        }
    }

    fn send_to_subnet_service(&self, message: SubnetMessage<W>) {
        if self.finished_loading_from_storage {
            message.send(&self.subnet_tx);
        }
    }

    fn send_to_validator(&self, message: ValidatorMessage<P, W>) {
        if self.finished_loading_from_storage {
            message.send(&self.validator_tx);
        }
    }

    fn track_epoch_transition_metrics(
        head_state: &Arc<BeaconState<P>>,
        metrics: &Arc<Metrics>,
    ) -> Result<()> {
        metrics.set_beacon_processed_deposits_total(head_state.eth1_deposit_index());
        metrics.set_validator_count(head_state.validators().len_usize());
        metrics.set_beacon_current_active_validators(
            accessors::get_active_validator_indices(head_state, RelativeEpoch::Current)?.count(),
        );

        Ok(())
    }

    fn track_head_metrics(head: &ChainLink<P>, metrics: &Arc<Metrics>) {
        metrics.set_beacon_head_slot(head.slot());
    }

    #[expect(clippy::too_many_lines)]
    fn track_collection_metrics(&self) {
        if let Some(metrics) = self.metrics.as_ref() {
            let type_name = tynm::type_name::<Self>();

            let (high_priority_tasks, mid_priority_tasks, low_priority_tasks) =
                self.thread_pool.task_counts();

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_blobs",
                self.delayed_until_blobs.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block",
                self.delayed_until_block.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_data",
                self.delayed_until_data.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block_blob_sidecars",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.blob_sidecars.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block_data_columns",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.data_column_sidecars.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block_blocks",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.blocks.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block_unverified_blocks",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.unverified_blocks.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block_attestations",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.attestations.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block_aggregates",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.aggregates.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block_execution_payload_envelopes",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.execution_payload_envelopes.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block_payload_attestations",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.payload_attestations.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_block_proposer_preferences",
                self.delayed_until_block
                    .values()
                    .map(|delayed| delayed.proposer_preferences.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_payload",
                self.delayed_until_payload.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_slot",
                self.delayed_until_slot.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_slot_blocks",
                self.delayed_until_slot
                    .values()
                    .map(|delayed| delayed.blocks.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_slot_attestations",
                self.delayed_until_slot
                    .values()
                    .map(|delayed| delayed.attestations.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_slot_aggregates",
                self.delayed_until_slot
                    .values()
                    .map(|delayed| delayed.aggregates.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_slot_blob_sidecars",
                self.delayed_until_slot
                    .values()
                    .map(|delayed| delayed.blob_sidecars.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_slot_data_column_sidecars",
                self.delayed_until_slot
                    .values()
                    .map(|delayed| delayed.data_column_sidecars.len())
                    .sum(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "delayed_until_state",
                self.delayed_until_state.len(),
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "high_priority_tasks",
                high_priority_tasks,
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "mid_priority_tasks",
                mid_priority_tasks,
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "low_priority_tasks",
                low_priority_tasks,
            );

            metrics.set_collection_length(
                module_path!(),
                &type_name,
                "sidecars_pending_reconstruction",
                self.sidecars_pending_reconstruction.len(),
            );

            self.event_channels.track_collection_metrics(metrics);
            self.pubkey_cache.track_collection_metrics(metrics);
            self.store.track_collection_metrics(metrics);
        }
    }

    fn block_blob_availability<'blob>(
        &self,
        block: &SignedBeaconBlock<P>,
        pending_blobs_for_block: impl Iterator<Item = &'blob BlobSidecar<P>>,
    ) -> BlockBlobAvailability {
        let Some(body) = block.message().body().with_blob_kzg_commitments() else {
            return BlockBlobAvailability::Irrelevant;
        };

        let missing_blob_indices = self.store.indices_of_missing_blobs(block);

        if missing_blob_indices.is_empty() {
            return BlockBlobAvailability::Complete;
        }

        let pending_missing_blobs = pending_blobs_for_block
            .filter(|blob_sidecar| missing_blob_indices.contains(&blob_sidecar.index))
            .collect_vec();

        let all_blobs_downloaded = body
            .blob_kzg_commitments()
            .into_iter()
            .zip(0..)
            .filter(|(_, index)| missing_blob_indices.contains(index))
            .all(|(block_commitment, index)| {
                pending_missing_blobs.iter().any(|blob_sidecar| {
                    blob_sidecar.index == index && blob_sidecar.kzg_commitment == *block_commitment
                })
            });

        if all_blobs_downloaded {
            return BlockBlobAvailability::CompleteWithPending;
        }

        BlockBlobAvailability::Missing(missing_blob_indices)
    }

    fn block_data_column_availability<'column>(
        &self,
        block: &SignedBeaconBlock<P>,
        mut pending_data_columns_for_block: impl Iterator<Item = &'column DataColumnSidecar<P>>,
    ) -> BlockDataColumnAvailability {
        if !block.phase().is_peerdas_activated() {
            return BlockDataColumnAvailability::Irrelevant;
        }

        let Some(body) = block.message().body().with_blob_kzg_commitments() else {
            return BlockDataColumnAvailability::Irrelevant;
        };

        let missing_indices = self.store.indices_of_missing_data_columns(block);

        if missing_indices.is_empty() {
            return BlockDataColumnAvailability::Complete;
        }

        let available_columns_count = self
            .store
            .sampling_columns_count()
            .saturating_sub(missing_indices.len());

        let any_pending_columns = pending_data_columns_for_block.any(|data_column_sidecar| {
            missing_indices.contains(&data_column_sidecar.index())
                && data_column_sidecar
                    .kzg_commitments()
                    .is_none_or(|kzg_commiments| {
                        itertools::equal(kzg_commiments, body.blob_kzg_commitments())
                    })
        });

        if any_pending_columns {
            return BlockDataColumnAvailability::AnyPending;
        }

        if available_columns_count.saturating_mul(2) >= P::NumberOfColumns::USIZE
            && (self.store.is_forward_synced()
                || !self.store.store_config().sync_without_reconstruction)
        {
            return BlockDataColumnAvailability::CompleteWithReconstruction {
                import_block: self.store.is_forward_synced(),
            };
        }

        BlockDataColumnAvailability::Missing(missing_indices)
    }
}

fn reply_to_http_api(
    sender: Option<OneshotSender<Result<ValidationOutcome>>>,
    reply: Result<ValidationOutcome>,
) {
    if let Some(sender) = sender
        && let Err(reply) = sender.send(reply)
    {
        debug_with_peers!("reply to HTTP API failed because the receiver was dropped: {reply:?}");
    }
}

fn reply_block_validation_result_to_http_api(
    sender: Option<MultiSender<Result<ValidationOutcome>>>,
    reply: Result<ValidationOutcome>,
) {
    if let Some(mut sender) = sender
        && let Err(reply) = sender.try_send(reply)
    {
        debug_with_peers!("reply to HTTP API failed because the receiver was dropped: {reply:?}");
    }
}

fn reply_execution_payload_bid_validation_result_to_http_api(
    sender: Option<OneshotSender<Result<ValidationOutcomeWithReason>>>,
    reply: Result<ValidationOutcomeWithReason>,
) {
    if let Some(sender) = sender
        && let Err(reply) = sender.send(reply)
    {
        debug_with_peers!("reply to HTTP API failed because the receiver was dropped: {reply:?}");
    }
}

fn reply_execution_proof_validation_result_to_http_api(
    sender: Option<OneshotSender<Result<ValidationOutcomeWithReason>>>,
    reply: Result<ValidationOutcomeWithReason>,
) {
    if let Some(sender) = sender
        && let Err(reply) = sender.send(reply)
    {
        debug_with_peers!("reply to HTTP API failed because the receiver was dropped: {reply:?}");
    }
}

fn reply_payload_envelope_validation_result_to_http_api(
    sender: Option<MultiSender<Result<ValidationOutcome>>>,
    reply: Result<ValidationOutcome>,
) {
    if let Some(mut sender) = sender
        && let Err(reply) = sender.try_send(reply)
    {
        debug_with_peers!("reply to HTTP API failed because the receiver was dropped: {reply:?}");
    }
}

fn reply_delayed_block_validation_result<P: Preset>(
    pending_block: PendingBlock<P>,
    reply: Result<ValidationOutcome>,
) -> PendingBlock<P> {
    let PendingBlock {
        block,
        origin,
        processing_timings,
        tracing_span,
    } = pending_block;

    if let BlockOrigin::Api(Some(sender)) = origin {
        reply_block_validation_result_to_http_api(Some(sender), reply);

        PendingBlock {
            block,
            origin: BlockOrigin::Api(None),
            processing_timings,
            tracing_span,
        }
    } else {
        PendingBlock {
            block,
            origin,
            processing_timings,
            tracing_span,
        }
    }
}

const fn is_requested_envelope<P: Preset>(pending: &PendingExecutionPayloadEnvelope<P>) -> bool {
    matches!(pending.origin, ExecutionPayloadEnvelopeOrigin::Requested(_))
}

// Requested (sync) and other envelopes have separate limits.
// So a sync backlog can't crowd out gossip, and the other way round.
const fn delayed_execution_payload_envelopes_until_block_limit<P: Preset>(
    requested: bool,
) -> usize {
    if requested {
        MAX_DELAYED_REQUESTED_ENVELOPES_UNTIL_BLOCK_IN_EPOCHS
            .saturating_mul(P::SlotsPerEpoch::USIZE)
    } else {
        MAX_DELAYED_BLOCKS_UNTIL_PARENT
    }
}

fn count_delayed_execution_payload_envelopes_until_block<P: Preset>(
    delayed_until_block: &HashMap<H256, Delayed<P>>,
    requested: bool,
) -> usize {
    delayed_until_block
        .values()
        .flat_map(|delayed| &delayed.execution_payload_envelopes)
        .filter(|pending| is_requested_envelope(pending) == requested)
        .count()
}

// Makes room for `pending` in the delayed until block queue.
// Returns the envelope evicted to make room, if any.
// Fails if the queue is full and nothing can be evicted.
fn make_room_for_delayed_execution_payload_envelope<P: Preset>(
    delayed_until_block: &mut HashMap<H256, Delayed<P>>,
    pending: &PendingExecutionPayloadEnvelope<P>,
) -> Result<Option<(H256, PendingExecutionPayloadEnvelope<P>)>> {
    // Envelopes produced by the application itself should never be dropped.
    if matches!(pending.origin, ExecutionPayloadEnvelopeOrigin::Own) {
        return Ok(None);
    }

    let requested = is_requested_envelope(pending);

    if count_delayed_execution_payload_envelopes_until_block(delayed_until_block, requested)
        < delayed_execution_payload_envelopes_until_block_limit::<P>(requested)
    {
        return Ok(None);
    }

    let slot = pending.execution_payload_envelope.slot();

    evict_delayed_execution_payload_envelope_until_block(delayed_until_block, requested, slot)
        .map(Some)
        .ok_or_else(|| Error::<P>::DelayedUntilBlockQueueFull.into())
}

// Frees a queue slot by dropping the highest-slot envelope.
// Only drops it if it is above `slot`.
// The head needs the lowest slots first, so those are kept.
// Own envelopes are never dropped.
fn evict_delayed_execution_payload_envelope_until_block<P: Preset>(
    delayed_until_block: &mut HashMap<H256, Delayed<P>>,
    requested: bool,
    slot: Slot,
) -> Option<(H256, PendingExecutionPayloadEnvelope<P>)> {
    let (block_root, index, _) = delayed_until_block
        .iter()
        .flat_map(|(block_root, delayed)| {
            delayed
                .execution_payload_envelopes
                .iter()
                .enumerate()
                .map(move |(index, pending)| (*block_root, index, pending))
        })
        .filter(|(_, _, pending)| {
            is_requested_envelope(pending) == requested
                && !matches!(pending.origin, ExecutionPayloadEnvelopeOrigin::Own)
        })
        .map(|(block_root, index, pending)| {
            (block_root, index, pending.execution_payload_envelope.slot())
        })
        .filter(|(_, _, evicted_slot)| *evicted_slot > slot)
        .max_by_key(|(_, _, evicted_slot)| *evicted_slot)?;

    let delayed = delayed_until_block.get_mut(&block_root)?;
    let evicted = delayed.execution_payload_envelopes.swap_remove(index);

    if delayed.is_empty() {
        delayed_until_block.remove(&block_root);
    }

    Some((block_root, evicted))
}

fn reply_delayed_payload_envelope_validation_result<P: Preset>(
    pending_envelope: PendingExecutionPayloadEnvelope<P>,
    reply: Result<ValidationOutcome>,
) -> PendingExecutionPayloadEnvelope<P> {
    let PendingExecutionPayloadEnvelope {
        execution_payload_envelope,
        origin,
        seen_before_deadline,
        processing_timings,
        tracing_span,
    } = pending_envelope;

    if let ExecutionPayloadEnvelopeOrigin::Api(Some(sender)) = origin {
        reply_payload_envelope_validation_result_to_http_api(Some(sender), reply);

        PendingExecutionPayloadEnvelope {
            execution_payload_envelope,
            origin: ExecutionPayloadEnvelopeOrigin::Api(None),
            seen_before_deadline,
            processing_timings,
            tracing_span,
        }
    } else {
        PendingExecutionPayloadEnvelope {
            execution_payload_envelope,
            origin,
            seen_before_deadline,
            processing_timings,
            tracing_span,
        }
    }
}

fn reply_delayed_blob_sidecar_validation_result<P: Preset>(
    pending_blob_sidecar: PendingBlobSidecar<P>,
    reply: Result<ValidationOutcome>,
) -> PendingBlobSidecar<P> {
    let PendingBlobSidecar {
        blob_sidecar,
        block_seen,
        origin,
        submission_time,
    } = pending_blob_sidecar;

    if let BlobSidecarOrigin::Api(Some(sender)) = origin {
        reply_to_http_api(Some(sender), reply);

        PendingBlobSidecar {
            blob_sidecar,
            block_seen,
            origin: BlobSidecarOrigin::Api(None),
            submission_time,
        }
    } else {
        PendingBlobSidecar {
            blob_sidecar,
            block_seen,
            origin,
            submission_time,
        }
    }
}

fn reply_delayed_data_column_sidecar_validation_result<P: Preset>(
    pending_data_column_sidecar: PendingDataColumnSidecar<P>,
    reply: Result<ValidationOutcome>,
) -> PendingDataColumnSidecar<P> {
    let PendingDataColumnSidecar {
        data_column_sidecar,
        block_seen,
        origin,
        submission_time,
    } = pending_data_column_sidecar;

    if let DataColumnSidecarOrigin::Api(Some(sender)) = origin {
        reply_to_http_api(Some(sender), reply);

        PendingDataColumnSidecar {
            data_column_sidecar,
            block_seen,
            origin: DataColumnSidecarOrigin::Api(None),
            submission_time,
        }
    } else {
        PendingDataColumnSidecar {
            data_column_sidecar,
            block_seen,
            origin,
            submission_time,
        }
    }
}

#[cfg(test)]
mod tests {
    use eth2_libp2p::PeerId;
    use types::{gloas::containers::SignedExecutionPayloadEnvelope, preset::Minimal};

    use super::*;

    type Queue = HashMap<H256, Delayed<Minimal>>;

    fn requested_envelope() -> ExecutionPayloadEnvelopeOrigin {
        ExecutionPayloadEnvelopeOrigin::Requested(PeerId::random())
    }

    fn gossip_envelope() -> ExecutionPayloadEnvelopeOrigin {
        ExecutionPayloadEnvelopeOrigin::Gossip(GossipId::default())
    }

    fn requested_envelope_limit() -> usize {
        delayed_execution_payload_envelopes_until_block_limit::<Minimal>(true)
    }

    fn gossip_envelope_limit() -> usize {
        delayed_execution_payload_envelopes_until_block_limit::<Minimal>(false)
    }

    fn pending_envelope(
        origin: ExecutionPayloadEnvelopeOrigin,
        slot: Slot,
    ) -> PendingExecutionPayloadEnvelope<Minimal> {
        let mut envelope = SignedExecutionPayloadEnvelope::<Minimal>::default();
        envelope.message.payload.slot_number = slot;

        PendingExecutionPayloadEnvelope {
            execution_payload_envelope: Arc::new(envelope),
            origin,
            seen_before_deadline: false,
            processing_timings: ProcessingTimings::new(),
            tracing_span: Span::none(),
        }
    }

    // One block root per slot, like forward sync.
    fn root(slot: Slot) -> H256 {
        H256::from_low_u64_be(slot)
    }

    fn insert_into_queue(queue: &mut Queue, pending: PendingExecutionPayloadEnvelope<Minimal>) {
        let slot = pending.execution_payload_envelope.slot();

        queue
            .entry(root(slot))
            .or_default()
            .execution_payload_envelopes
            .push(pending);
    }

    // Fills `count` envelopes at slots `first_slot..first_slot + count`.
    fn fill_queue(
        queue: &mut Queue,
        origin: impl Fn() -> ExecutionPayloadEnvelopeOrigin,
        first_slot: Slot,
        count: usize,
    ) {
        for slot in (first_slot..).take(count) {
            insert_into_queue(queue, pending_envelope(origin(), slot));
        }
    }

    fn assert_queue_full(result: Result<Option<(H256, PendingExecutionPayloadEnvelope<Minimal>)>>) {
        let error = result.expect_err("envelope should be rejected");

        assert!(matches!(
            error.downcast_ref(),
            Some(Error::<Minimal>::DelayedUntilBlockQueueFull),
        ));
    }

    fn queued_slots(queue: &Queue) -> Vec<Slot> {
        let mut slots = queue
            .values()
            .flat_map(|delayed| &delayed.execution_payload_envelopes)
            .map(|pending| pending.execution_payload_envelope.slot())
            .collect_vec();

        slots.sort_unstable();
        slots
    }

    #[test]
    fn requested_limit_covers_many_sync_batches() {
        // 16 epochs, well above the old shared limit of 64 on mainnet.
        assert_eq!(requested_envelope_limit(), 16 * 8);
        assert_eq!(gossip_envelope_limit(), MAX_DELAYED_BLOCKS_UNTIL_PARENT);
    }

    #[test]
    fn admits_envelope_below_limit() -> Result<()> {
        let mut queue = Queue::new();

        fill_queue(
            &mut queue,
            requested_envelope,
            100,
            requested_envelope_limit() - 1,
        );

        let evicted = make_room_for_delayed_execution_payload_envelope(
            &mut queue,
            &pending_envelope(requested_envelope(), 1),
        )?;

        assert!(evicted.is_none());
        assert_eq!(queued_slots(&queue).len(), requested_envelope_limit() - 1);

        Ok(())
    }

    #[test]
    fn evicts_highest_slot_when_full() -> Result<()> {
        let mut queue = Queue::new();
        let limit = requested_envelope_limit() as Slot;

        fill_queue(
            &mut queue,
            requested_envelope,
            100,
            requested_envelope_limit(),
        );

        let (evicted_root, evicted) = make_room_for_delayed_execution_payload_envelope(
            &mut queue,
            &pending_envelope(requested_envelope(), 50),
        )?
        .expect("an envelope should be evicted");

        let highest_slot = 100 + limit - 1;

        assert_eq!(evicted.execution_payload_envelope.slot(), highest_slot);
        assert_eq!(evicted_root, root(highest_slot));

        // Emptied entries are removed.
        assert!(!queue.contains_key(&root(highest_slot)));
        assert_eq!(queued_slots(&queue), (100..highest_slot).collect_vec());

        Ok(())
    }

    #[test]
    fn rejects_envelope_above_all_queued_when_full() {
        let mut queue = Queue::new();

        fill_queue(
            &mut queue,
            requested_envelope,
            100,
            requested_envelope_limit(),
        );

        let before = queued_slots(&queue);
        let result = make_room_for_delayed_execution_payload_envelope(
            &mut queue,
            &pending_envelope(requested_envelope(), 10_000),
        );

        assert_queue_full(result);
        assert_eq!(queued_slots(&queue), before);
    }

    #[test]
    fn rejects_envelope_at_same_slot_as_highest_when_full() {
        let mut queue = Queue::new();
        let highest_slot = 100 + requested_envelope_limit() as Slot - 1;

        fill_queue(
            &mut queue,
            requested_envelope,
            100,
            requested_envelope_limit(),
        );

        let result = make_room_for_delayed_execution_payload_envelope(
            &mut queue,
            &pending_envelope(requested_envelope(), highest_slot),
        );

        assert_queue_full(result);
    }

    #[test]
    fn full_requested_queue_does_not_block_gossip() -> Result<()> {
        let mut queue = Queue::new();

        fill_queue(
            &mut queue,
            requested_envelope,
            100,
            requested_envelope_limit(),
        );

        let evicted = make_room_for_delayed_execution_payload_envelope(
            &mut queue,
            &pending_envelope(gossip_envelope(), 10_000),
        )?;

        assert!(evicted.is_none());

        Ok(())
    }

    #[test]
    fn full_gossip_queue_does_not_block_requested() -> Result<()> {
        let mut queue = Queue::new();

        fill_queue(&mut queue, gossip_envelope, 100, gossip_envelope_limit());

        let evicted = make_room_for_delayed_execution_payload_envelope(
            &mut queue,
            &pending_envelope(requested_envelope(), 10_000),
        )?;

        assert!(evicted.is_none());

        Ok(())
    }

    #[test]
    fn evicts_only_from_same_class() -> Result<()> {
        let mut queue = Queue::new();

        fill_queue(&mut queue, gossip_envelope, 100, gossip_envelope_limit());

        // Higher than every gossip envelope, but in the other class.
        insert_into_queue(&mut queue, pending_envelope(requested_envelope(), 10_000));

        let (_, evicted) = make_room_for_delayed_execution_payload_envelope(
            &mut queue,
            &pending_envelope(gossip_envelope(), 50),
        )?
        .expect("an envelope should be evicted");

        assert_eq!(
            evicted.execution_payload_envelope.slot(),
            100 + gossip_envelope_limit() as Slot - 1,
        );
        assert!(queue.contains_key(&root(10_000)));

        Ok(())
    }

    #[test]
    fn never_evicts_own_envelopes() {
        let mut queue = Queue::new();

        fill_queue(
            &mut queue,
            || ExecutionPayloadEnvelopeOrigin::Own,
            100,
            gossip_envelope_limit(),
        );

        let before = queued_slots(&queue);
        let result = make_room_for_delayed_execution_payload_envelope(
            &mut queue,
            &pending_envelope(gossip_envelope(), 1),
        );

        assert_queue_full(result);
        assert_eq!(queued_slots(&queue), before);
    }

    #[test]
    fn always_admits_own_envelopes() -> Result<()> {
        let mut queue = Queue::new();

        fill_queue(&mut queue, gossip_envelope, 100, gossip_envelope_limit());

        let evicted = make_room_for_delayed_execution_payload_envelope(
            &mut queue,
            &pending_envelope(ExecutionPayloadEnvelopeOrigin::Own, 10_000),
        )?;

        assert!(evicted.is_none());
        assert_eq!(queued_slots(&queue).len(), gossip_envelope_limit());

        Ok(())
    }

    #[test]
    fn keeps_entry_that_still_has_objects() -> Result<()> {
        let mut queue = Queue::new();

        fill_queue(
            &mut queue,
            requested_envelope,
            100,
            requested_envelope_limit() - 1,
        );

        // Two envelopes for the same block, e.g. from different peers.
        let shared_slot = 1_000;
        insert_into_queue(
            &mut queue,
            pending_envelope(requested_envelope(), shared_slot),
        );
        insert_into_queue(
            &mut queue,
            pending_envelope(requested_envelope(), shared_slot),
        );

        let (evicted_root, _) = make_room_for_delayed_execution_payload_envelope(
            &mut queue,
            &pending_envelope(requested_envelope(), 50),
        )?
        .expect("an envelope should be evicted");

        assert_eq!(evicted_root, root(shared_slot));
        assert_eq!(
            queue[&root(shared_slot)].execution_payload_envelopes.len(),
            1,
        );

        Ok(())
    }

    // Controlled service-stage fixture: these coherent links model already-validated ChainLink
    // outputs. They exercise public FFG and Store lifecycle APIs, not full block-import reachability.
    mod execution_proof_tests {
        use core::{
            sync::atomic::{AtomicUsize, Ordering},
            time::Duration,
        };
        use std::{
            collections::{HashMap, HashSet},
            sync::{
                Arc, Mutex,
                mpsc::{self, Receiver, SyncSender},
            },
            time::Instant,
        };

        use arc_swap::ArcSwap;
        use bls::{SecretKey, SecretKeyBytes, SignatureBytes, traits::SecretKey as _};
        use clock::Tick;
        use database::Database;
        use eth2_libp2p::{GossipId, MessageId, PeerId};
        use execution_engine::MockExecutionEngine;
        use fork_choice_store::{
            ChainLink, ExecutionPayloadEnvelopeOrigin, ExecutionPayloadEnvelopeValidationAction,
            ExecutionProofAdmission, ExecutionProofAdmissionDecline, ExecutionProofOrigin,
            ExecutionProofPreparation, PayloadPresence, Store, StoreConfig,
        };
        use futures::sink::Drain;
        use helper_functions::{
            accessors, misc,
            signing::{SignForSingleFork as _, SignForSingleForkAtSlot},
            verifier::MultiVerifier,
        };
        use proof_engine::{ProofEngine, ProofVerdict};
        use pubkey_cache::PubkeyCache;
        use scc::HashMap as SccHashMap;
        use ssz::{Hc, ProgressiveList, SszHash as _, SszList as _, SszListMut as _};
        use std_ext::ArcExt;
        use transition_functions::combined;
        use types::{
            altair::consts::TIMELY_TARGET_FLAG_INDEX,
            combined::{BeaconState, SignedBeaconBlock},
            config::Config,
            eip8025::{
                containers::{
                    ExecutionProof, ExecutionProofEnvelope, ProofData, SignedExecutionProofEnvelope,
                },
                primitives::get_supported_proof_types,
            },
            gloas::{
                beacon_state::BeaconState as GloasBeaconState,
                consts::BUILDER_INDEX_SELF_BUILD,
                containers::{
                    BeaconBlock as GloasBeaconBlock, BeaconBlockBody as GloasBeaconBlockBody,
                    ExecutionPayload as GloasExecutionPayload, ExecutionPayloadBid,
                    ExecutionPayloadEnvelope, ExecutionRequests,
                    SignedBeaconBlock as GloasSignedBeaconBlock, SignedExecutionPayloadBid,
                    SignedExecutionPayloadEnvelope,
                },
            },
            nonstandard::{PayloadStatus, Phase, StorageMode, ValidationOutcomeWithReason},
            phase0::{
                consts::FAR_FUTURE_EPOCH,
                containers::{BeaconBlockHeader, Checkpoint, Validator},
                primitives::{ExecutionBlockHash, H256, Slot},
            },
            preset::Minimal,
            traits::{BeaconState as _, SignedBeaconBlock as _},
        };

        use crate::{
            block_processor::BlockProcessor,
            events::EventChannels,
            messages::{
                AttestationVerifierMessage, MutatorMessage, P2pMessage, PoolMessage, SubnetMessage,
                SyncMessage, ValidatorMessage,
            },
            misc::{MutatorRejectionReason, PendingExecutionPayloadEnvelope, ProcessingTimings},
            mutator::Mutator,
            specialized::TestExecutionEngine,
            state_at_slot_cache::StateAtSlotCache,
            storage::{DEFAULT_ARCHIVAL_EPOCH_INTERVAL, DEFAULT_ZSTD_COMPRESSION_LEVEL, Storage},
            tasks::{ProcessExecutionProofTask, Run},
            thread_pool::ThreadPool,
            unbounded_sink::UnboundedSink,
        };

        type ControlStore = Store<Minimal, Storage<Minimal>>;
        type TestMutator = Mutator<
            Minimal,
            TestExecutionEngine<Minimal>,
            (),
            Drain<AttestationVerifierMessage<Minimal, ()>>,
            ObservingP2pSink,
            Drain<PoolMessage<Minimal, ()>>,
            Drain<SubnetMessage<()>>,
            Drain<SyncMessage<Minimal>>,
            Drain<ValidatorMessage<Minimal, ()>>,
        >;

        const TEST_TIMEOUT: Duration = Duration::from_secs(10);
        // Minimal has eight slots per epoch; real PTC processing needs a nonempty
        // committee in each slot. Validators 0/1/2 remain the proof signers.
        const VALIDATOR_COUNT: usize = 8;
        const EFFECTIVE_BALANCE: u64 = 32_000_000_000;
        const PROOF_TYPE: u8 = 1;
        const TARGET_FLAG: u8 = 1 << TIMELY_TARGET_FLAG_INDEX;

        type ApiValidationResult = anyhow::Result<ValidationOutcomeWithReason>;
        type ApiResponseReceiver = futures::channel::oneshot::Receiver<ApiValidationResult>;

        #[derive(Clone, Copy)]
        enum ProofOriginKind {
            Gossip,
            Api,
        }

        #[derive(Clone, Copy)]
        enum VerificationScenario {
            Verdict(ProofVerdict),
            StoppedPool,
        }

        fn make_proof_origin(
            kind: ProofOriginKind,
            gossip_id: &GossipId,
        ) -> (ExecutionProofOrigin, Option<ApiResponseReceiver>) {
            match kind {
                ProofOriginKind::Gossip => (ExecutionProofOrigin::Gossip(gossip_id.clone()), None),
                ProofOriginKind::Api => {
                    let (sender, receiver) = futures::channel::oneshot::channel();
                    (ExecutionProofOrigin::Api(sender), Some(receiver))
                }
            }
        }

        fn assert_proof_origin(
            origin: &ExecutionProofOrigin,
            kind: ProofOriginKind,
            attempt: &ProofAttempt,
        ) {
            match kind {
                ProofOriginKind::Gossip => {
                    assert_gossip_identity(origin.gossip_id_ref(), &attempt.gossip_id);
                }
                ProofOriginKind::Api => {
                    assert!(matches!(origin, ExecutionProofOrigin::Api(_)));
                    assert!(origin.gossip_id_ref().is_none());
                }
            }
        }

        fn assert_prepared_origin(
            message: &MutatorMessage<Minimal, ()>,
            kind: ProofOriginKind,
            attempt: &ProofAttempt,
        ) {
            match message {
                MutatorMessage::ExecutionProofPrepared {
                    result: Ok(ExecutionProofPreparation::Prepared(_)),
                    origin,
                    ..
                } => assert_proof_origin(origin, kind, attempt),
                _ => panic!("detached task must return genuine prepared proof authority"),
            }
        }

        const fn expected_proof_p2p(execution: VerificationScenario) -> (P2pOutcome, bool) {
            match execution {
                VerificationScenario::Verdict(ProofVerdict::Valid) => (P2pOutcome::Accept, false),
                VerificationScenario::Verdict(ProofVerdict::Invalid) => (P2pOutcome::Reject, true),
                VerificationScenario::Verdict(ProofVerdict::Undetermined)
                | VerificationScenario::StoppedPool => (P2pOutcome::Ignore, false),
            }
        }

        fn assert_proof_p2p_observation(
            observation: &P2pObservation,
            attempt: &ProofAttempt,
            execution: VerificationScenario,
        ) {
            let (expected_outcome, expected_rejection) = expected_proof_p2p(execution);
            assert_eq!(observation.outcome, expected_outcome);
            assert_gossip_identity(observation.gossip_id.as_ref(), &attempt.gossip_id);
            assert_eq!(
                observation.is_invalid_execution_proof_rejection,
                expected_rejection,
            );
            let stored_attempt = matches!(
                execution,
                VerificationScenario::Verdict(ProofVerdict::Valid),
            )
            .then_some(attempt);
            assert_observation(&observation.store, &[attempt], stored_attempt);
            assert_eq!(
                observation.stored_envelope.as_deref(),
                stored_attempt.map(|stored| &stored.envelope),
            );
        }

        fn assert_api_response(
            receiver: &mut ApiResponseReceiver,
            execution: VerificationScenario,
        ) {
            let response = receiver
                .try_recv()
                .expect("terminal API sender must not be canceled")
                .expect("closed proof batch must have one ready API response");
            match execution {
                VerificationScenario::Verdict(ProofVerdict::Valid) => {
                    assert!(matches!(response, Ok(ValidationOutcomeWithReason::Accept)));
                }
                VerificationScenario::Verdict(ProofVerdict::Invalid) => {
                    let Err(error) = response else {
                        panic!("invalid proof must produce the API error terminal");
                    };
                    assert_eq!(error.to_string(), "invalid execution proof");
                }
                VerificationScenario::Verdict(ProofVerdict::Undetermined)
                | VerificationScenario::StoppedPool => {
                    let Ok(ValidationOutcomeWithReason::Ignore(reason)) = response else {
                        panic!("local proof fault must produce the API Ignore terminal");
                    };
                    assert_eq!(reason, "local execution proof verification failure");
                }
            }
        }

        fn run_proof_service_case(kind: ProofOriginKind, execution: VerificationScenario) {
            let mut harness = ProofServiceHarness::new();
            harness.accept_anchor_payload();
            let snapshot = harness.store_snapshot.load_full();
            let attempt = build_proof_attempt(&harness.anchor, &snapshot, 0, 0xd1, 0x71);
            let (origin, mut api_receiver) = make_proof_origin(kind, &attempt.gossip_id);
            let prepared = harness.prepare_detached_with_origin(snapshot, &attempt, origin);
            assert_prepared_origin(&prepared, kind, &attempt);

            assert_eq!(harness.mutator.thread_pool.task_counts(), (0, 0, 0));
            assert!(matches!(
                harness.mutator.mutator_rx.try_recv(),
                Err(mpsc::TryRecvError::Empty),
            ));
            assert_eq!(harness.engine.invocation_count(), 0);
            assert!(harness.engine_events.try_recv().is_err());
            let pool_stopped = matches!(execution, VerificationScenario::StoppedPool);
            if pool_stopped {
                // ThreadPool::drop sets the shared done bit and wakes workers; live dispatch below
                // still owns authentic admitted authority and observes try_spawn's real failure.
                drop(harness.mutator.thread_pool.clone());
            } else {
                harness.releases.register(
                    &harness.engine,
                    AttemptId::A,
                    attempt.execution_proof.clone(),
                );
            }
            harness.deliver_prepared(prepared);

            if pool_stopped {
                assert_eq!(harness.engine.invocation_count(), 0);
                assert_eq!(harness.mutator.thread_pool.task_counts(), (0, 0, 0));
            } else {
                harness.observe_entry(AttemptId::A, &attempt, &[&attempt]);
                assert_eq!(harness.engine.invocation_count(), 1);
            }

            harness.seal_completion_batch();
            if let VerificationScenario::Verdict(verdict) = execution {
                harness.releases.release(AttemptId::A, verdict);
            }
            let completion_count = harness.drain_closed_batch(&attempt, kind);
            let expected_worker_count = usize::from(!pool_stopped);
            assert_eq!(completion_count, expected_worker_count);
            assert_eq!(harness.engine.invocation_count(), expected_worker_count);
            assert!(harness.engine_events.try_recv().is_err());
            assert_eq!(harness.mutator.thread_pool.task_counts(), (0, 0, 0));

            let stored_attempt = matches!(
                execution,
                VerificationScenario::Verdict(ProofVerdict::Valid),
            )
            .then_some(&attempt);
            assert_observation(
                &StoreObservation::capture(&harness.mutator.store),
                &[&attempt],
                stored_attempt,
            );
            assert_observation(
                &StoreObservation::capture(&harness.store_snapshot.load_full()),
                &[&attempt],
                stored_attempt,
            );

            let p2p_observations = harness.drain_p2p_observations();
            match kind {
                ProofOriginKind::Gossip => {
                    assert_eq!(p2p_observations.len(), 1);
                    let observation = p2p_observations
                        .into_iter()
                        .next()
                        .expect("one exact gossip terminal was observed");
                    assert_proof_p2p_observation(&observation, &attempt, execution);
                }
                ProofOriginKind::Api => assert!(p2p_observations.is_empty()),
            }
            match kind {
                ProofOriginKind::Gossip => assert!(api_receiver.is_none()),
                ProofOriginKind::Api => assert_api_response(
                    api_receiver
                        .as_mut()
                        .expect("API origin retains its one-shot receiver"),
                    execution,
                ),
            }
        }

        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        struct StoreObservation {
            seen_roots: HashMap<H256, HashSet<H256>>,
            seen_provers: HashSet<(H256, u8, u64)>,
            execution_proofs: HashMap<H256, HashMap<u8, ExecutionProofEnvelope>>,
        }

        impl StoreObservation {
            fn capture(store: &ControlStore) -> Self {
                Self {
                    seen_roots: store
                        .execution_proof_roots()
                        .iter()
                        .map(|(root, roots)| (*root, roots.iter().copied().collect()))
                        .collect(),
                    seen_provers: store.execution_proof_provers().iter().copied().collect(),
                    execution_proofs: store
                        .execution_proofs()
                        .iter()
                        .map(|(root, proofs)| {
                            (
                                *root,
                                proofs
                                    .iter()
                                    .map(|(proof_type, envelope)| {
                                        (*proof_type, envelope.as_ref().clone())
                                    })
                                    .collect(),
                            )
                        })
                        .collect(),
                }
            }
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum P2pOutcome {
            Accept,
            Ignore,
            Reject,
            Other,
        }

        struct P2pObservation {
            outcome: P2pOutcome,
            gossip_id: Option<GossipId>,
            is_invalid_execution_proof_rejection: bool,
            store: StoreObservation,
            stored_envelope: Option<Arc<ExecutionProofEnvelope>>,
        }

        #[derive(Clone)]
        struct ObservingP2pSink {
            store_snapshot: Arc<ArcSwap<ControlStore>>,
            sender: SyncSender<P2pObservation>,
        }

        impl UnboundedSink<P2pMessage<Minimal>> for ObservingP2pSink {
            fn clone(&self) -> Self {
                Clone::clone(self)
            }

            fn unbounded_send(
                &self,
                message: P2pMessage<Minimal>,
            ) -> Result<(), P2pMessage<Minimal>> {
                let (outcome, gossip_id) = match &message {
                    P2pMessage::Accept(gossip_id) => (P2pOutcome::Accept, Some(gossip_id.clone())),
                    P2pMessage::Ignore(gossip_id)
                    | P2pMessage::IgnoreWithReason(Some(gossip_id), _) => {
                        (P2pOutcome::Ignore, Some(gossip_id.clone()))
                    }
                    P2pMessage::Reject(gossip_id, _) => (P2pOutcome::Reject, gossip_id.clone()),
                    _ => (P2pOutcome::Other, None),
                };
                let store = self.store_snapshot.load_full();
                let observation = P2pObservation {
                    outcome,
                    gossip_id,
                    is_invalid_execution_proof_rejection: matches!(
                        &message,
                        P2pMessage::Reject(_, MutatorRejectionReason::InvalidExecutionProof,),
                    ),
                    store: StoreObservation::capture(&store),
                    stored_envelope: store
                        .execution_proofs()
                        .values()
                        .flat_map(|proofs| proofs.values())
                        .next()
                        .map(ArcExt::clone_arc),
                };

                self.sender.send(observation).map_err(|_| message)
            }
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        enum AttemptId {
            A,
            B,
        }

        struct RegisteredGate {
            id: AttemptId,
            expected_input: ExecutionProof,
            release: Receiver<ProofVerdict>,
        }

        struct EngineEvent {
            id: AttemptId,
            execution_proof: ExecutionProof,
            published_store: StoreObservation,
        }

        struct GatedProofEngine {
            store_snapshot: Arc<ArcSwap<ControlStore>>,
            registered: Mutex<Vec<RegisteredGate>>,
            events: SyncSender<EngineEvent>,
            invocations: AtomicUsize,
        }

        impl GatedProofEngine {
            fn register(
                &self,
                id: AttemptId,
                expected_input: ExecutionProof,
            ) -> SyncSender<ProofVerdict> {
                let (release_tx, release_rx) = mpsc::sync_channel(1);
                let mut registered = self
                    .registered
                    .lock()
                    .expect("test engine registry mutex should not be poisoned");
                assert!(registered.iter().all(|gate| gate.id != id));
                registered.push(RegisteredGate {
                    id,
                    expected_input,
                    release: release_rx,
                });
                release_tx
            }

            fn invocation_count(&self) -> usize {
                self.invocations.load(Ordering::SeqCst)
            }
        }

        impl ProofEngine for GatedProofEngine {
            fn is_null(&self) -> bool {
                false
            }

            fn verify_execution_proof(&self, execution_proof: ExecutionProof) -> ProofVerdict {
                self.invocations.fetch_add(1, Ordering::SeqCst);
                let gate = {
                    let mut registered = self
                        .registered
                        .lock()
                        .expect("test engine registry mutex should not be poisoned");
                    registered
                        .iter()
                        .position(|gate| gate.expected_input == execution_proof)
                        .map(|index| registered.remove(index))
                }
                .expect("only registered, actually admitted inputs may enter the verifier");
                let id = gate.id;
                let published_store = StoreObservation::capture(&self.store_snapshot.load_full());
                self.events
                    .send(EngineEvent {
                        id,
                        execution_proof,
                        published_store,
                    })
                    .expect("retirement tests keep the bounded engine observer alive");
                gate.release
                    .recv_timeout(TEST_TIMEOUT)
                    .expect("each entered verifier must receive an explicit test verdict")
            }
        }

        #[derive(Default)]
        struct GateReleaseGuard {
            releases: HashMap<AttemptId, SyncSender<ProofVerdict>>,
        }

        impl GateReleaseGuard {
            fn register(
                &mut self,
                engine: &GatedProofEngine,
                id: AttemptId,
                expected_input: ExecutionProof,
            ) {
                assert!(
                    self.releases
                        .insert(id, engine.register(id, expected_input))
                        .is_none(),
                    "attempt gate may be registered only once",
                );
            }

            fn release(&mut self, id: AttemptId, verdict: ProofVerdict) {
                self.releases
                    .remove(&id)
                    .expect("attempt release guard must own every pending gate")
                    .send(verdict)
                    .expect("entered verifier must still be waiting for its verdict");
            }
        }

        impl Drop for GateReleaseGuard {
            fn drop(&mut self) {
                for sender in self.releases.drain().map(|(_, sender)| sender) {
                    // Cleanup only: assertions never treat this fallback as a test result.
                    let _ = sender.try_send(ProofVerdict::Undetermined);
                }
            }
        }

        struct AnchorFixture {
            config: Arc<Config>,
            validator_keys: [SecretKey; VALIDATOR_COUNT],
            state: Arc<BeaconState<Minimal>>,
            block: Arc<SignedBeaconBlock<Minimal>>,
            block_root: H256,
            bid: ExecutionPayloadBid<Minimal>,
            payload: Arc<SignedExecutionPayloadEnvelope<Minimal>>,
        }

        impl AnchorFixture {
            fn new() -> Self {
                let mut config = Config::minimal().start_and_stay_in(Phase::Gloas);
                config.deposit_chain_id = 1337;
                let config = Arc::new(config);
                let validator_keys = [1, 2, 3, 4, 5, 6, 7, 8].map(test_validator_key);
                let (state, block, block_root, bid) =
                    build_anchor_block_and_state(&config, &validator_keys);
                let payload =
                    build_anchor_payload(&config, &state, &validator_keys, &bid, block_root);

                Self {
                    config,
                    validator_keys,
                    state: Arc::new(state),
                    block,
                    block_root,
                    bid,
                    payload,
                }
            }
        }

        fn build_anchor_block_and_state(
            config: &Config,
            validator_keys: &[SecretKey; VALIDATOR_COUNT],
        ) -> (
            BeaconState<Minimal>,
            Arc<SignedBeaconBlock<Minimal>>,
            H256,
            ExecutionPayloadBid<Minimal>,
        ) {
            let execution_requests = ExecutionRequests::<Minimal>::default();
            let bid = ExecutionPayloadBid {
                parent_block_hash: ExecutionBlockHash::default(),
                parent_block_root: H256::zero(),
                block_hash: ExecutionBlockHash::repeat_byte(0x44),
                prev_randao: H256::repeat_byte(0x55),
                gas_limit: 30_000_000,
                builder_index: BUILDER_INDEX_SELF_BUILD,
                slot: 0,
                execution_requests_root: execution_requests.hash_tree_root(),
                ..Default::default()
            };
            let body = block_body(bid.clone());
            let mut gloas_state = GloasBeaconState::<Minimal> {
                genesis_time: config.min_genesis_time,
                validators: validator_keys
                    .iter()
                    .map(|key| Validator {
                        pubkey: key.to_public_key().into(),
                        activation_epoch: 0,
                        exit_epoch: FAR_FUTURE_EPOCH,
                        effective_balance: EFFECTIVE_BALANCE,
                        ..Default::default()
                    })
                    .collect(),
                latest_block_header: BeaconBlockHeader {
                    body_root: body.hash_tree_root(),
                    ..Default::default()
                },
                latest_execution_payload_bid: bid.clone(),
                ..Default::default()
            };
            initialize_validator_lists(&mut gloas_state);
            let state = BeaconState::from(gloas_state);
            let state_root = state.hash_tree_root();
            let signed_block = GloasSignedBeaconBlock {
                message: Hc::from(GloasBeaconBlock {
                    state_root,
                    body,
                    ..Default::default()
                }),
                signature: SignatureBytes::default(),
            };
            let block_root = signed_block.message.hash_tree_root();
            assert_eq!(state.slot(), signed_block.message.slot);
            assert_eq!(state.hash_tree_root(), state_root);
            assert_eq!(signed_block.message.state_root, state_root);
            assert_eq!(
                signed_block.message.body.hash_tree_root(),
                state.latest_block_header().body_root,
            );
            assert_eq!(state.latest_block_header().state_root, H256::zero());
            assert_eq!(accessors::latest_block_root(&state), block_root);
            assert_eq!(state.validators().len_usize(), VALIDATOR_COUNT);
            assert_eq!(state.balances().len_usize(), VALIDATOR_COUNT);
            assert_eq!(
                state
                    .post_gloas()
                    .expect("retirement fixture state is Gloas")
                    .previous_epoch_participation()
                    .len_usize(),
                VALIDATOR_COUNT,
            );
            assert_eq!(
                state
                    .post_gloas()
                    .expect("retirement fixture state is Gloas")
                    .current_epoch_participation()
                    .len_usize(),
                VALIDATOR_COUNT,
            );

            (
                state,
                Arc::new(SignedBeaconBlock::from(signed_block)),
                block_root,
                bid,
            )
        }

        fn initialize_validator_lists(state: &mut GloasBeaconState<Minimal>) {
            state
                .balances
                .try_assign_from_iter(&mut core::iter::repeat_n(
                    EFFECTIVE_BALANCE,
                    VALIDATOR_COUNT,
                ))
                .expect("eight validator balances fit the persistent progressive list");
            state
                .previous_epoch_participation
                .try_assign_from_iter(&mut core::iter::repeat_n(0_u8, VALIDATOR_COUNT))
                .expect("eight previous participation flags fit the persistent progressive list");
            state
                .current_epoch_participation
                .try_assign_from_iter(&mut core::iter::repeat_n(0_u8, VALIDATOR_COUNT))
                .expect("eight current participation flags fit the persistent progressive list");
            state
                .inactivity_scores
                .try_assign_from_iter(&mut core::iter::repeat_n(0_u64, VALIDATOR_COUNT))
                .expect("eight inactivity scores fit the persistent progressive list");
        }

        fn build_anchor_payload(
            config: &Config,
            state: &BeaconState<Minimal>,
            validator_keys: &[SecretKey; VALIDATOR_COUNT],
            bid: &ExecutionPayloadBid<Minimal>,
            block_root: H256,
        ) -> Arc<SignedExecutionPayloadEnvelope<Minimal>> {
            let post_gloas_state = state.post_gloas().expect("anchor state is Gloas");
            let timestamp = misc::compute_timestamp_at_slot(config, state, state.slot())
                .expect("anchor fixture timestamp should be computable");
            let payload = ExecutionPayloadEnvelope {
                payload: GloasExecutionPayload {
                    parent_hash: post_gloas_state.latest_block_hash(),
                    prev_randao: bid.prev_randao,
                    gas_limit: bid.gas_limit,
                    timestamp,
                    withdrawals: ProgressiveList::try_from(
                        post_gloas_state
                            .payload_expected_withdrawals()
                            .iter()
                            .copied()
                            .collect::<Vec<_>>(),
                    )
                    .expect("anchor expected withdrawals fit the payload list"),
                    block_hash: bid.block_hash,
                    slot_number: state.slot(),
                    ..Default::default()
                },
                execution_requests: ExecutionRequests::default(),
                builder_index: bid.builder_index,
                beacon_block_root: block_root,
                parent_beacon_block_root: state.latest_block_header().parent_root,
            };
            Arc::new(SignedExecutionPayloadEnvelope {
                signature: payload.sign(config, state, &validator_keys[0]).into(),
                message: payload,
            })
        }

        struct ProofAttempt {
            envelope: ExecutionProofEnvelope,
            envelope_root: H256,
            proof_type: u8,
            validator_index: u64,
            execution_proof: ExecutionProof,
            signed_proof: Arc<SignedExecutionProofEnvelope>,
            gossip_id: GossipId,
        }

        struct InFlightAttempts {
            a: ProofAttempt,
            b: Option<ProofAttempt>,
            original_resident_arc: Option<Arc<ExecutionProofEnvelope>>,
        }

        impl InFlightAttempts {
            fn expected(&self) -> Vec<&ProofAttempt> {
                if let Some(attempt_b) = &self.b {
                    vec![&self.a, attempt_b]
                } else {
                    vec![&self.a]
                }
            }

            fn resident(&self) -> Option<&ProofAttempt> {
                self.b.as_ref().map(|_| &self.a)
            }

            fn pending(&self) -> (&ProofAttempt, AttemptId) {
                if let Some(attempt_b) = &self.b {
                    (attempt_b, AttemptId::B)
                } else {
                    (&self.a, AttemptId::A)
                }
            }

            const fn occupied(&self) -> bool {
                self.b.is_some()
            }
        }

        struct RetiredProbePair {
            diagnostic_probe: ProofAttempt,
            handler_probe: ProofAttempt,
            diagnostic_message: MutatorMessage<Minimal, ()>,
            handler_message: MutatorMessage<Minimal, ()>,
        }

        fn build_proof_attempt(
            anchor: &AnchorFixture,
            store: &ControlStore,
            validator_index: u64,
            proof_byte: u8,
            gossip_seed: u8,
        ) -> ProofAttempt {
            assert!(get_supported_proof_types().contains(&PROOF_TYPE));
            let envelope = ExecutionProofEnvelope {
                proof_data: ProofData::try_from(vec![proof_byte, 0x82])
                    .expect("test proof bytes fit the bounded proof container"),
                proof_type: PROOF_TYPE,
                beacon_block_root: anchor.block_root,
            };
            let public_input = store
                .get_execution_proof(anchor.state.as_ref(), &envelope, &anchor.payload.message)
                .expect("accepted B payload supplies its public proof context")
                .public_input;
            assert!(public_input.successful_validation);
            assert_eq!(public_input.chain_id, anchor.config.deposit_chain_id);
            assert_eq!(public_input.chain_id, 1337);

            let index =
                usize::try_from(validator_index).expect("test validator index fits this host");
            let signature = SignForSingleForkAtSlot::<Minimal>::sign(
                &envelope,
                &anchor.config,
                anchor.state.as_ref(),
                anchor.state.slot(),
                &anchor.validator_keys[index],
            )
            .into();
            let gossip_id = test_gossip_id(gossip_seed);
            let envelope_root = envelope.hash_tree_root();
            let execution_proof = ExecutionProof {
                proof_data: envelope.proof_data.clone(),
                proof_type: envelope.proof_type,
                public_input,
            };
            assert_ne!(envelope_root, H256::zero());

            ProofAttempt {
                envelope: envelope.clone(),
                envelope_root,
                proof_type: envelope.proof_type,
                validator_index,
                execution_proof,
                signed_proof: Arc::new(SignedExecutionProofEnvelope {
                    message: Hc::from(envelope),
                    validator_index,
                    signature,
                }),
                gossip_id,
            }
        }

        struct RetirementTopology {
            c_link: ChainLink<Minimal>,
            e_link: ChainLink<Minimal>,
            d_link: ChainLink<Minimal>,
            c_root: H256,
            e_root: H256,
            d_root: H256,
            c2: Checkpoint,
            e3: Checkpoint,
            c2_state: Arc<BeaconState<Minimal>>,
            e3_state: Arc<BeaconState<Minimal>>,
        }

        impl RetirementTopology {
            fn build(anchor: &AnchorFixture, pubkey_cache: &PubkeyCache) -> Self {
                let z = anchor.state.current_justified_checkpoint();
                assert_eq!(z.epoch, 0);
                assert_eq!(anchor.state.finalized_checkpoint(), z);

                let c_bid = make_bid(0x45, anchor.bid.block_hash, anchor.block_root, 16);
                let mut c_state = anchor.state.as_ref().clone();
                combined::process_slots(&anchor.config, pubkey_cache, &mut c_state, 16)
                    .expect("public slot processing constructs C's slot-16 state");
                let (c_link, c_root) = make_link(c_state, 16, &anchor.block, c_bid);
                assert_eq!(c_link.parent_payload_presence, PayloadPresence::Full);
                assert_eq!(c_link.payload_status, PayloadStatus::Valid);
                assert_link_checkpoint_table(&c_link, z, z, z, z);

                let mut c_end_epoch = c_link
                    .state
                    .as_ref()
                    .expect("C link carries its coherent post-state")
                    .as_ref()
                    .clone();
                combined::process_slots(&anchor.config, pubkey_cache, &mut c_end_epoch, 23)
                    .expect("public slot processing reaches epoch-2 boundary state");
                set_current_target_participation(&mut c_end_epoch, true);
                assert_target_participation(&c_end_epoch, false);
                assert!(!has_target_participation(&c_end_epoch, true));
                let mut justification_probe = c_end_epoch.clone();
                combined::process_justification_and_finalization(&mut justification_probe)
                    .expect("public FFG calculation derives C2 from current participation");
                let c2 = Checkpoint {
                    epoch: 2,
                    root: c_root,
                };
                assert_eq!(justification_probe.current_justified_checkpoint(), c2);
                assert_eq!(justification_probe.finalized_checkpoint(), z);
                assert_eq!(accessors::latest_block_root(&justification_probe), c_root);

                let mut e_state = c_end_epoch;
                combined::process_slots(&anchor.config, pubkey_cache, &mut e_state, 24)
                    .expect("epoch transition carries C2 and rotates participation into E");
                assert_eq!(e_state.current_justified_checkpoint(), c2);
                assert_eq!(e_state.finalized_checkpoint(), z);
                assert_target_participation(&e_state, true);
                assert!(!has_target_participation(&e_state, false));

                let e_bid = make_bid(0x46, anchor.bid.block_hash, c_root, 24);
                let (e_link, e_root) = make_link(e_state, 24, &c_link.block, e_bid);
                assert_eq!(e_link.parent_payload_presence, PayloadPresence::Empty);
                assert_eq!(e_link.payload_status, PayloadStatus::Valid);
                assert_link_checkpoint_table(&e_link, c2, z, c2, z);

                let mut e_end_epoch = e_link
                    .state
                    .as_ref()
                    .expect("E link carries its coherent post-state")
                    .as_ref()
                    .clone();
                combined::process_slots(&anchor.config, pubkey_cache, &mut e_end_epoch, 31)
                    .expect("public slot processing reaches epoch-3 boundary state");
                assert_target_participation(&e_end_epoch, true);
                set_current_target_participation(&mut e_end_epoch, true);
                assert_target_participation(&e_end_epoch, false);
                let mut finalization_probe = e_end_epoch.clone();
                combined::process_justification_and_finalization(&mut finalization_probe)
                    .expect("public FFG calculation derives E3 and finalizes C2");
                let e3 = Checkpoint {
                    epoch: 3,
                    root: e_root,
                };
                assert_eq!(finalization_probe.current_justified_checkpoint(), e3);
                assert_eq!(finalization_probe.finalized_checkpoint(), c2);
                assert_eq!(accessors::latest_block_root(&finalization_probe), e_root);

                let mut d_state = e_end_epoch;
                combined::process_slots(&anchor.config, pubkey_cache, &mut d_state, 32)
                    .expect("public epoch processing carries E3/C2 into D at slot 32");
                assert_eq!(d_state.current_justified_checkpoint(), e3);
                assert_eq!(d_state.finalized_checkpoint(), c2);

                let d_bid = make_bid(0x47, anchor.bid.block_hash, e_root, 32);
                let (d_link, d_root) = make_link(d_state, 32, &e_link.block, d_bid);
                assert_eq!(d_link.parent_payload_presence, PayloadPresence::Empty);
                assert_eq!(d_link.payload_status, PayloadStatus::Valid);
                assert_link_checkpoint_table(&d_link, e3, c2, e3, c2);

                // The FFG probes above are at slots 23/31; checkpoint cache entries must
                // instead be the actual C/E boundary post-states at slots 16/24.
                let c2_boundary_state = checkpoint_boundary_state(&c_link, 16);
                let e3_boundary_state = checkpoint_boundary_state(&e_link, 24);

                Self {
                    c_link,
                    e_link,
                    d_link,
                    c_root,
                    e_root,
                    d_root,
                    c2,
                    e3,
                    c2_state: c2_boundary_state,
                    e3_state: e3_boundary_state,
                }
            }
        }

        fn checkpoint_boundary_state(
            link: &ChainLink<Minimal>,
            slot: Slot,
        ) -> Arc<BeaconState<Minimal>> {
            let state = link
                .state
                .as_ref()
                .expect("link carries its frozen checkpoint boundary post-state")
                .clone_arc();
            assert_eq!(state.slot(), slot);
            assert_eq!(accessors::latest_block_root(&state), link.block_root);
            state
        }

        fn make_bid(
            seed: u8,
            parent_block_hash: ExecutionBlockHash,
            parent_block_root: H256,
            slot: Slot,
        ) -> ExecutionPayloadBid<Minimal> {
            let requests = ExecutionRequests::<Minimal>::default();
            ExecutionPayloadBid {
                parent_block_hash,
                parent_block_root,
                block_hash: ExecutionBlockHash::repeat_byte(seed),
                prev_randao: H256::repeat_byte(seed ^ 0x80),
                gas_limit: 30_000_000,
                builder_index: BUILDER_INDEX_SELF_BUILD,
                slot,
                execution_requests_root: requests.hash_tree_root(),
                ..Default::default()
            }
        }

        fn block_body(bid: ExecutionPayloadBid<Minimal>) -> GloasBeaconBlockBody<Minimal> {
            GloasBeaconBlockBody {
                signed_execution_payload_bid: SignedExecutionPayloadBid {
                    message: bid,
                    signature: SignatureBytes::default(),
                },
                parent_execution_requests: ExecutionRequests::default(),
                ..Default::default()
            }
        }

        fn make_link(
            mut state: BeaconState<Minimal>,
            slot: Slot,
            parent: &Arc<SignedBeaconBlock<Minimal>>,
            bid: ExecutionPayloadBid<Minimal>,
        ) -> (ChainLink<Minimal>, H256) {
            let body = block_body(bid.clone());
            let body_root = body.hash_tree_root();
            let parent_root = parent.message().hash_tree_root();
            let executed_hash = ExecutionBlockHash::repeat_byte(0x44);
            {
                let gloas_state = match &mut state {
                    BeaconState::Gloas(state) => state.as_mut(),
                    _ => panic!("controlled lifecycle links must use Gloas state"),
                };
                gloas_state.latest_execution_payload_bid = bid;
                gloas_state.latest_block_hash = executed_hash;
                gloas_state.latest_block_header = BeaconBlockHeader {
                    slot,
                    parent_root,
                    state_root: H256::zero(),
                    body_root,
                    ..Default::default()
                };
            }

            let realized_justified = state.current_justified_checkpoint();
            let realized_finalized = state.finalized_checkpoint();
            let (unrealized_justified, unrealized_finalized) = unrealized_checkpoints(&state);
            let state_root = state.hash_tree_root();
            let signed_block = GloasSignedBeaconBlock {
                message: Hc::from(GloasBeaconBlock {
                    slot,
                    proposer_index: 0,
                    parent_root,
                    state_root,
                    body,
                }),
                signature: SignatureBytes::default(),
            };
            let block_root = signed_block.message.hash_tree_root();
            assert_eq!(state.slot(), slot);
            assert_eq!(signed_block.message.slot, state.slot());
            assert_eq!(signed_block.message.parent_root, parent_root);
            assert_eq!(signed_block.message.body.hash_tree_root(), body_root);
            assert_eq!(state_root, state.hash_tree_root());
            assert_eq!(signed_block.message.state_root, state_root);
            assert_eq!(accessors::latest_block_root(&state), block_root);
            let header = state.latest_block_header();
            assert_eq!(header.slot, slot);
            assert_eq!(header.parent_root, parent_root);
            assert_eq!(header.body_root, body_root);
            assert_eq!(header.state_root, H256::zero());
            assert_eq!(
                state
                    .post_gloas()
                    .expect("retirement fixture state is Gloas")
                    .latest_block_hash(),
                executed_hash
            );

            let block = Arc::new(SignedBeaconBlock::from(signed_block));
            let parent_payload_presence =
                PayloadPresence::of_parent(block.message(), parent.message());
            (
                ChainLink {
                    block_root,
                    block,
                    state: Some(Arc::new(state)),
                    current_justified_checkpoint: realized_justified,
                    finalized_checkpoint: realized_finalized,
                    unrealized_justified_checkpoint: unrealized_justified,
                    unrealized_finalized_checkpoint: unrealized_finalized,
                    payload_status: PayloadStatus::Valid,
                    parent_payload_presence,
                },
                block_root,
            )
        }

        fn unrealized_checkpoints(state: &BeaconState<Minimal>) -> (Checkpoint, Checkpoint) {
            let mut state = state.clone();
            combined::process_justification_and_finalization(&mut state)
                .expect("public FFG routine computes unrealized checkpoints on a clone");
            (
                state.current_justified_checkpoint(),
                state.finalized_checkpoint(),
            )
        }

        fn assert_link_checkpoint_table(
            link: &ChainLink<Minimal>,
            realized_justified: Checkpoint,
            realized_finalized: Checkpoint,
            unrealized_justified: Checkpoint,
            unrealized_finalized: Checkpoint,
        ) {
            assert_eq!(link.current_justified_checkpoint, realized_justified);
            assert_eq!(link.finalized_checkpoint, realized_finalized);
            assert_eq!(link.unrealized_justified_checkpoint, unrealized_justified);
            assert_eq!(link.unrealized_finalized_checkpoint, unrealized_finalized);
        }

        fn set_current_target_participation(state: &mut BeaconState<Minimal>, participating: bool) {
            let flags = if participating { TARGET_FLAG } else { 0 };
            let BeaconState::Gloas(state) = state else {
                panic!("participation fixture must be Gloas");
            };
            state
                .current_epoch_participation
                .try_assign_from_iter(&mut core::iter::repeat_n(flags, VALIDATOR_COUNT))
                .expect("eight target participation flags fit the persistent progressive list");
        }

        fn has_target_participation(state: &BeaconState<Minimal>, previous: bool) -> bool {
            let post_gloas = state.post_gloas().expect("participation state is Gloas");
            let participation = if previous {
                post_gloas.previous_epoch_participation()
            } else {
                post_gloas.current_epoch_participation()
            };
            assert_eq!(participation.len_usize(), VALIDATOR_COUNT);
            participation
                .iter()
                .all(|flags| flags & TARGET_FLAG == TARGET_FLAG)
        }

        fn assert_target_participation(state: &BeaconState<Minimal>, previous: bool) {
            assert!(has_target_participation(state, previous));
        }

        fn test_validator_key(scalar: u8) -> SecretKey {
            let mut key_bytes = SecretKeyBytes::default();
            key_bytes.as_mut()[31] = scalar;
            key_bytes
                .try_into()
                .expect("nonzero small scalar is a valid test key")
        }

        fn test_gossip_id(seed: u8) -> GossipId {
            let mut peer_id_bytes = vec![0x12, 0x20];
            peer_id_bytes.resize(34, seed);
            GossipId {
                source: PeerId::from_bytes(&peer_id_bytes).expect("test peer id should decode"),
                message_id: MessageId::new(&[seed, 0xc3]),
            }
        }

        fn assert_gossip_identity(actual: Option<&GossipId>, expected: &GossipId) {
            let actual = actual.expect("gossip response preserves source and message id");
            assert_eq!(&actual.source, &expected.source);
            assert_eq!(&actual.message_id, &expected.message_id);
            let source_bytes = actual.source.to_bytes();
            assert_eq!(source_bytes.len(), 34);
            assert!(source_bytes[2..].iter().any(|byte| *byte != 0));
            assert_ne!(actual.message_id, MessageId::new(&[]));
        }

        fn expected_store(
            attempts: &[&ProofAttempt],
            stored: Option<&ProofAttempt>,
        ) -> StoreObservation {
            let mut expected = StoreObservation::default();
            for attempt in attempts {
                expected
                    .seen_roots
                    .entry(attempt.envelope.beacon_block_root)
                    .or_default()
                    .insert(attempt.envelope_root);
                expected.seen_provers.insert((
                    attempt.envelope.beacon_block_root,
                    attempt.proof_type,
                    attempt.validator_index,
                ));
            }
            if let Some(attempt) = stored {
                expected.execution_proofs.insert(
                    attempt.envelope.beacon_block_root,
                    HashMap::from([(attempt.proof_type, attempt.envelope.clone())]),
                );
            }
            expected
        }

        fn assert_observation(
            observation: &StoreObservation,
            attempts: &[&ProofAttempt],
            stored: Option<&ProofAttempt>,
        ) {
            assert_eq!(observation, &expected_store(attempts, stored));
        }

        fn assert_origin(origin: &ExecutionProofOrigin, expected: &GossipId) {
            let actual = origin
                .gossip_id_ref()
                .expect("retirement attempts use gossip origins");
            assert_gossip_identity(Some(actual), expected);
        }

        struct ProofServiceHarness {
            anchor: AnchorFixture,
            pubkey_cache: Arc<PubkeyCache>,
            store_snapshot: Arc<ArcSwap<ControlStore>>,
            mutator: TestMutator,
            proof_engine: Arc<dyn ProofEngine>,
            engine: Arc<GatedProofEngine>,
            engine_events: Receiver<EngineEvent>,
            p2p_events: Receiver<P2pObservation>,
            releases: GateReleaseGuard,
        }

        impl Drop for ProofServiceHarness {
            fn drop(&mut self) {
                // Unblock verifier workers before the Mutator-owned pool is dropped.
                drop(core::mem::take(&mut self.releases));
            }
        }

        impl ProofServiceHarness {
            fn new() -> Self {
                let anchor = AnchorFixture::new();
                let pubkey_cache = Arc::new(PubkeyCache::default());
                let storage = Arc::new(Storage::new(
                    anchor.config.clone_arc(),
                    pubkey_cache.clone_arc(),
                    Database::in_memory(),
                    DEFAULT_ARCHIVAL_EPOCH_INTERVAL,
                    StorageMode::Prune,
                    true,
                    DEFAULT_ZSTD_COMPRESSION_LEVEL,
                ));
                let store = Store::new(
                    anchor.config.clone_arc(),
                    pubkey_cache.clone_arc(),
                    StoreConfig::aggressive(&anchor.config),
                    anchor.block.clone_arc(),
                    anchor.state.clone_arc(),
                    storage.clone_arc(),
                    true,
                    true,
                    HashSet::new(),
                    Arc::new(SccHashMap::new()),
                );
                let store_snapshot = Arc::new(ArcSwap::from_pointee(store));
                let (p2p_sender, p2p_events) = mpsc::sync_channel(16);
                let p2p_sink = ObservingP2pSink {
                    store_snapshot: store_snapshot.clone_arc(),
                    sender: p2p_sender,
                };
                let (engine_sender, engine_events) = mpsc::sync_channel(8);
                let engine = Arc::new(GatedProofEngine {
                    store_snapshot: store_snapshot.clone_arc(),
                    registered: Mutex::new(Vec::new()),
                    events: engine_sender,
                    invocations: AtomicUsize::new(0),
                });
                let proof_engine: Arc<dyn ProofEngine> = engine.clone_arc();
                let execution_engine: TestExecutionEngine<Minimal> =
                    Arc::new(Mutex::new(MockExecutionEngine::new(true, false, None)));
                let state_cache = store_snapshot.load_full().state_cache();
                let block_processor = Arc::new(BlockProcessor::new(
                    anchor.config.clone_arc(),
                    pubkey_cache.clone_arc(),
                    state_cache.clone_arc(),
                ));
                let thread_pool = ThreadPool::<Minimal, _, ()>::with_worker_count(2)
                    .expect("retirement fixture starts the actual proof worker pool");
                let (mutator_tx, mutator_rx) = mpsc::channel();
                let mut mutator = Mutator::new(
                    pubkey_cache.clone_arc(),
                    store_snapshot.clone_arc(),
                    state_cache,
                    block_processor,
                    Arc::new(EventChannels::new(16)),
                    execution_engine,
                    !proof_engine.is_null(),
                    Arc::new(SccHashMap::new()),
                    Arc::new(StateAtSlotCache::build()),
                    storage,
                    thread_pool,
                    None,
                    mutator_tx,
                    mutator_rx,
                    futures::sink::drain(),
                    p2p_sink,
                    futures::sink::drain(),
                    futures::sink::drain(),
                    futures::sink::drain(),
                    futures::sink::drain(),
                );
                mutator
                    .process_unfinalized_blocks(core::iter::empty())
                    .expect("empty anchor fixture completes Mutator load initialization");
                assert_eq!(
                    store_snapshot.load().finalized_checkpoint(),
                    Checkpoint {
                        epoch: 0,
                        root: anchor.block_root,
                    },
                    "Store::new uses the anchor-root epoch-zero checkpoint, unlike the state stub",
                );

                Self {
                    anchor,
                    pubkey_cache,
                    store_snapshot,
                    mutator,
                    proof_engine,
                    engine,
                    engine_events,
                    p2p_events,
                    releases: GateReleaseGuard::default(),
                }
            }

            fn accept_anchor_payload(&mut self) {
                let gossip_id = test_gossip_id(0x11);
                let origin = ExecutionPayloadEnvelopeOrigin::Gossip(gossip_id.clone());
                let snapshot = self.store_snapshot.load_full();
                let result = snapshot.validate_execution_payload_envelope(
                    &self.anchor.payload,
                    &origin,
                    &self.mutator.execution_engine,
                    MultiVerifier::default(),
                    self.mutator.capture_proof_context,
                );
                assert!(matches!(
                    &result,
                    Ok(ExecutionPayloadEnvelopeValidationAction::Accept(_))
                ));
                let identifier = self.anchor.payload.as_ref().into();
                self.mutator.handle_execution_payload_envelope(
                    (),
                    result,
                    origin,
                    identifier,
                    true,
                    ProcessingTimings::new(),
                    tracing::Span::none(),
                );
                let response = self.receive_p2p(P2pOutcome::Accept, &gossip_id);
                assert_observation(&response.store, &[], None);
                assert_eq!(response.stored_envelope, None);
                let accepted = self.store_snapshot.load_full();
                assert!(accepted.is_payload_verified(self.anchor.block_root));
                assert_eq!(
                    accepted
                        .cached_execution_payload_envelope_by_root(self.anchor.block_root)
                        .expect("accepted B envelope is published")
                        .as_ref(),
                    self.anchor.payload.as_ref(),
                );
            }

            fn receive_p2p(&self, outcome: P2pOutcome, gossip_id: &GossipId) -> P2pObservation {
                let observation = self
                    .p2p_events
                    .recv_timeout(TEST_TIMEOUT)
                    .expect("actual P2P send is synchronously observed");
                assert_eq!(observation.outcome, outcome);
                assert_gossip_identity(observation.gossip_id.as_ref(), gossip_id);
                observation
            }

            fn run_preparation(&mut self, snapshot: Arc<ControlStore>, attempt: &ProofAttempt) {
                ProcessExecutionProofTask {
                    store_snapshot: snapshot,
                    proof_engine: self.proof_engine.clone_arc(),
                    mutator_tx: self.mutator.mutator_tx.clone(),
                    signed_proof: attempt.signed_proof.clone_arc(),
                    origin: ExecutionProofOrigin::Gossip(attempt.gossip_id.clone()),
                }
                .run();
                let message = self
                    .mutator
                    .mutator_rx
                    .recv_timeout(TEST_TIMEOUT)
                    .expect("real preparation task sends a protected prepared message");
                self.deliver_prepared(message);
            }

            fn prepare_detached(
                &self,
                snapshot: Arc<ControlStore>,
                attempt: &ProofAttempt,
            ) -> MutatorMessage<Minimal, ()> {
                let (sender, receiver) = mpsc::channel();
                ProcessExecutionProofTask {
                    store_snapshot: snapshot,
                    proof_engine: self.proof_engine.clone_arc(),
                    mutator_tx: sender,
                    signed_proof: attempt.signed_proof.clone_arc(),
                    origin: ExecutionProofOrigin::Gossip(attempt.gossip_id.clone()),
                }
                .run();
                receiver
                    .recv_timeout(TEST_TIMEOUT)
                    .expect("independent preparation uses the accepted pre-transition snapshot")
            }

            fn prepare_detached_with_origin(
                &self,
                snapshot: Arc<ControlStore>,
                attempt: &ProofAttempt,
                origin: ExecutionProofOrigin,
            ) -> MutatorMessage<Minimal, ()> {
                let (sender, receiver) = mpsc::channel();
                ProcessExecutionProofTask {
                    store_snapshot: snapshot,
                    proof_engine: self.proof_engine.clone_arc(),
                    mutator_tx: sender,
                    signed_proof: attempt.signed_proof.clone_arc(),
                    origin,
                }
                .run();
                receiver
                    .recv_timeout(TEST_TIMEOUT)
                    .expect("genuine detached preparation returns before live dispatch")
            }

            fn deliver_prepared(&mut self, message: MutatorMessage<Minimal, ()>) {
                match message {
                    MutatorMessage::ExecutionProofPrepared {
                        result,
                        proof_engine,
                        origin,
                    } => self
                        .mutator
                        .handle_prepared_execution_proof(result, proof_engine, origin),
                    _ => panic!("expected the actual prepared-proof mutator message"),
                }
            }

            fn observe_entry(
                &self,
                id: AttemptId,
                attempt: &ProofAttempt,
                expected_attempts: &[&ProofAttempt],
            ) {
                let event = self
                    .engine_events
                    .recv_timeout(TEST_TIMEOUT)
                    .expect("real VerifyExecutionProofTask enters the gated engine");
                assert_eq!(event.id, id);
                assert_eq!(event.execution_proof, attempt.execution_proof);
                assert_observation(&event.published_store, expected_attempts, None);
            }

            fn seal_completion_batch(&mut self) {
                // This receiver is intentionally discarded; replacing the root sender closes only
                // the original completion channel once every real verifier task drops its sender.
                let (replacement_sender, replacement_receiver) = mpsc::channel();
                drop(replacement_receiver);
                drop(core::mem::replace(
                    &mut self.mutator.mutator_tx,
                    replacement_sender,
                ));
            }

            fn drain_closed_batch(
                &mut self,
                attempt: &ProofAttempt,
                kind: ProofOriginKind,
            ) -> usize {
                let deadline = Instant::now()
                    .checked_add(TEST_TIMEOUT)
                    .expect("sealed proof batch deadline must be representable");
                let mut completion_count = 0_usize;

                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    assert!(
                        !remaining.is_zero(),
                        "sealed proof batch did not disconnect before deadline"
                    );
                    match self.mutator.mutator_rx.recv_timeout(remaining) {
                        Ok(MutatorMessage::ExecutionProofCompleted { completion, origin }) => {
                            assert_proof_origin(&origin, kind, attempt);
                            self.mutator
                                .handle_completed_execution_proof(completion, origin);
                            completion_count = completion_count
                                .checked_add(1)
                                .expect("sealed proof batch completion count must not overflow");
                        }
                        Ok(_) => panic!("unexpected message on sealed proof completion channel"),
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            panic!("sealed proof batch timed out before producer disconnection");
                        }
                    }
                }

                completion_count
            }

            fn drain_p2p_observations(&self) -> Vec<P2pObservation> {
                core::iter::from_fn(|| self.p2p_events.try_recv().ok()).collect()
            }

            fn receive_completion(
                &mut self,
                attempt: &ProofAttempt,
                expected_attempts: &[&ProofAttempt],
                stored: Option<&ProofAttempt>,
                expected_outcome: P2pOutcome,
            ) -> P2pObservation {
                let message = self
                    .mutator
                    .mutator_rx
                    .recv_timeout(TEST_TIMEOUT)
                    .expect("released worker sends its actual completed-proof message");
                match message {
                    MutatorMessage::ExecutionProofCompleted { completion, origin } => {
                        assert_origin(&origin, &attempt.gossip_id);
                        self.mutator
                            .handle_completed_execution_proof(completion, origin);
                    }
                    _ => panic!("expected worker-produced ExecutionProofCompleted"),
                }
                let response = self.receive_p2p(expected_outcome, &attempt.gossip_id);
                assert_observation(&response.store, expected_attempts, stored);
                response
            }

            fn apply_retirement_topology(&mut self, topology: &RetirementTopology) {
                {
                    let store = self.mutator.store_mut();
                    drop(
                        store
                            .apply_tick(Tick::start_of_slot(16))
                            .expect("public Store tick reaches C"),
                    );
                    drop(
                        store
                            .apply_block(topology.c_link.clone())
                            .expect("public Store applies C"),
                    );
                    store.insert_checkpoint_state(topology.c2, topology.c2_state.clone_arc());
                }
                {
                    let store = self.mutator.store_mut();
                    drop(
                        store
                            .apply_tick(Tick::start_of_slot(24))
                            .expect("public Store tick reaches E"),
                    );
                    drop(
                        store
                            .apply_block(topology.e_link.clone())
                            .expect("public Store applies E"),
                    );
                    store.insert_checkpoint_state(topology.e3, topology.e3_state.clone_arc());
                }
                {
                    let store = self.mutator.store_mut();
                    drop(
                        store
                            .apply_tick(Tick::start_of_slot(32))
                            .expect("public Store tick reaches D"),
                    );
                    drop(
                        store
                            .apply_block(topology.d_link.clone())
                            .expect("public Store applies D"),
                    );
                }
                self.mutator.update_store_snapshot();

                let store = self.store_snapshot.load_full();
                assert_eq!(store.last_finalized().block_root, topology.c_root);
                assert_eq!(store.finalized_checkpoint(), topology.c2);
                assert_eq!(store.head().block_root, topology.d_root);
                let retained: HashSet<_> = store
                    .unfinalized_canonical_chain()
                    .map(|link| link.block_root)
                    .collect();
                assert!(retained.contains(&topology.e_root));
                assert!(retained.contains(&topology.d_root));
                assert!(!retained.contains(&self.anchor.block_root));
                assert!(!retained.contains(&topology.c_root));
                assert!(!store.is_payload_verified(topology.c_root));
                assert!(!store.is_payload_verified(topology.e_root));
                assert!(!store.is_payload_verified(topology.d_root));
                assert_eq!(
                    StoreObservation::capture(&store),
                    StoreObservation::capture(&self.mutator.store),
                    "snapshot publication exposes the actual live Mutator Store",
                );
            }

            fn assert_retired_admission_and_handler(
                &mut self,
                probes: RetiredProbePair,
                attempts: &InFlightAttempts,
            ) {
                let expected_attempts = attempts.expected();
                let stored = attempts.resident();
                let before_live = StoreObservation::capture(&self.mutator.store);
                let before_published = StoreObservation::capture(&self.store_snapshot.load_full());
                assert_eq!(before_live, before_published);
                let count_before = self.engine.invocation_count();

                let MutatorMessage::ExecutionProofPrepared { result, origin, .. } =
                    probes.diagnostic_message
                else {
                    panic!("diagnostic probe came from actual authenticated preparation");
                };
                assert_origin(&origin, &probes.diagnostic_probe.gossip_id);
                let prepared = match result
                    .expect("diagnostic preparation uses the old accepted snapshot")
                {
                    ExecutionProofPreparation::Prepared(prepared) => prepared,
                    ExecutionProofPreparation::Ignore(reason) => {
                        panic!("fresh probe unexpectedly ignored before live admission: {reason}")
                    }
                };
                assert!(matches!(
                    self.mutator.store_mut().admit_execution_proof(prepared),
                    ExecutionProofAdmission::Declined(ExecutionProofAdmissionDecline::Retired),
                ));
                assert_eq!(StoreObservation::capture(&self.mutator.store), before_live);
                assert_eq!(
                    StoreObservation::capture(&self.store_snapshot.load_full()),
                    before_published,
                );
                assert_eq!(self.engine.invocation_count(), count_before);

                let MutatorMessage::ExecutionProofPrepared {
                    result,
                    proof_engine,
                    origin,
                } = probes.handler_message
                else {
                    panic!("handler probe came from a separate actual preparation");
                };
                assert_origin(&origin, &probes.handler_probe.gossip_id);
                self.mutator
                    .handle_prepared_execution_proof(result, proof_engine, origin);
                let response =
                    self.receive_p2p(P2pOutcome::Ignore, &probes.handler_probe.gossip_id);
                assert_observation(&response.store, &expected_attempts, stored);
                assert_eq!(self.engine.invocation_count(), count_before);
                assert_eq!(StoreObservation::capture(&self.mutator.store), before_live);
            }
        }

        fn make_attempt_pair(
            anchor: &AnchorFixture,
            snapshot: &ControlStore,
            occupied: bool,
        ) -> (ProofAttempt, Option<ProofAttempt>) {
            let attempt_a = build_proof_attempt(anchor, snapshot, 0, 0xa1, 0x21);
            let attempt_b = occupied.then(|| build_proof_attempt(anchor, snapshot, 1, 0xb2, 0x22));
            if let Some(attempt_b) = &attempt_b {
                assert_ne!(attempt_a.envelope_root, attempt_b.envelope_root);
                assert_ne!(attempt_a.validator_index, attempt_b.validator_index);
                assert_eq!(
                    attempt_a.execution_proof.public_input,
                    attempt_b.execution_proof.public_input
                );
            }
            (attempt_a, attempt_b)
        }

        fn prepare_retired_probe_pair(
            harness: &ProofServiceHarness,
            anchor: &AnchorFixture,
            accepted_snapshot: Arc<ControlStore>,
        ) -> RetiredProbePair {
            let diagnostic_probe = build_proof_attempt(anchor, &accepted_snapshot, 2, 0xc3, 0x34);
            let handler_probe = build_proof_attempt(anchor, &accepted_snapshot, 2, 0xc3, 0x35);
            assert_eq!(diagnostic_probe.envelope_root, handler_probe.envelope_root);
            assert_eq!(diagnostic_probe.validator_index, 2);
            assert_eq!(handler_probe.validator_index, 2);
            assert_eq!(diagnostic_probe.proof_type, handler_probe.proof_type);
            assert_eq!(
                diagnostic_probe.execution_proof,
                handler_probe.execution_proof
            );
            assert_eq!(
                diagnostic_probe.signed_proof.as_ref(),
                handler_probe.signed_proof.as_ref()
            );
            assert_ne!(
                diagnostic_probe.gossip_id.source,
                handler_probe.gossip_id.source
            );
            assert_ne!(
                diagnostic_probe.gossip_id.message_id,
                handler_probe.gossip_id.message_id,
            );
            assert_ne!(diagnostic_probe.envelope_root, H256::zero());
            let diagnostic_message =
                harness.prepare_detached(accepted_snapshot.clone_arc(), &diagnostic_probe);
            let handler_message = harness.prepare_detached(accepted_snapshot, &handler_probe);
            RetiredProbePair {
                diagnostic_probe,
                handler_probe,
                diagnostic_message,
                handler_message,
            }
        }

        fn gate_initial_attempts(
            harness: &mut ProofServiceHarness,
            accepted_snapshot: Arc<ControlStore>,
            attempts: &mut InFlightAttempts,
        ) {
            harness.releases.register(
                &harness.engine,
                AttemptId::A,
                attempts.a.execution_proof.clone(),
            );
            harness.run_preparation(accepted_snapshot.clone_arc(), &attempts.a);
            harness.observe_entry(AttemptId::A, &attempts.a, &[&attempts.a]);

            if let Some(attempt_b) = &attempts.b {
                harness.releases.register(
                    &harness.engine,
                    AttemptId::B,
                    attempt_b.execution_proof.clone(),
                );
                harness.run_preparation(accepted_snapshot, attempt_b);
                {
                    let expected = attempts.expected();
                    harness.observe_entry(AttemptId::B, attempt_b, &expected);
                }
                assert_eq!(harness.engine.invocation_count(), 2);
                harness.releases.release(AttemptId::A, ProofVerdict::Valid);
                let first_response = {
                    let expected = attempts.expected();
                    harness.receive_completion(
                        &attempts.a,
                        &expected,
                        Some(&attempts.a),
                        P2pOutcome::Accept,
                    )
                };
                let original_arc = first_response
                    .stored_envelope
                    .expect("first actual Valid completion publishes the resident Arc");
                assert_eq!(original_arc.as_ref(), &attempts.a.envelope);
                attempts.original_resident_arc = Some(original_arc);
            } else {
                assert_eq!(harness.engine.invocation_count(), 1);
            }
        }

        fn finish_retired_attempts(
            harness: &mut ProofServiceHarness,
            topology: &RetirementTopology,
            attempts: &InFlightAttempts,
            probes: RetiredProbePair,
            verdict: ProofVerdict,
        ) {
            assert_eq!(
                probes.diagnostic_probe.envelope.beacon_block_root,
                attempts.a.envelope.beacon_block_root,
            );
            assert_eq!(probes.diagnostic_probe.proof_type, attempts.a.proof_type);
            assert_ne!(
                probes.diagnostic_probe.envelope_root,
                attempts.a.envelope_root
            );
            assert_ne!(
                probes.diagnostic_probe.validator_index,
                attempts.a.validator_index
            );
            if let Some(attempt_b) = &attempts.b {
                assert_eq!(
                    probes.diagnostic_probe.envelope.beacon_block_root,
                    attempt_b.envelope.beacon_block_root,
                );
                assert_eq!(probes.diagnostic_probe.proof_type, attempt_b.proof_type);
                assert_ne!(
                    probes.diagnostic_probe.envelope_root,
                    attempt_b.envelope_root
                );
                assert_ne!(
                    probes.diagnostic_probe.validator_index,
                    attempt_b.validator_index
                );
            }
            assert_eq!(
                harness.engine.invocation_count(),
                if attempts.occupied() { 2 } else { 1 },
            );

            harness.apply_retirement_topology(topology);
            let expected = attempts.expected();
            let stored = attempts.resident();
            assert_observation(
                &StoreObservation::capture(&harness.mutator.store),
                &expected,
                stored,
            );
            harness.assert_retired_admission_and_handler(probes, attempts);

            let (pending, pending_id) = attempts.pending();
            harness.releases.release(pending_id, verdict);
            let late_response =
                harness.receive_completion(pending, &expected, stored, P2pOutcome::Ignore);
            if let Some(original_arc) = &attempts.original_resident_arc {
                let retained_arc = late_response
                    .stored_envelope
                    .as_ref()
                    .expect("late completion observes the original resident Arc");
                assert!(Arc::ptr_eq(original_arc, retained_arc));
                assert_eq!(retained_arc.as_ref(), &attempts.a.envelope);
            } else {
                assert_eq!(late_response.stored_envelope, None);
            }
            assert_eq!(
                harness.engine.invocation_count(),
                if attempts.occupied() { 2 } else { 1 },
            );
            assert_eq!(
                StoreObservation::capture(&harness.store_snapshot.load_full()),
                expected_store(&expected, stored),
            );
        }

        fn run_retired_late_completion(verdict: ProofVerdict, occupied: bool) {
            let mut harness = ProofServiceHarness::new();
            // Build and assert all C/E/D state, root, payload and FFG inputs before gating workers.
            let topology = RetirementTopology::build(&harness.anchor, &harness.pubkey_cache);
            harness.accept_anchor_payload();
            let accepted_snapshot = harness.store_snapshot.load_full();
            let (a, b) = make_attempt_pair(&harness.anchor, &accepted_snapshot, occupied);
            let mut attempts = InFlightAttempts {
                a,
                b,
                original_resident_arc: None,
            };
            gate_initial_attempts(&mut harness, accepted_snapshot.clone_arc(), &mut attempts);

            // Both independent authentic preparations use the same fresh signed B/T/R input and
            // the pre-transition snapshot; only their gossip identities differ.
            let probes = prepare_retired_probe_pair(&harness, &harness.anchor, accepted_snapshot);
            finish_retired_attempts(&mut harness, &topology, &attempts, probes, verdict);
        }

        #[test]
        fn execution_payload_retry_preserves_proof_context_capture_policy() {
            for capture_proof_context in [false, true] {
                let mut harness = ProofServiceHarness::new();
                // Isolate the shared retry seam used by block/state/data-delayed payloads.
                // Controller policy derivation is covered by the ordinary submission regression.
                harness.mutator.capture_proof_context = capture_proof_context;
                let gossip_id = test_gossip_id(0x11);
                harness.mutator.retry_execution_payload_envelope(
                    (),
                    PendingExecutionPayloadEnvelope {
                        execution_payload_envelope: harness.anchor.payload.clone_arc(),
                        origin: ExecutionPayloadEnvelopeOrigin::Gossip(gossip_id.clone()),
                        seen_before_deadline: true,
                        processing_timings: ProcessingTimings::new(),
                        tracing_span: tracing::Span::none(),
                    },
                );
                let message = harness
                    .mutator
                    .mutator_rx
                    .recv_timeout(TEST_TIMEOUT)
                    .expect("retried payload worker must finish validation");
                let MutatorMessage::ExecutionPayloadEnvelope {
                    wait_group,
                    result,
                    origin,
                    payload_envelope_identifier,
                    seen_before_deadline,
                    processing_timings,
                    tracing_span,
                } = message
                else {
                    panic!("retry must return an ordinary payload validation result");
                };
                assert!(matches!(
                    &result,
                    Ok(ExecutionPayloadEnvelopeValidationAction::Accept(_))
                ));
                harness.mutator.handle_execution_payload_envelope(
                    wait_group,
                    result,
                    origin,
                    payload_envelope_identifier,
                    seen_before_deadline,
                    processing_timings,
                    tracing_span,
                );
                harness.receive_p2p(P2pOutcome::Accept, &gossip_id);
                let snapshot = harness.store_snapshot.load_full();
                assert!(snapshot.is_payload_verified(harness.anchor.block_root));
                assert_eq!(
                    snapshot
                        .cached_execution_payload_envelope_by_root(harness.anchor.block_root)
                        .expect("retried payload must be applied")
                        .as_ref(),
                    harness.anchor.payload.as_ref(),
                );
                let attempt = build_proof_attempt(&harness.anchor, &snapshot, 0, 0xa1, 0x21);
                let preparation =
                    fork_choice_store::prepare_execution_proof(&snapshot, &attempt.signed_proof)
                        .expect("healthy retry fixture must not reject proof preparation");
                match preparation {
                    ExecutionProofPreparation::Prepared(_) => assert!(capture_proof_context),
                    ExecutionProofPreparation::Ignore(reason) => {
                        assert!(!capture_proof_context);
                        assert_eq!(
                            reason,
                            "execution proof's accepted payload context is no longer applicable"
                        );
                    }
                }
                assert_observation(&StoreObservation::capture(&snapshot), &[], None);
                assert_eq!(harness.engine.invocation_count(), 0);
            }
        }

        #[test]
        fn execution_proof_retired_late_valid_vacant() {
            run_retired_late_completion(ProofVerdict::Valid, false);
        }

        #[test]
        fn execution_proof_retired_late_invalid_vacant() {
            run_retired_late_completion(ProofVerdict::Invalid, false);
        }

        #[test]
        fn execution_proof_retired_late_undetermined_vacant() {
            run_retired_late_completion(ProofVerdict::Undetermined, false);
        }

        #[test]
        fn execution_proof_retired_late_valid_occupied() {
            run_retired_late_completion(ProofVerdict::Valid, true);
        }

        #[test]
        fn execution_proof_retired_late_invalid_occupied() {
            run_retired_late_completion(ProofVerdict::Invalid, true);
        }

        #[test]
        fn execution_proof_retired_late_undetermined_occupied() {
            run_retired_late_completion(ProofVerdict::Undetermined, true);
        }

        #[test]
        fn execution_proof_service_gossip_valid() {
            run_proof_service_case(
                ProofOriginKind::Gossip,
                VerificationScenario::Verdict(ProofVerdict::Valid),
            );
        }

        #[test]
        fn execution_proof_service_gossip_invalid() {
            run_proof_service_case(
                ProofOriginKind::Gossip,
                VerificationScenario::Verdict(ProofVerdict::Invalid),
            );
        }

        #[test]
        fn execution_proof_service_gossip_undetermined() {
            run_proof_service_case(
                ProofOriginKind::Gossip,
                VerificationScenario::Verdict(ProofVerdict::Undetermined),
            );
        }

        #[test]
        fn execution_proof_service_api_valid() {
            run_proof_service_case(
                ProofOriginKind::Api,
                VerificationScenario::Verdict(ProofVerdict::Valid),
            );
        }

        #[test]
        fn execution_proof_service_api_invalid() {
            run_proof_service_case(
                ProofOriginKind::Api,
                VerificationScenario::Verdict(ProofVerdict::Invalid),
            );
        }

        #[test]
        fn execution_proof_service_api_undetermined() {
            run_proof_service_case(
                ProofOriginKind::Api,
                VerificationScenario::Verdict(ProofVerdict::Undetermined),
            );
        }

        #[test]
        fn execution_proof_service_gossip_stopped_pool_dispatch() {
            run_proof_service_case(ProofOriginKind::Gossip, VerificationScenario::StoppedPool);
        }

        #[test]
        fn execution_proof_service_api_stopped_pool_dispatch() {
            run_proof_service_case(ProofOriginKind::Api, VerificationScenario::StoppedPool);
        }
    }
}
