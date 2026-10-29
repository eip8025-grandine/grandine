use core::panic::AssertUnwindSafe;
use std::{
    sync::{Arc, mpsc::Sender},
    time::Instant,
};

use anyhow::Result;
use eth2_libp2p::GossipId;
use execution_engine::{ExecutionEngine, NullExecutionEngine};
use features::Feature;
use fork_choice_store::{
    AdmittedExecutionProof, AggregateAndProofOrigin, AttestationItem, AttestationOrigin,
    AttesterSlashingOrigin, BlobSidecarOrigin, BlockAction, BlockItem, BlockOrigin,
    DataColumnSidecarAction, DataColumnSidecarOrigin, Error as StoreError,
    ExecutionPayloadBidOrigin, ExecutionPayloadEnvelopeAction, ExecutionPayloadEnvelopeOrigin,
    ExecutionProofOrigin, ExecutionProofPreparation, ExecutionProofVerificationOutcome,
    PayloadAttestationItem, PayloadAttestationOrigin, ProposerPreferencesOrigin,
    StateCacheProcessor, Store, prepare_execution_proof,
};
use futures::channel::mpsc::Sender as MultiSender;
use helper_functions::{
    accessors, deposit_signatures, misc,
    verifier::{MultiVerifier, NullVerifier},
};
use logging::{debug_with_peers, warn_with_peers};
use prometheus_metrics::Metrics;
use proof_engine::{ProofEngine, ProofVerdict};
use pubkey_cache::PubkeyCache;
use spec_test_utils::BlsSetting;
use ssz::SszHash as _;
use tracing::{Span, instrument};
use types::{
    combined::{
        AttesterSlashing, BeaconState as CombinedBeaconState, DataColumnSidecar,
        SignedAggregateAndProof, SignedBeaconBlock,
    },
    config::Config,
    deneb::containers::{BlobIdentifier, BlobSidecar},
    eip8025::containers::SignedExecutionProofEnvelope,
    fulu::containers::DataColumnIdentifier,
    gloas::containers::{
        SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope, SignedProposerPreferences,
    },
    nonstandard::{RelativeEpoch, ValidationOutcome, ValidationOutcomeWithReason},
    phase0::{
        containers::Checkpoint,
        primitives::{H256, Slot},
    },
    preset::Preset,
    traits::{BeaconState, SignedBeaconBlock as _},
};

use crate::{
    block_processor::BlockProcessor,
    messages::MutatorMessage,
    misc::{ProcessingTimings, VerifyAggregateAndProofResult},
    state_at_slot_cache::StateAtSlotCache,
    storage::Storage,
};

pub trait Run {
    fn run(self);

    fn run_and_handle_panics(self)
    where
        Self: Sized,
    {
        // All tasks should be unwind safe.
        // Running a task consumes it, making it impossible to observe any invalid state.
        std::panic::catch_unwind(AssertUnwindSafe(|| self.run())).unwrap_or_else(panics::log)
    }
}

// TODO(Grandine Team): Now that the time measuring logic has become permanent, consider refactoring
//                      the tasks to contain `*Pending` structs instead of duplicating their fields.

pub struct BlockTask<P: Preset, E, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub block_processor: Arc<BlockProcessor<P>>,
    pub execution_engine: E,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub block: BlockItem<P>,
    pub origin: BlockOrigin,
    pub processing_timings: ProcessingTimings,
    pub metrics: Option<Arc<Metrics>>,
    pub tracing_span: Span,
}

impl<P: Preset, E: ExecutionEngine<P> + Send, W> Run for BlockTask<P, E, W> {
    #[instrument(
        skip_all,
        name = "BlockTask::run",
        parent = &self.tracing_span,
        fields(
            origin = ?&self.origin,
            slot = self.block.item.message().slot()
        ),
    )]
    fn run(self) {
        let Self {
            store_snapshot,
            block_processor,
            execution_engine,
            mutator_tx,
            wait_group,
            block,
            origin,
            processing_timings,
            metrics,
            tracing_span,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            prometheus_metrics::start_timer_vec(&metrics.fc_block_task_times, origin.as_ref())
        });

        let started_at = Instant::now();
        let block_slot = block.item.message().slot();
        let block_root = block.item.message().hash_tree_root();

        let result = match origin {
            BlockOrigin::Gossip(_) | BlockOrigin::Requested(_) | BlockOrigin::Api(_) => {
                block_processor.validate_block(
                    &store_snapshot,
                    block,
                    origin.state_root_policy(),
                    origin.data_availability_policy(),
                    execution_engine,
                    MultiVerifier::default(),
                )
            }
            BlockOrigin::Own => {
                if Feature::TrustOwnBlockSignatures.is_enabled() {
                    block_processor.validate_block(
                        &store_snapshot,
                        block,
                        origin.state_root_policy(),
                        origin.data_availability_policy(),
                        execution_engine,
                        NullVerifier,
                    )
                } else {
                    block_processor.validate_block(
                        &store_snapshot,
                        block,
                        origin.state_root_policy(),
                        origin.data_availability_policy(),
                        execution_engine,
                        MultiVerifier::default(),
                    )
                }
            }
            BlockOrigin::Persisted => block_processor.validate_block(
                &store_snapshot,
                block,
                origin.state_root_policy(),
                origin.data_availability_policy(),
                NullExecutionEngine,
                NullVerifier,
            ),
            BlockOrigin::Test(bls_setting) => match bls_setting {
                BlsSetting::Required | BlsSetting::Optional => block_processor.validate_block(
                    &store_snapshot,
                    block,
                    origin.state_root_policy(),
                    origin.data_availability_policy(),
                    execution_engine,
                    MultiVerifier::default(),
                ),
                BlsSetting::Ignored => block_processor.validate_block(
                    &store_snapshot,
                    block.into_base_verified(),
                    origin.state_root_policy(),
                    origin.data_availability_policy(),
                    execution_engine,
                    NullVerifier,
                ),
            },
        };

        features::log!(
            LogBlockProcessingTime,
            "block {block_root:?} validated in {:?} ms",
            started_at.elapsed().as_millis(),
        );

        if block_slot == store_snapshot.slot() {
            store_snapshot.dec_current_slot_blocks_in_processing();
        }

        MutatorMessage::Block {
            wait_group,
            result: result.into(),
            origin,
            processing_timings,
            block_root,
            tracing_span,
        }
        .send(&mutator_tx);
    }
}

pub struct BlockVerifyForGossipTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub block_processor: Arc<BlockProcessor<P>>,
    pub wait_group: W,
    pub block: Arc<SignedBeaconBlock<P>>,
    pub sender: MultiSender<Result<ValidationOutcome>>,
}

impl<P: Preset, W> Run for BlockVerifyForGossipTask<P, W> {
    #[instrument(
        skip_all,
        name = "BlockVerifyForGossipTask::run",
        level = "debug",
        fields(
            slot = self.block.message().slot()
        ),
    )]
    fn run(self) {
        let Self {
            store_snapshot,
            block_processor,
            wait_group,
            block,
            mut sender,
        } = self;

        let validation_outcome = block_processor
            .validate_block_for_gossip(&store_snapshot, &block)
            .map(|block_action| match block_action {
                Some(BlockAction::Accept(_, _)) | None => ValidationOutcome::Accept,
                Some(BlockAction::Ignore(publishable)) => ValidationOutcome::Ignore(publishable),
                Some(_) => ValidationOutcome::Ignore(false),
            });

        if let Err(reply) = sender.try_send(validation_outcome) {
            debug_with_peers!(
                "reply to HTTP API failed because the receiver was dropped: {reply:?}"
            );
        }

        drop(wait_group);
    }
}

pub struct ExecutionPayloadEnvelopeVerifyForGossipTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub wait_group: W,
    pub execution_payload_envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
    pub sender: MultiSender<Result<ValidationOutcome>>,
}

impl<P: Preset, W> Run for ExecutionPayloadEnvelopeVerifyForGossipTask<P, W> {
    #[instrument(
        skip_all,
        name = "ExecutionPayloadEnvelopeVerifyForGossipTask::run",
        level = "debug",
        fields(
            slot = self.execution_payload_envelope.slot()
        ),
    )]
    fn run(self) {
        let Self {
            store_snapshot,
            wait_group,
            execution_payload_envelope,
            mut sender,
        } = self;

        let validation_outcome = store_snapshot
            .validate_execution_payload_envelope_for_gossip_rules(
                &execution_payload_envelope,
                &ExecutionPayloadEnvelopeOrigin::Api(None),
            )
            .map(|action| match action {
                ExecutionPayloadEnvelopeAction::Ignore(publishable) => {
                    ValidationOutcome::Ignore(publishable)
                }
                _ => ValidationOutcome::Ignore(false),
            })
            .unwrap_or(ValidationOutcome::Accept);

        if let Err(reply) = sender.try_send(Ok(validation_outcome)) {
            debug_with_peers!(
                "reply to HTTP API failed because the receiver was dropped: {reply:?}"
            );
        }

        drop(wait_group);
    }
}

pub struct AggregateAndProofTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub aggregate_and_proof: Arc<SignedAggregateAndProof<P>>,
    pub origin: AggregateAndProofOrigin<GossipId>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for AggregateAndProofTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "AggregateAndProofTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            aggregate_and_proof,
            origin,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            prometheus_metrics::start_timer_vec(
                &metrics.fc_aggregate_and_proof_task_times,
                origin.as_ref(),
            )
        });

        let result =
            store_snapshot.validate_aggregate_and_proof(aggregate_and_proof, &origin, false);

        let result = VerifyAggregateAndProofResult { result, origin };

        MutatorMessage::AggregateAndProof { wait_group, result }.send(&mutator_tx);
    }
}

pub struct AttestationTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub attestation: AttestationItem<P, GossipId>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for AttestationTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "AttestationTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            attestation,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            prometheus_metrics::start_timer_vec(
                &metrics.fc_attestation_task_times,
                attestation.origin.as_ref(),
            )
        });

        let result = store_snapshot.validate_attestation(attestation, false);

        MutatorMessage::Attestation { wait_group, result }.send(&mutator_tx);
    }
}

// TODO(Grandine Team): Merge this with `BlockTask` and benchmark.
pub struct BlockAttestationsTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub block_root: H256,
    pub block: Arc<SignedBeaconBlock<P>>,
    pub from_test_block: bool,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for BlockAttestationsTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "BlockAttestationTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            block_root,
            block,
            from_test_block,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_block_attestation_task_times.start_timer());

        // TODO(Grandine Team): Consider turning the pipeline into a new method in `Store`.
        let results = block
            .message()
            .body()
            .combined_attestations()
            .map(|attestation| {
                store_snapshot.validate_attestation(
                    AttestationItem::verified(
                        Arc::new(attestation),
                        AttestationOrigin::Block(block_root),
                    ),
                    true,
                )
            })
            .collect();

        MutatorMessage::BlockAttestations {
            wait_group,
            from_test_block,
            results,
        }
        .send(&mutator_tx);
    }
}

pub struct BlockPayloadAttestationsTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub block_root: H256,
    pub block: Arc<SignedBeaconBlock<P>>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for BlockPayloadAttestationsTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "BlockPayloadAttestationsTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            block_root,
            block,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            metrics
                .fc_block_payload_attestation_task_times
                .start_timer()
        });

        let Some(body) = block.message().body().with_payload_attestations() else {
            return;
        };

        // TODO(Grandine Team): Consider turning the pipeline into a new method in `Store`.
        let results = body
            .payload_attestations()
            .iter()
            .map(|payload_attestation| {
                store_snapshot.validate_payload_attestation(
                    PayloadAttestationItem::verified(
                        Arc::new((*payload_attestation).into()),
                        PayloadAttestationOrigin::Block(block_root),
                    ),
                    true,
                )
            })
            .collect();

        MutatorMessage::BlockPayloadAttestations {
            wait_group,
            results,
        }
        .send(&mutator_tx);
    }
}

pub struct AttesterSlashingTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub attester_slashing: Box<AttesterSlashing<P>>,
    pub origin: AttesterSlashingOrigin,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for AttesterSlashingTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "AttesterSlashingTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            attester_slashing,
            origin,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_attester_slashing_task_times.start_timer());

        let result = store_snapshot.validate_attester_slashing(&*attester_slashing, origin);

        MutatorMessage::AttesterSlashing {
            wait_group,
            result,
            origin,
        }
        .send(&mutator_tx);
    }
}

pub struct BlobSidecarTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub blob_sidecar: Arc<BlobSidecar<P>>,
    pub state: Option<Arc<CombinedBeaconState<P>>>,
    pub block_seen: bool,
    pub origin: BlobSidecarOrigin,
    pub submission_time: Instant,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for BlobSidecarTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "BlobSidecarTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            blob_sidecar,
            state,
            block_seen,
            origin,
            submission_time,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_blob_sidecar_task_times.start_timer());

        let block_root = blob_sidecar.signed_block_header.message.hash_tree_root();
        let index = blob_sidecar.index;
        let blob_identifier = BlobIdentifier { block_root, index };

        let result = store_snapshot.validate_blob_sidecar(blob_sidecar, state, block_seen, &origin);

        MutatorMessage::BlobSidecar {
            wait_group,
            result,
            origin,
            blob_identifier,
            block_seen,
            submission_time,
        }
        .send(&mutator_tx);
    }
}

pub struct DataColumnSidecarTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub data_column_sidecar: Arc<DataColumnSidecar<P>>,
    pub state: Option<Arc<CombinedBeaconState<P>>>,
    pub block_seen: bool,
    pub origin: DataColumnSidecarOrigin,
    pub submission_time: Instant,
    pub validate_block_presence: bool,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for DataColumnSidecarTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "DataColumnSidecarTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            data_column_sidecar,
            state,
            block_seen,
            origin,
            submission_time,
            validate_block_presence,
            metrics,
        } = self;

        let _data_column_sidecar_verification_timer = metrics
            .as_ref()
            .map(|metrics| metrics.data_column_sidecar_verification_times.start_timer());

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_data_column_sidecar_task_times.start_timer());

        let data_column_identifier = DataColumnIdentifier {
            block_root: data_column_sidecar.beacon_block_root(),
            index: data_column_sidecar.index(),
        };

        let result = store_snapshot.validate_data_column_sidecar(
            data_column_sidecar,
            state,
            block_seen,
            &origin,
            validate_block_presence,
            metrics.as_ref(),
        );

        if result.is_err()
            && let Some(metrics) = metrics.as_ref()
        {
            metrics.data_column_sidecars_submitted_for_processing.inc();
        }

        if let Ok(DataColumnSidecarAction::Accept(_)) = result
            && let Some(metrics) = metrics.as_ref()
        {
            metrics.data_column_sidecars_submitted_for_processing.inc();
            metrics.verified_gossip_data_column_sidecar.inc();
        }

        MutatorMessage::DataColumnSidecar {
            wait_group,
            result,
            origin,
            data_column_identifier,
            block_seen,
            submission_time,
        }
        .send(&mutator_tx);
    }
}

pub struct RetryDataColumnSidecarTask<P: Preset, W> {
    pub task: DataColumnSidecarTask<P, W>,
}

impl<P: Preset, W> Run for RetryDataColumnSidecarTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "RetryDataColumnSidecarTask::run")]
    fn run(self) {
        self.task.run()
    }
}

pub struct ExecutionPayloadEnvelopeTask<P: Preset, E, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub execution_engine: E,
    pub wait_group: W,
    pub execution_payload_envelope: Arc<SignedExecutionPayloadEnvelope<P>>,
    pub origin: ExecutionPayloadEnvelopeOrigin,
    pub seen_before_deadline: bool,
    pub processing_timings: ProcessingTimings,
    pub metrics: Option<Arc<Metrics>>,
    pub tracing_span: Span,
}

impl<P: Preset, E: ExecutionEngine<P> + Send, W> Run for ExecutionPayloadEnvelopeTask<P, E, W> {
    #[instrument(
        skip_all,
        name = "ExecutionPayloadEnvelopeTask::run",
        parent = &self.tracing_span,
        fields(
            origin = ?&self.origin,
            slot = self.execution_payload_envelope.slot()
        ),
    )]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            execution_engine,
            wait_group,
            execution_payload_envelope,
            origin,
            seen_before_deadline,
            processing_timings,
            metrics,
            tracing_span,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            metrics
                .fc_execution_payload_envelope_task_times
                .start_timer()
        });

        let payload_envelope_identifier = execution_payload_envelope.as_ref().into();

        let result = store_snapshot.validate_execution_payload_envelope(
            &execution_payload_envelope,
            &origin,
            &execution_engine,
            MultiVerifier::default(),
        );

        MutatorMessage::ExecutionPayloadEnvelope {
            wait_group,
            result,
            origin,
            payload_envelope_identifier,
            seen_before_deadline,
            processing_timings,
            tracing_span,
        }
        .send(&mutator_tx);
    }
}

pub struct ExecutionPayloadBidTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub payload_bid: Arc<SignedExecutionPayloadBid<P>>,
    pub origin: ExecutionPayloadBidOrigin,
}

impl<P: Preset, W> Run for ExecutionPayloadBidTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "ExecutionPayloadBidTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            payload_bid,
            origin,
        } = self;

        let result = store_snapshot.validate_execution_payload_bid(payload_bid, &origin);

        MutatorMessage::PayloadBid { result, origin }.send(&mutator_tx);
    }
}

pub struct ProcessExecutionProofTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub proof_engine: Arc<dyn ProofEngine>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub signed_proof: Arc<SignedExecutionProofEnvelope>,
    pub origin: ExecutionProofOrigin,
}

impl<P: Preset, W> Run for ProcessExecutionProofTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "ProcessExecutionProofTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            proof_engine,
            mutator_tx,
            signed_proof,
            origin,
        } = self;

        if proof_engine.is_null() {
            MutatorMessage::ExecutionProof {
                result: Ok(ValidationOutcomeWithReason::Ignore(
                    "proof engine not enabled",
                )),
                origin,
            }
            .send(&mutator_tx);
            return;
        }

        let result = classify_execution_proof_preparation::<P>(prepare_execution_proof(
            &store_snapshot,
            &signed_proof,
        ));

        // The worker exits rather than waiting for live admission. A snapshot can
        // authenticate input, but cannot authorize an engine invocation.
        MutatorMessage::ExecutionProofPrepared {
            result,
            proof_engine,
            origin,
        }
        .send(&mutator_tx);
    }
}

// Only these typed errors establish peer-invalid envelope input. Binding,
// reconstruction and other local errors must never reach the rejection arm.
fn classify_execution_proof_preparation<P: Preset>(
    result: Result<ExecutionProofPreparation>,
) -> Result<ExecutionProofPreparation> {
    match result {
        Err(error)
            if !matches!(
                error.downcast_ref::<StoreError<P>>(),
                Some(
                    StoreError::ExecutionProofEnvelopeInvalidValidatorIndex { .. }
                        | StoreError::ExecutionProofEnvelopeEmptyProof
                        | StoreError::ExecutionProofEnvelopeUnsupportedProofType { .. }
                        | StoreError::ExecutionProofEnvelopeInactiveValidator { .. }
                        | StoreError::ExecutionProofEnvelopeInvalidSignature { .. }
                )
            ) =>
        {
            warn_with_peers!("execution proof preparation failed locally (error: {error:?})");
            Ok(ExecutionProofPreparation::Ignore(
                "local execution proof preparation failure",
            ))
        }
        result => result,
    }
}

const fn execution_proof_verification_outcome(
    verdict: ProofVerdict,
) -> ExecutionProofVerificationOutcome {
    match verdict {
        ProofVerdict::Valid => ExecutionProofVerificationOutcome::Valid,
        ProofVerdict::Invalid => ExecutionProofVerificationOutcome::Invalid,
        ProofVerdict::Undetermined => ExecutionProofVerificationOutcome::LocalFault,
    }
}

pub struct VerifyExecutionProofTask<P: Preset, W> {
    pub admitted: AdmittedExecutionProof,
    pub proof_engine: Arc<dyn ProofEngine>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub origin: ExecutionProofOrigin,
}

impl<P: Preset, W> Run for VerifyExecutionProofTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "VerifyExecutionProofTask::run")]
    fn run(self) {
        let Self {
            admitted,
            proof_engine,
            mutator_tx,
            origin,
        } = self;
        let completion = admitted.verify_with(|input| {
            execution_proof_verification_outcome(proof_engine.verify_execution_proof(input))
        });
        MutatorMessage::ExecutionProofCompleted { completion, origin }.send(&mutator_tx);
    }
}

pub struct PayloadAttestationTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub payload_attestation: PayloadAttestationItem<P>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PayloadAttestationTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "PayloadAttestationTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            payload_attestation,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            prometheus_metrics::start_timer_vec(
                &metrics.fc_payload_attestation_task_times,
                payload_attestation.origin.as_ref(),
            )
        });

        let result = store_snapshot.validate_payload_attestation(payload_attestation, false);

        MutatorMessage::PayloadAttestation { wait_group, result }.send(&mutator_tx);
    }
}

pub struct PayloadAttestationBatchTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub payload_attestations: Vec<PayloadAttestationItem<P>>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PayloadAttestationBatchTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "PayloadAttestationBatchTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            payload_attestations,
            metrics,
        } = self;

        let Some(origin_label) = payload_attestations
            .first()
            .map(|attestation| attestation.origin.as_ref())
        else {
            return;
        };

        let _timer = metrics.as_ref().map(|metrics| {
            prometheus_metrics::start_timer_vec(
                &metrics.fc_payload_attestation_batch_task_times,
                origin_label,
            )
        });

        let results = payload_attestations
            .into_iter()
            .map(|payload_attestation| {
                store_snapshot.validate_payload_attestation(payload_attestation, false)
            })
            .collect();

        MutatorMessage::PayloadAttestationBatch {
            wait_group,
            results,
        }
        .send(&mutator_tx);
    }
}

pub struct ProposerPreferencesTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub signed_preferences: Arc<SignedProposerPreferences>,
    pub origin: ProposerPreferencesOrigin,
}

impl<P: Preset, W> Run for ProposerPreferencesTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "ProposerPreferencesTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            mutator_tx,
            wait_group,
            signed_preferences,
            origin,
        } = self;

        let result = store_snapshot.validate_proposer_preferences(signed_preferences, &origin);

        MutatorMessage::ProposerPreferences {
            wait_group,
            result,
            origin,
        }
        .send(&mutator_tx);
    }
}

pub struct PersistBlobSidecarsTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub storage: Arc<Storage<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PersistBlobSidecarsTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "PersistBlobSidecarTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            storage,
            mutator_tx,
            wait_group,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_blob_sidecar_persist_task_times.start_timer());

        let blob_sidecars = store_snapshot.unpersisted_blob_sidecars();

        match storage.append_blob_sidecars(blob_sidecars) {
            Ok(persisted_blob_ids) => {
                MutatorMessage::FinishedPersistingBlobSidecars {
                    wait_group,
                    persisted_blob_ids,
                }
                .send(&mutator_tx);
            }
            Err(error) => {
                warn_with_peers!("failed to persist blob sidecars to storage: {error:?}");
            }
        }
    }
}

pub struct PruneStateCacheTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub preserve_unfinalized_fork_tips: bool,
    pub wait_group: W,
}

impl<P: Preset, W> Run for PruneStateCacheTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "PruneStateCacheTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            preserve_unfinalized_fork_tips,
            wait_group,
        } = self;

        store_snapshot.prune_state_cache(preserve_unfinalized_fork_tips);

        drop(wait_group);
    }
}

pub struct PersistDataColumnSidecarsTask<P: Preset, W> {
    pub slot: Slot,
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub storage: Arc<Storage<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PersistDataColumnSidecarsTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "PersistDataColumnSidecarTask::run")]
    fn run(self) {
        let Self {
            slot,
            storage,
            store_snapshot,
            mutator_tx,
            wait_group,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            metrics
                .fc_data_column_sidecar_persist_task_times
                .start_timer()
        });

        let data_column_sidecars = store_snapshot.unpersisted_data_column_sidecars();

        match storage.append_data_column_sidecars(data_column_sidecars) {
            Ok(persisted_data_column_ids) => {
                MutatorMessage::FinishedPersistingDataColumnSidecars {
                    wait_group,
                    persisted_data_column_ids,
                    slot,
                }
                .send(&mutator_tx);
            }
            Err(error) => {
                warn_with_peers!("failed to persist data column sidecars to storage: {error:?}");
            }
        }
    }
}

pub struct PersistExecutionPayloadEnvelopesTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub storage: Arc<Storage<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PersistExecutionPayloadEnvelopesTask<P, W> {
    fn run(self) {
        let Self {
            store_snapshot,
            storage,
            mutator_tx,
            wait_group,
            metrics,
        } = self;

        let _timer = metrics.as_ref().map(|metrics| {
            metrics
                .fc_execution_payload_envelope_persist_task_times
                .start_timer()
        });

        let envelopes = store_snapshot.unpersisted_envelopes();

        match storage.append_execution_payload_envelopes(envelopes) {
            Ok(persisted_block_roots) => {
                MutatorMessage::FinishedPersistingExecutionPayloadEnvelopes {
                    wait_group,
                    persisted_block_roots,
                }
                .send(&mutator_tx);
            }
            Err(error) => {
                warn_with_peers!(
                    "failed to persist execution payload envelopes to storage: {error:?}"
                );
            }
        }
    }
}

pub struct CheckpointStateTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub state_cache: Arc<StateCacheProcessor<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub wait_group: W,
    pub checkpoint: Checkpoint,
    pub pubkey_cache: Arc<PubkeyCache>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for CheckpointStateTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "CheckpointStateTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            state_cache,
            mutator_tx,
            wait_group,
            checkpoint,
            pubkey_cache,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_checkpoint_state_task_times.start_timer());

        let Checkpoint { epoch, root } = checkpoint;

        let slot = misc::compute_start_slot_at_epoch::<P>(epoch);

        let checkpoint_state = match state_cache.try_state_at_slot(
            &pubkey_cache,
            &store_snapshot,
            root,
            slot,
            store_snapshot.is_forward_synced(),
        ) {
            Ok(state) => state,
            Err(error) => {
                warn_with_peers!("failed to compute checkpoint state: {error:?}");
                return;
            }
        };

        MutatorMessage::CheckpointState {
            wait_group,
            checkpoint,
            checkpoint_state,
        }
        .send(&mutator_tx);
    }
}

pub struct PreprocessStateTask<P: Preset, W> {
    pub store_snapshot: Arc<Store<P, Storage<P>>>,
    pub state_cache: Arc<StateCacheProcessor<P>>,
    pub mutator_tx: Sender<MutatorMessage<P, W>>,
    pub head_block_root: H256,
    pub next_slot: Slot,
    pub pubkey_cache: Arc<PubkeyCache>,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PreprocessStateTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "PreprocessStateTask::run")]
    fn run(self) {
        let Self {
            store_snapshot,
            state_cache,
            mutator_tx,
            head_block_root,
            next_slot,
            pubkey_cache,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_preprocess_state_task_times.start_timer());

        match state_cache.state_at_slot_quiet(
            &pubkey_cache,
            &store_snapshot,
            head_block_root,
            next_slot,
        ) {
            Ok(state) => {
                if let Err(error) =
                    initialize_preprocessed_state_cache(store_snapshot.chain_config(), &state)
                {
                    warn_with_peers!(
                        "failed to initialize preprocessed state's cache values: {error:?}"
                    );
                }

                MutatorMessage::PreprocessedBeaconState { state }.send(&mutator_tx);
            }
            Err(error) => {
                warn_with_peers!("failed to preprocess beacon state for the next slot: {error:?}");
            }
        }
    }
}

pub struct PersistPubkeyCacheTask<P: Preset, W> {
    pub pubkey_cache: Arc<PubkeyCache>,
    pub state: Arc<CombinedBeaconState<P>>,
    pub wait_group: W,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for PersistPubkeyCacheTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "PersistPubkeyCacheTask::run")]
    fn run(self) {
        let Self {
            pubkey_cache,
            state,
            wait_group,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_persist_pubkey_cache_task_times.start_timer());

        if let Err(error) = pubkey_cache.persist(&state) {
            warn_with_peers!("failed to persist pubkey cache to disk: {error:?}");
        }

        drop(wait_group);
    }
}

/// Verifies the deposit signatures added to `pending_deposits` by the block just processed.
pub struct CacheDepositSignaturesTask<P: Preset, W> {
    pub config: Arc<Config>,
    pub pubkey_cache: Arc<PubkeyCache>,
    pub state: Arc<CombinedBeaconState<P>>,
    pub wait_group: W,
    pub metrics: Option<Arc<Metrics>>,
}

impl<P: Preset, W> Run for CacheDepositSignaturesTask<P, W> {
    #[instrument(skip_all, level = "debug", name = "CacheDepositSignaturesTask::run")]
    fn run(self) {
        let Self {
            config,
            pubkey_cache,
            state,
            wait_group,
            metrics,
        } = self;

        let _timer = metrics
            .as_ref()
            .map(|metrics| metrics.fc_cache_deposit_signatures_task_times.start_timer());

        let verified = deposit_signatures::cache_new_pending_deposit_signatures(
            &config,
            &pubkey_cache,
            &state,
        );

        if verified > 0 {
            debug_with_peers!(
                "verified {verified} new pending deposit signatures (slot: {})",
                state.slot(),
            );
        }

        drop(wait_group);
    }
}

fn initialize_preprocessed_state_cache<P: Preset>(
    config: &Config,
    state: &impl BeaconState<P>,
) -> Result<()> {
    accessors::get_or_try_init_beacon_proposer_index(config, state, false)?;
    accessors::get_or_init_active_validator_indices_shuffled(state, RelativeEpoch::Current, false)?;
    accessors::get_or_init_active_validator_indices_shuffled(state, RelativeEpoch::Next, false)?;
    accessors::get_or_init_total_active_balance(state, false);

    Ok(())
}

pub struct StateAtSlotCacheFlushTask<P: Preset> {
    pub state_at_slot_cache: Arc<StateAtSlotCache<P>>,
}

impl<P: Preset> Run for StateAtSlotCacheFlushTask<P> {
    #[instrument(skip_all, level = "debug", name = "StateAtSlotCacheFlushTask::run")]
    fn run(self) {
        let Self {
            state_at_slot_cache,
        } = self;

        if let Err(error) = state_at_slot_cache.flush() {
            warn_with_peers!("failed to flush state at slot cache: {error:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use core::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use std::sync::{
        Arc, Mutex,
        mpsc::{Receiver, Sender, channel},
    };

    use crossbeam_utils::sync::WaitGroup;
    use eth2_libp2p::{GossipId, MessageId};
    use execution_engine::MockExecutionEngine;
    use fork_choice_store::{
        Error as StoreError, ExecutionProofOrigin, ExecutionProofPreparation,
        ExecutionProofVerificationOutcome,
    };
    use proof_engine::{NullProofEngine, ProofEngine, ProofVerdict};
    use pubkey_cache::PubkeyCache;
    use ssz::Hc;
    use std_ext::ArcExt as _;
    use types::{
        config::Config,
        eip8025::containers::{
            ExecutionProof, ExecutionProofEnvelope, ProofData, SignedExecutionProofEnvelope,
        },
        phase0::primitives::H256,
        preset::Minimal,
    };

    use crate::{
        controller::MutatorHandle,
        events::EventChannels,
        messages::{MutatorMessage, P2pMessage},
        specialized::TestController,
        tasks::{
            ProcessExecutionProofTask, Run as _, classify_execution_proof_preparation,
            execution_proof_verification_outcome,
        },
        unbounded_sink::UnboundedSink,
    };

    // `bls` is not a direct dependency, so `SignatureBytes::default()` cannot be named.
    #[expect(clippy::default_trait_access)]
    fn test_signed_proof() -> Arc<SignedExecutionProofEnvelope> {
        let proof_data = ProofData::try_from(vec![1, 2, 3]).expect("proof data should build");

        Arc::new(SignedExecutionProofEnvelope {
            message: Hc::from(ExecutionProofEnvelope {
                proof_data,
                proof_type: 1,
                beacon_block_root: H256::zero(),
            }),
            validator_index: 0,
            signature: Default::default(),
        })
    }

    const TEST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

    #[derive(Clone)]
    struct TestP2pSink(Sender<P2pMessage<Minimal>>);

    impl UnboundedSink<P2pMessage<Minimal>> for TestP2pSink {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }

        fn unbounded_send(&self, message: P2pMessage<Minimal>) -> Result<(), P2pMessage<Minimal>> {
            self.0.send(message).map_err(|error| error.0)
        }
    }

    type TestGossipControllerParts = (
        Arc<TestController<Minimal>>,
        MutatorHandle<Minimal, WaitGroup>,
        Receiver<P2pMessage<Minimal>>,
    );

    // Test-only selection between the default-Null constructor and explicit injection. The
    // production Controller boundary always requires an engine Arc.
    fn test_gossip_controller(
        injected_proof_engine: Option<Arc<dyn ProofEngine>>,
    ) -> TestGossipControllerParts {
        let config = Arc::new(Config::minimal());
        let state = factory::min_genesis_state::<Minimal>(&config, &PubkeyCache::default())
            .expect("should build beacon state")
            .0;
        let block = Arc::new(genesis::beacon_block(&state));
        let (p2p_tx, p2p_rx) = channel();
        let p2p_sink = TestP2pSink(p2p_tx);
        let execution_engine = Arc::new(Mutex::new(MockExecutionEngine::new(true, false, None)));
        let pubkey_cache = Arc::new(PubkeyCache::default());
        let event_channels = Arc::new(EventChannels::default());

        let (controller, mutator_handle) = match injected_proof_engine {
            Some(proof_engine) => TestController::with_p2p_tx_and_proof_engine(
                config,
                pubkey_cache,
                block,
                state,
                execution_engine,
                proof_engine,
                p2p_sink,
                event_channels,
                Some(1),
            ),
            None => TestController::with_p2p_tx(
                config,
                pubkey_cache,
                block,
                state,
                execution_engine,
                p2p_sink,
                event_channels,
                Some(1),
            ),
        };

        (controller, mutator_handle, p2p_rx)
    }

    fn empty_signed_proof() -> Arc<SignedExecutionProofEnvelope> {
        let mut signed_proof = (*test_signed_proof()).clone();
        let mut envelope = (*signed_proof.message).clone();
        envelope.proof_data = ProofData::default();
        signed_proof.message = Hc::from(envelope);
        Arc::new(signed_proof)
    }

    fn test_gossip_id(label: &[u8]) -> GossipId {
        GossipId {
            source: GossipId::default().source,
            message_id: MessageId::new(label),
        }
    }

    fn receive_p2p_response(receiver: &Receiver<P2pMessage<Minimal>>) -> P2pMessage<Minimal> {
        receiver
            .recv_timeout(TEST_RESPONSE_TIMEOUT)
            .expect("Controller should emit a terminal gossip response")
    }

    fn assert_ignore_identity(response: P2pMessage<Minimal>, expected: &GossipId) {
        match response {
            P2pMessage::Ignore(actual) => {
                assert_eq!(actual.source, expected.source);
                assert_eq!(actual.message_id, expected.message_id);
            }
            other => panic!("expected Ignore for submitted gossip identity, got {other:?}"),
        }
    }

    fn assert_execution_proof_store_empty(controller: &TestController<Minimal>) {
        let snapshot = controller.store_snapshot();
        assert!(snapshot.execution_proofs().is_empty());
        assert!(snapshot.execution_proof_roots().is_empty());
        assert!(snapshot.execution_proof_provers().is_empty());
    }

    fn run_preparation_task(
        proof_engine: Arc<dyn ProofEngine>,
        signed_proof: Arc<SignedExecutionProofEnvelope>,
    ) -> MutatorMessage<Minimal, ()> {
        let config = Arc::new(Config::minimal());
        let genesis_state = factory::min_genesis_state::<Minimal>(&config, &PubkeyCache::default())
            .expect("should build beacon state")
            .0;
        let genesis_block = Arc::new(genesis::beacon_block(&genesis_state));
        let (controller, _mutator_handle) =
            TestController::quiet(config, genesis_block, genesis_state);

        let (mutator_tx, mutator_rx) = channel();

        ProcessExecutionProofTask {
            store_snapshot: controller.owned_store_snapshot(),
            proof_engine,
            mutator_tx,
            signed_proof,
            origin: ExecutionProofOrigin::Gossip(GossipId::default()),
        }
        .run();

        let message = mutator_rx.try_recv().expect("task should send an outcome");
        assert!(
            mutator_rx.try_recv().is_err(),
            "task sent more than one outcome"
        );
        message
    }

    #[test]
    fn execution_proof_unknown_block_ignores_before_engine() {
        let message = run_preparation_task(
            Arc::new(NoVerificationEngine { null: false }),
            test_signed_proof(),
        );
        assert!(matches!(
            message,
            MutatorMessage::ExecutionProofPrepared {
                result: Ok(ExecutionProofPreparation::Ignore(
                    "execution proof's beacon block has not been seen"
                )),
                ..
            }
        ));
    }

    struct NoVerificationEngine {
        null: bool,
    }

    impl ProofEngine for NoVerificationEngine {
        fn is_null(&self) -> bool {
            self.null
        }
        fn verify_execution_proof(&self, _: ExecutionProof) -> ProofVerdict {
            panic!("preparation must never enter the verifier")
        }
    }

    #[test]
    fn null_proof_engine_short_circuits_to_ignore() {
        // Empty input would REJECT during preparation, so this also proves the
        // null-engine guard precedes preparation, not just engine dispatch.
        let mut signed_proof = (*test_signed_proof()).clone();
        let mut message = (*signed_proof.message).clone();
        message.proof_data = ProofData::default();
        signed_proof.message = Hc::from(message);
        let proof_engines: [Arc<dyn ProofEngine>; 2] = [
            Arc::new(NullProofEngine),
            Arc::new(NoVerificationEngine { null: true }),
        ];
        for proof_engine in proof_engines {
            let message = run_preparation_task(proof_engine, Arc::new(signed_proof.clone()));
            assert!(matches!(
                message,
                MutatorMessage::ExecutionProof {
                    result: Ok(types::nonstandard::ValidationOutcomeWithReason::Ignore(
                        "proof engine not enabled"
                    )),
                    ..
                }
            ));
        }
    }

    #[test]
    fn execution_proof_empty_input_is_typed_peer_rejection() {
        let mut signed_proof = (*test_signed_proof()).clone();
        let mut envelope = (*signed_proof.message).clone();
        envelope.proof_data = ProofData::default();
        signed_proof.message = Hc::from(envelope);
        let message = run_preparation_task(
            Arc::new(NoVerificationEngine { null: false }),
            Arc::new(signed_proof),
        );
        let MutatorMessage::ExecutionProofPrepared {
            result: Err(error), ..
        } = message
        else {
            panic!("empty proof should be rejected");
        };
        assert!(matches!(
            error.downcast_ref::<StoreError<Minimal>>(),
            Some(StoreError::ExecutionProofEnvelopeEmptyProof)
        ));
    }

    #[test]
    fn execution_proof_preparation_rejects_only_envelope_errors() {
        let peer_errors = [
            StoreError::<Minimal>::ExecutionProofEnvelopeEmptyProof,
            StoreError::ExecutionProofEnvelopeUnsupportedProofType { proof_type: 255 },
            StoreError::ExecutionProofEnvelopeInvalidValidatorIndex {
                validator_index: 42,
            },
            StoreError::ExecutionProofEnvelopeInactiveValidator {
                validator_index: 42,
                epoch: 1,
            },
            StoreError::ExecutionProofEnvelopeInvalidSignature {
                validator_index: 42,
            },
        ];
        for error in peer_errors {
            // Context on anyhow errors must not hide the typed source.
            assert!(
                classify_execution_proof_preparation::<Minimal>(Err(
                    anyhow::Error::new(error).context("preparation")
                ))
                .is_err()
            );
        }
        for error in [
            anyhow::anyhow!("local binding failure"),
            StoreError::<Minimal>::InvalidExecutionPayload.into(),
        ] {
            assert!(matches!(
                classify_execution_proof_preparation::<Minimal>(Err(error)),
                Ok(ExecutionProofPreparation::Ignore(
                    "local execution proof preparation failure"
                ))
            ));
        }
    }

    #[test]
    fn execution_proof_preparation_replies_through_live_mutator() {
        let config = Arc::new(Config::minimal());
        let state = factory::min_genesis_state::<Minimal>(&config, &PubkeyCache::default())
            .expect("should build beacon state")
            .0;
        let block = Arc::new(genesis::beacon_block(&state));
        let (controller, _mutator_handle) = TestController::quiet(config, block, state);

        for (null, empty) in [(true, true), (false, true), (false, false)] {
            let mut proof = (*test_signed_proof()).clone();
            if empty {
                let mut envelope = (*proof.message).clone();
                envelope.proof_data = ProofData::default();
                proof.message = Hc::from(envelope);
            }
            let (sender, receiver) = futures::channel::oneshot::channel();
            ProcessExecutionProofTask {
                store_snapshot: controller.owned_store_snapshot(),
                proof_engine: Arc::new(NoVerificationEngine { null }),
                mutator_tx: controller.owned_mutator_tx(),
                signed_proof: Arc::new(proof),
                origin: ExecutionProofOrigin::Api(sender),
            }
            .run();
            let result = futures::executor::block_on(receiver)
                .expect("live mutator should send a terminal API response");
            if !null && empty {
                assert!(result.is_err(), "active empty proof should reject");
            } else {
                assert!(matches!(
                    result,
                    Ok(types::nonstandard::ValidationOutcomeWithReason::Ignore(_))
                ));
            }
            let snapshot = controller.store_snapshot();
            assert!(snapshot.execution_proofs().is_empty());
            assert!(snapshot.execution_proof_roots().is_empty());
            assert!(snapshot.execution_proof_provers().is_empty());
        }
    }

    #[test]
    fn execution_proof_engine_verdict_mapping_preserves_local_fault() {
        for (verdict, expected) in [
            (
                ProofVerdict::Valid,
                ExecutionProofVerificationOutcome::Valid,
            ),
            (
                ProofVerdict::Invalid,
                ExecutionProofVerificationOutcome::Invalid,
            ),
            (
                ProofVerdict::Undetermined,
                ExecutionProofVerificationOutcome::LocalFault,
            ),
        ] {
            assert_eq!(execution_proof_verification_outcome(verdict), expected);
        }
    }

    #[test]
    fn execution_proof_controller_default_engine_bypasses_empty_proof() {
        let (controller, _mutator_handle, p2p_rx) = test_gossip_controller(None);
        let gossip_id = test_gossip_id(b"default-null-proof");

        controller.on_gossip_execution_proof(empty_signed_proof(), gossip_id.clone());

        assert_ignore_identity(receive_p2p_response(&p2p_rx), &gossip_id);
        assert_execution_proof_store_empty(&controller);
    }

    #[test]
    fn execution_proof_controller_injected_null_engine_bypasses_empty_proof() {
        let (controller, _mutator_handle, p2p_rx) =
            test_gossip_controller(Some(Arc::new(NullProofEngine)));
        let gossip_id = test_gossip_id(b"injected-null-proof");

        controller.on_gossip_execution_proof(empty_signed_proof(), gossip_id.clone());

        assert_ignore_identity(receive_p2p_response(&p2p_rx), &gossip_id);
        assert_execution_proof_store_empty(&controller);
    }

    #[derive(Default)]
    struct TrackingProofEngine {
        null_checks: AtomicUsize,
        verification_calls: AtomicUsize,
    }

    impl ProofEngine for TrackingProofEngine {
        fn is_null(&self) -> bool {
            self.null_checks.fetch_add(1, Ordering::SeqCst);
            false
        }

        fn verify_execution_proof(&self, _: ExecutionProof) -> ProofVerdict {
            self.verification_calls.fetch_add(1, Ordering::SeqCst);
            ProofVerdict::Undetermined
        }
    }

    #[test]
    fn execution_proof_controller_uses_injected_engine_for_unknown_block() {
        let engine = Arc::new(TrackingProofEngine::default());
        let proof_engine: Arc<dyn ProofEngine> = engine.clone_arc();
        let (controller, _mutator_handle, p2p_rx) = test_gossip_controller(Some(proof_engine));
        let gossip_id = test_gossip_id(b"injected-active-proof");

        controller.on_gossip_execution_proof(test_signed_proof(), gossip_id.clone());

        assert_ignore_identity(receive_p2p_response(&p2p_rx), &gossip_id);
        assert_eq!(engine.null_checks.load(Ordering::SeqCst), 1);
        assert_eq!(engine.verification_calls.load(Ordering::SeqCst), 0);
        assert_execution_proof_store_empty(&controller);
    }
}
