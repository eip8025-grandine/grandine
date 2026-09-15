use ssz::ContiguousList;
use static_assertions::const_assert_eq;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;

use crate::{
    combined::{ExecutionPayload as CombinedExecutionPayload, ExecutionPayloadParams},
    eip8025::{containers::SszNewPayloadRequest, error::PayloadBindingError},
    preset::{Mainnet, Minimal, Preset},
};

// Payload binding is preset-independent under Gloas.
//
// Most of what `SSZNewPayloadRequest` contains carries no limit into
// its root: `transactions`, `withdrawals` and every field of
// `ExecutionRequests` are progressive lists, and each `Transaction`
// and the `BlockAccessList` are progressive byte lists, whose roots
// do not depend on their bounds. Three preset-derived bounds still
// reach the root — `BytesPerLogsBloom` and `MaxExtraDataBytes`
// through `ExecutionPayload`, and `MaxBlobCommitmentsPerBlock`
// through `versioned_hashes` — and `MaxBytesPerTransaction` bounds
// decoding.
//
// All four are equal across presets today. If one ever diverges, this
// stops compiling rather than silently producing a root that depends
// on which preset a node runs.
const_assert_eq!(
    <Mainnet as Preset>::BytesPerLogsBloom::USIZE,
    <Minimal as Preset>::BytesPerLogsBloom::USIZE
);
const_assert_eq!(
    <Mainnet as Preset>::MaxExtraDataBytes::USIZE,
    <Minimal as Preset>::MaxExtraDataBytes::USIZE
);
const_assert_eq!(
    <Mainnet as Preset>::MaxBlobCommitmentsPerBlock::USIZE,
    <Minimal as Preset>::MaxBlobCommitmentsPerBlock::USIZE
);
const_assert_eq!(
    <Mainnet as Preset>::MaxBytesPerTransaction::USIZE,
    <Minimal as Preset>::MaxBytesPerTransaction::USIZE
);

// Equal across presets is not enough on its own: a prover commits to
// the values consensus-specs pins for mainnet, so those are pinned
// here too.
const_assert_eq!(<Mainnet as Preset>::BytesPerLogsBloom::USIZE, 256);
const_assert_eq!(<Mainnet as Preset>::MaxExtraDataBytes::USIZE, 32);
const_assert_eq!(<Mainnet as Preset>::MaxBlobCommitmentsPerBlock::USIZE, 4096);
// 1 GiB
const_assert_eq!(
    <Mainnet as Preset>::MaxBytesPerTransaction::USIZE,
    0x4000_0000
);

impl<P: Preset> SszNewPayloadRequest<P> {
    /// Reconstructs the spec's `SSZNewPayloadRequest` from the pair
    /// Grandine already holds at the `notify_new_payload` boundary.
    ///
    /// That pair is assembled from the same sources the spec's
    /// `get_execution_proof` uses: the payload and execution requests
    /// come from the `ExecutionPayloadEnvelope`, and
    /// `versioned_hashes` from
    /// `state.latest_execution_payload_bid.blob_kzg_commitments`.
    ///
    /// EIP-8025 builds on Gloas, so payloads and params from earlier
    /// phases cannot be bound.
    pub fn new(
        payload: &CombinedExecutionPayload<P>,
        params: &ExecutionPayloadParams<P>,
    ) -> Result<Self, PayloadBindingError> {
        let CombinedExecutionPayload::Gloas(execution_payload) = payload else {
            return Err(PayloadBindingError::PayloadPhaseNotSupported {
                phase: payload.phase(),
            });
        };

        let ExecutionPayloadParams::Gloas {
            versioned_hashes,
            parent_beacon_block_root,
            execution_requests,
        } = params
        else {
            return Err(PayloadBindingError::ExecutionRequestsNotGloas);
        };

        let versioned_hashes = ContiguousList::try_from_iter(versioned_hashes.iter().copied())
            .map_err(PayloadBindingError::VersionedHashesTooLong)?;

        Ok(Self {
            execution_payload: execution_payload.clone(),
            versioned_hashes,
            parent_beacon_block_root: *parent_beacon_block_root,
            execution_requests: execution_requests.clone(),
        })
    }
}
