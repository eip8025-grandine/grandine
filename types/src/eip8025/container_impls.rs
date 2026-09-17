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
// Most variable-size collections in `SSZNewPayloadRequest` use
// progressive lists or progressive byte lists, whose roots do not
// depend on their bounds. Three preset-derived bounds still affect
// the root: `BytesPerLogsBloom` and `MaxExtraDataBytes` through
// `ExecutionPayload`, and `MaxBlobCommitmentsPerBlock` through
// `versioned_hashes`. `MaxBytesPerTransaction` affects decoding.
//
// All four bounds are equal across presets today. These assertions
// make any divergence explicit at compile time.
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

// Equal across presets is not enough: the implementation must also
// use the mainnet values pinned by consensus-specs, so those are
// asserted here.
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
    /// `get_execution_proof` uses: the payload, parent beacon block
    /// root, and execution requests come from the
    /// `ExecutionPayloadEnvelope`, while `versioned_hashes` are
    /// derived from
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
