use ssz::{ContiguousList, H256, SszHash as _};
use static_assertions::const_assert_eq;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;

use crate::{
    combined::{ExecutionPayload as CombinedExecutionPayload, ExecutionPayloadParams},
    eip8025::{containers::NewPayloadRequest, error::PayloadBindingError},
    preset::{Mainnet, Preset},
};

// The spec's `NewPayloadRequest` uses fixed bounds while the fields reused here are
// preset-derived. Binding is Mainnet-only because those two agree on Mainnet and nowhere else:
// `MaxWithdrawalsPerPayload` is 16 on Mainnet and 4 on Minimal, which is enough on its own to
// change the root.
//
// These assertions are the guard the design asks for. If a preset value ever diverges from the
// spec's fixed bound, this stops compiling rather than silently producing a root no prover
// agrees with.
const_assert_eq!(<Mainnet as Preset>::BytesPerLogsBloom::USIZE, 256);
const_assert_eq!(<Mainnet as Preset>::MaxExtraDataBytes::USIZE, 32);
// 1 GiB
const_assert_eq!(
    <Mainnet as Preset>::MaxBytesPerTransaction::USIZE,
    0x4000_0000
);
// 1 Mi
const_assert_eq!(
    <Mainnet as Preset>::MaxTransactionsPerPayload::USIZE,
    0x0010_0000
);
const_assert_eq!(<Mainnet as Preset>::MaxWithdrawalsPerPayload::USIZE, 16);
const_assert_eq!(
    <Mainnet as Preset>::MaxDepositRequestsPerPayload::USIZE,
    8192
);
const_assert_eq!(
    <Mainnet as Preset>::MaxWithdrawalRequestsPerPayload::USIZE,
    16
);
const_assert_eq!(
    <Mainnet as Preset>::MaxConsolidationRequestsPerPayload::USIZE,
    2
);

// This one bounds a field the spec leaves unbounded. See the comment on
// `NewPayloadRequest.versioned_hashes`: the value is a prototype assumption, not a settled rule.
// The assertion pins what the prototype currently assumes rather than what the spec requires.
const_assert_eq!(<Mainnet as Preset>::MaxBlobCommitmentsPerBlock::USIZE, 4096);

impl<P: Preset> NewPayloadRequest<P> {
    /// Reconstructs the spec's `NewPayloadRequest` from the pair Grandine already holds at the
    /// `notify_new_payload` boundary.
    ///
    /// EIP-8025 builds on Gloas, which inherits the Electra shape of `NewPayloadRequest`, so
    /// payloads and params from earlier phases cannot be bound.
    pub fn new(
        payload: &CombinedExecutionPayload<P>,
        params: &ExecutionPayloadParams<P>,
    ) -> Result<Self, PayloadBindingError> {
        let CombinedExecutionPayload::Deneb(execution_payload) = payload else {
            return Err(PayloadBindingError::PayloadPhaseNotSupported {
                phase: payload.phase(),
            });
        };

        let ExecutionPayloadParams::Electra {
            versioned_hashes,
            parent_beacon_block_root,
            execution_requests,
        } = params
        else {
            return Err(PayloadBindingError::ExecutionRequestsMissing);
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

/// Computes `public_input.new_payload_request_root` for a payload and its params.
///
/// Mainnet only. The spec's container has fixed bounds and Grandine's are preset-derived; they
/// agree on Mainnet and not on Minimal, so a root computed under another preset would be
/// meaningless to a prover. The `const_assert_eq!`s above guard the Mainnet side of that.
///
/// The root is still provisional even on Mainnet: Grandine does not support EIP-7928's
/// `block_access_list`, which the EIP's `ExecutionPayload` schema includes, so this cannot match
/// a prover's root until that support lands. The bound chosen for `versioned_hashes` is a
/// prototype assumption on top of that; see the comment on the field.
pub fn new_payload_request_root(
    payload: &CombinedExecutionPayload<Mainnet>,
    params: &ExecutionPayloadParams<Mainnet>,
) -> Result<H256, PayloadBindingError> {
    NewPayloadRequest::new(payload, params).map(|request| request.hash_tree_root())
}
