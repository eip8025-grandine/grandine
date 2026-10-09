use bls::SignatureBytes;
use ethereum_types::H256;
use serde::{Deserialize, Serialize};
use ssz::{ByteList, Hc, ProgressiveList, Ssz};

use crate::{
    deneb::primitives::VersionedHash,
    eip8025::primitives::{MaxProofSize, ProofType},
    gloas::containers::{ExecutionPayload, ExecutionRequests},
    phase0::primitives::ValidatorIndex,
    preset::Preset,
};

/// The opaque proof bytes of an execution proof.
///
/// The spec defines this as a `ByteList` with `LIMIT = MAX_PROOF_SIZE`,
/// following consensus-specs#5593. The limit is enforced during
/// construction and decoding, and affects SSZ merkleization.
///
/// Construct from proof bytes with `TryFrom<Vec<u8>>`.
pub type ProofData = ByteList<MaxProofSize>;

/// The public input a verifier reconstructs and checks an
/// [`ExecutionProof`] against.
///
/// Defined as a `ProgressiveContainer` in consensus-specs, so
/// merkleization mixes in the active-field layout and supports adding
/// fields without changing roots for earlier layouts.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
#[ssz(stable(active = [1; 4]))]
pub struct PublicInput {
    pub new_payload_request_root: H256,
    pub successful_validation: bool,
    #[serde(with = "serde_utils::string_or_native")]
    pub chain_id: u64,
    #[serde(with = "serde_utils::string_or_native")]
    pub schema_id: u16,
}

/// The proof-engine input a verifier assembles locally.
///
/// This value is assembled locally for verification from the
/// [`ExecutionProofEnvelope`] carried by
/// [`SignedExecutionProofEnvelope`].
#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProof {
    pub proof_data: ProofData,
    #[serde(with = "serde_utils::string_or_native")]
    pub proof_type: ProofType,
    pub public_input: PublicInput,
}

/// A proof bound to the payload it certifies, by the block root that
/// payload belongs to.
///
/// This is the message carried by [`SignedExecutionProofEnvelope`].
/// It carries `beacon_block_root` in place of `public_input`: the
/// verifier derives the public input locally from the stored payload.
#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProofEnvelope {
    pub proof_data: ProofData,
    #[serde(with = "serde_utils::string_or_native")]
    pub proof_type: ProofType,
    pub beacon_block_root: H256,
}

/// An [`ExecutionProofEnvelope`] signed by the validator that
/// produced the proof.
///
/// The message is wrapped in [`Hc`] so its Merkle root is computed
/// once and reused both as the gossip de-duplication key and as the
/// `object_root` for the domain-separated signing root.
#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SignedExecutionProofEnvelope {
    pub message: Hc<ExecutionProofEnvelope>,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub signature: SignatureBytes,
}

/// Which proof types to generate, for the prover-role `request_proofs` call.
///
/// Mirrors the `ProofAttributes` dataclass in
/// [`proof-engine.md`](https://github.com/ethereum/consensus-specs/blob/7fa044833194cbea2908f76c0de102d168d88fb0/specs/_features/eip8025/proof-engine.md#new-proofattributes):
/// a sequence of requested [`ProofType`]s.
///
/// The spec sequence is unbounded, so this is a plain [`Vec`], not an SSZ
/// list: any limit belongs to the validation bodies, not the shape. Nothing
/// reads this yet — Grandine is verifier-only, so the prover-role stubs
/// reject without looking at it.
#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProofAttributes {
    #[serde(with = "serde_utils::string_or_native_sequence")]
    pub proof_types: Vec<ProofType>,
}

/// The Gloas `NewPayloadRequest` whose execution a proof certifies.
///
/// The `hash_tree_root` of this container is
/// `public_input.new_payload_request_root`, which binds the proof to
/// the payload it certifies.
///
/// Defined as a `ProgressiveContainer` in the Gloas consensus specs
/// and built from the Gloas `ExecutionPayload` and
/// `ExecutionRequests`.
///
/// `versioned_hashes` follows consensus-specs#5643 rather than
/// `master`: it is a `ProgressiveList` with
/// `LIMIT = MAX_BLOB_COMMITMENTS_PER_BLOCK`, so its root differs from
/// `master`'s `List` root until that change merges.
#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1; 4]))]
pub struct NewPayloadRequest<P: Preset> {
    pub execution_payload: ExecutionPayload<P>,
    // consensus-specs#5643 limits this to
    // `MAX_BLOB_COMMITMENTS_PER_BLOCK`, represented here by
    // `MaxBlobCommitmentsPerBlock`. The limit applies on construction
    // and decoding but not to merkleization.
    pub versioned_hashes: ProgressiveList<VersionedHash, P::MaxBlobCommitmentsPerBlock>,
    pub parent_beacon_block_root: H256,
    pub execution_requests: ExecutionRequests<P>,
}
