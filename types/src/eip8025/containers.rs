use bls::SignatureBytes;
use ethereum_types::H256;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{
    ContiguousList, Hc, ProgressiveByteList, ReadError, Size, Ssz, SszHash, SszRead, SszSize,
    SszWrite, WriteError,
};

use crate::{
    deneb::{containers::ExecutionPayload, primitives::VersionedHash},
    eip8025::{
        consts::MAX_PROOF_SIZE,
        primitives::{MaxProofSize, ProofType},
    },
    electra::containers::ExecutionRequests,
    phase0::primitives::ValidatorIndex,
    preset::Preset,
};

/// The opaque proof bytes of an execution proof.
///
/// The spec defines this as a `ProgressiveList[Byte]`, which has
/// no length bound. Merkleization does not depend on the bound, so
/// the root does not depend on `MAX_PROOF_SIZE`, which matters
/// because that constant is still provisional.
///
/// The bound is enforced here, on construction and on decoding, and
/// again by `MaxProofSize` on the inner list, which bounds decoding
/// but not the root. Both report the same [`ReadError::ListTooLong`].
///
/// There is deliberately no conversion from `ProgressiveByteList`: it
/// would let callers build a `ProofData` without going through the
/// explicit bound. `TryFrom<Vec<u8>>` is the way in.
#[derive(Clone, PartialEq, Eq, Default, Debug, Serialize)]
#[serde(transparent)]
pub struct ProofData {
    bytes: ProgressiveByteList<MaxProofSize>,
}

impl ProofData {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }

    const fn validate_length(length: usize) -> Result<(), ReadError> {
        if length > MAX_PROOF_SIZE {
            return Err(ReadError::ListTooLong {
                maximum: MAX_PROOF_SIZE,
                actual: length,
            });
        }

        Ok(())
    }
}

impl TryFrom<Vec<u8>> for ProofData {
    type Error = ReadError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, ReadError> {
        Self::validate_length(bytes.len())?;

        Ok(Self {
            bytes: bytes.try_into()?,
        })
    }
}

impl<'de> Deserialize<'de> for ProofData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let bytes = ProgressiveByteList::<MaxProofSize>::deserialize(deserializer)?;

        Self::validate_length(bytes.as_bytes().len()).map_err(D::Error::custom)?;

        Ok(Self { bytes })
    }
}

impl SszSize for ProofData {
    const SIZE: Size = ProgressiveByteList::<MaxProofSize>::SIZE;
}

impl<C> SszRead<C> for ProofData {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        Self::validate_length(bytes.len())?;

        ProgressiveByteList::<MaxProofSize>::from_ssz_unchecked(context, bytes)
            .map(|bytes| Self { bytes })
    }
}

impl SszWrite for ProofData {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.bytes.write_variable(bytes)
    }
}

impl SszHash for ProofData {
    type PackingFactor = <ProgressiveByteList<MaxProofSize> as SszHash>::PackingFactor;

    fn hash_tree_root(&self) -> H256 {
        self.bytes.hash_tree_root()
    }
}

/// The public input a verifier reconstructs and checks an
/// [`ExecutionProof`] against.
///
/// A `ProgressiveContainer` in consensus-specs, so its root mixes in
/// the active-field layout and stays stable as fields are added.
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
/// Neither signed nor gossiped: [`ExecutionProofEnvelope`] is the object that travels.
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
/// This is the gossiped object, not [`ExecutionProof`]. It carries
/// `beacon_block_root` in place of `public_input`: the verifier
/// derives the public input locally from the stored payload so it
/// never travels with the proof.
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
/// The message is wrapped in [`Hc`] the way `SignedBeaconBlock` wraps
/// its message, so the object root is merkleized once and serves both
/// consumers: the gossip de-duplication key, and the `object_root`
/// the domain-separated signing root is built from.
#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SignedExecutionProofEnvelope {
    pub message: Hc<ExecutionProofEnvelope>,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub signature: SignatureBytes,
}

/// The Engine API `NewPayloadRequest` whose execution a proof certifies.
///
/// `hash_tree_root` of this container is `public_input.new_payload_request_root`, the only link
/// between a proof and the payload it certifies.
///
/// The spec gives this container fixed bounds, whereas the fields here are reused from Grandine's
/// preset-derived types. Those agree on Mainnet but not on Minimal, so binding is Mainnet-only;
/// see [`new_payload_request_root`](super::container_impls::new_payload_request_root), which is
/// where that restriction is enforced and where the bounds are asserted.
///
/// The root this produces cannot match a prover's yet. The EIP's `ExecutionPayload` schema
/// includes EIP-7928's `block_access_list`, which Grandine does not support, so the container is
/// missing a field the prover commits to. Payload binding stays provisional until that lands.
#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct NewPayloadRequest<P: Preset> {
    pub execution_payload: ExecutionPayload<P>,
    // PROTOTYPE ASSUMPTION, NOT A SETTLED PROTOCOL RULE.
    //
    // Neither pinned source specifies a bound for this field: consensus-specs has an unbounded
    // `Sequence[VersionedHash]` and the EIP has a `Tuple[VersionedHash, ...]`. Versioned hashes
    // are derived one-to-one from blob commitments, so the commitment bound is the natural
    // stand-in, but it changes every root it takes part in and must be revisited once the design
    // question is resolved. It is isolated here so that replacing it is a one-line change.
    pub versioned_hashes: ContiguousList<VersionedHash, P::MaxBlobCommitmentsPerBlock>,
    pub parent_beacon_block_root: H256,
    pub execution_requests: ExecutionRequests<P>,
}
