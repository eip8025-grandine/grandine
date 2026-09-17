use bls::SignatureBytes;
use ethereum_types::H256;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{
    ContiguousList, Hc, ProgressiveByteList, ReadError, Size, Ssz, SszHash, SszRead, SszSize,
    SszWrite, WriteError,
};

use crate::{
    deneb::primitives::VersionedHash,
    eip8025::{
        consts::MAX_PROOF_SIZE,
        primitives::{MaxProofSize, ProofType},
    },
    gloas::containers::{ExecutionPayload, ExecutionRequests},
    phase0::primitives::ValidatorIndex,
    preset::Preset,
};

/// The opaque proof bytes of an execution proof.
///
/// The spec defines this as an unbounded `ProgressiveList[Byte]`.
/// `MAX_PROOF_SIZE` is enforced during construction and decoding, but
/// does not affect SSZ merkleization.
///
/// Construct from proof bytes with `TryFrom<Vec<u8>>`.
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

/// The `SSZNewPayloadRequest` whose execution a proof certifies.
///
/// The `hash_tree_root` of this container is
/// `public_input.new_payload_request_root`, which binds the proof to
/// the payload it certifies.
///
/// Defined as a `ProgressiveContainer` in consensus-specs and built
/// from the Gloas `ExecutionPayload` and `ExecutionRequests`.
///
/// The `SSZ` prefix distinguishes this type from the Engine API
/// request of the same name, which is not an SSZ container.
#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(stable(active = [1; 4]))]
pub struct SszNewPayloadRequest<P: Preset> {
    pub execution_payload: ExecutionPayload<P>,
    // consensus-specs bounds this by
    // `MAX_BLOB_COMMITMENTS_PER_BLOCK`, represented here by
    // `MaxBlobCommitmentsPerBlock`.
    pub versioned_hashes: ContiguousList<VersionedHash, P::MaxBlobCommitmentsPerBlock>,
    pub parent_beacon_block_root: H256,
    pub execution_requests: ExecutionRequests<P>,
}
