use bls::SignatureBytes;
use ethereum_types::H256;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{
    Hc, ProgressiveByteList, ReadError, Size, Ssz, SszHash, SszRead, SszSize, SszWrite, WriteError,
};

use crate::{
    eip8025::{
        consts::MAX_PROOF_SIZE,
        primitives::{MaxProofSize, ProofType},
    },
    phase0::primitives::ValidatorIndex,
};

/// The opaque proof bytes of an execution proof.
///
/// The spec defines this as a `ProgressiveByteList`, which has no length bound. Merkleization
/// does not depend on the bound, so the root does not depend on `MAX_PROOF_SIZE`, which matters
/// because that constant is still provisional.
///
/// The bound is enforced here, on construction and on decoding, and again by `MaxProofSize` on
/// the inner list, which bounds decoding but not the root. Both report the same
/// [`ReadError::ListTooLong`].
///
/// There is deliberately no conversion from `ProgressiveByteList`: it would let callers build a
/// `ProofData` without going through the explicit bound. `TryFrom<Vec<u8>>` is the way in.
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

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct PublicInput {
    pub new_payload_request_root: H256,
}

#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProof {
    pub proof_data: ProofData,
    #[serde(with = "serde_utils::string_or_native")]
    pub proof_type: ProofType,
    pub public_input: PublicInput,
}

/// An [`ExecutionProof`] signed by the validator that produced it.
///
/// The message is wrapped in [`Hc`] the way `SignedBeaconBlock` wraps its message, so the object
/// root is merkleized once and serves both consumers: the gossip de-duplication key, and the
/// `object_root` the domain-separated signing root is built from.
#[derive(Clone, PartialEq, Eq, Default, Debug, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct SignedExecutionProof {
    pub message: Hc<ExecutionProof>,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub signature: SignatureBytes,
}
