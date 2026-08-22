use bls::SignatureBytes;
use serde::{Deserialize, Serialize};
use ssz::Ssz;

use crate::{
    eip_8025::primitives::{ProofData, ProofType, PublicInput},
    phase0::primitives::ValidatorIndex,
    preset::Preset,
};

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct ExecutionProof<P: Preset> {
    pub proof_data: ProofData<P>,
    pub proof_type: ProofType,
    pub public_input: PublicInput,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(bound = "", deny_unknown_fields)]
pub struct SignedExecutionProof<P: Preset> {
    pub message: ExecutionProof<P>,
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub signature: SignatureBytes,
}
