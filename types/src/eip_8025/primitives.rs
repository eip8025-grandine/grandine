use serde::{Deserialize, Serialize};
use ssz::{ByteList, Ssz};

use crate::{phase0::primitives::H256, preset::Preset};

pub type ProofType = u8;

pub type ProofData<P> = ByteList<<P as Preset>::MaxProofSize>;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize, Serialize, Ssz)]
#[serde(deny_unknown_fields)]
pub struct PublicInput {
    pub new_payload_request_root: H256,
}

