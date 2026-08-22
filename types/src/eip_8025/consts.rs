use ethereum_types::H32;
use hex_literal::hex;

use crate::phase0::primitives::DomainType;

pub const DOMAIN_EXECUTION_PROOF: DomainType = H32(hex!("0F000000"));

pub const MAX_SIGNED_EXECUTION_PROOF_SIZE: u64 = 4_194_449;
