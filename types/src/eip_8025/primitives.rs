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

#[cfg(test)]
mod tests {
    use serde_json::json;
    use ssz::SszHash;

    use super::*;

    #[test]
    fn public_input_json_round_trips() -> serde_json::Result<()> {
        let json = json!({
            "new_payload_request_root": format!("0x{}", "bb".repeat(32)),
        });
        let expected = PublicInput {
            new_payload_request_root: H256([0xbb; 32]),
        };

        assert_eq!(
            serde_json::from_value::<PublicInput>(json.clone())?,
            expected
        );
        assert_eq!(serde_json::to_value(expected)?, json);

        Ok(())
    }

    #[test]
    fn public_input_rejects_unknown_fields() {
        let json = json!({
            "new_payload_request_root": format!("0x{}", "bb".repeat(32)),
            "chain_config": {},
        });

        serde_json::from_value::<PublicInput>(json)
            .expect_err("deserialization should fail due to unknown field");
    }

    #[test]
    fn default_public_input_hash_tree_root_is_the_zero_chunk() {
        assert_eq!(PublicInput::default().hash_tree_root(), H256([0x00; 32]),);
    }
}
