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

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use serde_json::json;
    use ssz::{SszHash, SszReadDefault, SszWrite};
    use typenum::Unsigned;

    use crate::{
        phase0::primitives::H256,
        preset::{Mainnet, Minimal},
    };

    use super::*;

    #[test]
    fn default_signed_execution_proof_round_trips_through_ssz() {
        assert_ssz_round_trip(SignedExecutionProof::<Mainnet>::default());
    }

    #[test]
    fn populated_signed_execution_proof_round_trips_through_ssz_on_mainnet() {
        assert_ssz_round_trip(populated_signed_execution_proof());
    }

    #[test]
    fn populated_signed_execution_proof_round_trips_through_ssz_on_minimal() {
        let proof = SignedExecutionProof::<Minimal> {
            message: ExecutionProof {
                proof_data: ProofData::<Minimal>::try_from(vec![0xaa; 64])
                    .expect("length is under maximum"),
                proof_type: 7,
                public_input: PublicInput {
                    new_payload_request_root: H256([0x11; 32]),
                },
            },
            validator_index: 42,
            signature: SignatureBytes::default(),
        };

        assert_ssz_round_trip(proof);
    }

    #[test]
    fn signed_execution_proof_round_trips_max_size_proof_data() {
        let proof_data =
            ProofData::<Mainnet>::try_from(vec![0xaa; <Mainnet as Preset>::MaxProofSize::USIZE])
                .expect("length is under maximum");
        let proof = SignedExecutionProof {
            message: ExecutionProof {
                proof_data,
                ..populated_signed_execution_proof().message
            },
            validator_index: 42,
            signature: SignatureBytes::default(),
        };

        assert_ssz_round_trip(proof);
    }

    #[test]
    fn signed_execution_proof_serializes_validator_index_as_string_in_json()
    -> serde_json::Result<()> {
        let json = serde_json::to_value(populated_signed_execution_proof())?;

        assert_eq!(json["validator_index"], json!("42"));

        Ok(())
    }

    #[test]
    fn signed_execution_proof_deserializes_validator_index_from_number_in_json()
    -> serde_json::Result<()> {
        let mut json = serde_json::to_value(populated_signed_execution_proof())?;
        json["validator_index"] = json!(42);

        assert_eq!(
            serde_json::from_value::<SignedExecutionProof<Mainnet>>(json)?,
            populated_signed_execution_proof(),
        );

        Ok(())
    }

    #[test]
    fn proof_containers_reject_unknown_fields() {
        let message = json!({
            "proof_data": "0x00",
            "proof_type": "7",
            "public_input": {
                "new_payload_request_root": format!("0x{}", "bb".repeat(32)),
            },
        });

        serde_json::from_value::<ExecutionProof<Mainnet>>(json_with_unknown_field(&message))
            .expect_err("deserialization should fail due to unknown field");

        let signed = json!({
            "message": message,
            "validator_index": "42",
            "signature": format!("0x{}", "00".repeat(96)),
        });

        serde_json::from_value::<SignedExecutionProof<Mainnet>>(json_with_unknown_field(&signed))
            .expect_err("deserialization should fail due to unknown field");
    }

    #[test]
    fn default_proof_hash_tree_roots_match_independent_derivation() {
        assert_eq!(
            ExecutionProof::<Mainnet>::default().hash_tree_root(),
            H256(hex!(
                "f8f5b2c69e9e9608d42685351a7655c35d49cf932b4525bcdfcc411b43f5440c"
            )),
        );
        assert_eq!(
            SignedExecutionProof::<Mainnet>::default().hash_tree_root(),
            H256(hex!(
                "6406b31194daffb59e2d81d83ddd5431ba810e05427a15bdae4a1076dea77f11"
            )),
        );
    }

    #[test]
    fn populated_proof_hash_tree_roots_match_independent_derivation() {
        assert_eq!(
            populated_signed_execution_proof().message.hash_tree_root(),
            H256(hex!(
                "22ec1169902769ac159e35d1325664a63c6cfb57d7e376af28318b5f74f3c998"
            )),
        );
        assert_eq!(
            populated_signed_execution_proof().hash_tree_root(),
            H256(hex!(
                "f6fd31890bd783c2d0e1c4377abf8dca064aff93d9c8a280702d644de14464e2"
            )),
        );
    }

    fn assert_ssz_round_trip<P: Preset>(proof: SignedExecutionProof<P>) {
        let bytes = proof.to_ssz().expect("SSZ encoding should succeed");
        let decoded = SignedExecutionProof::<P>::from_ssz_default(bytes)
            .expect("SSZ decoding should succeed");

        assert_eq!(decoded, proof);
    }

    fn json_with_unknown_field(value: &serde_json::Value) -> serde_json::Value {
        let mut value = value.clone();
        value["unknown"] = json!(true);
        value
    }

    fn populated_signed_execution_proof() -> SignedExecutionProof<Mainnet> {
        SignedExecutionProof {
            message: ExecutionProof {
                proof_data: ProofData::<Mainnet>::try_from(vec![0xaa; 64])
                    .expect("length is under maximum"),
                proof_type: 7,
                public_input: PublicInput {
                    new_payload_request_root: H256([0x11; 32]),
                },
            },
            validator_index: 42,
            signature: SignatureBytes::default(),
        }
    }
}
