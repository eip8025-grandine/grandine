use types::{
    eip8025::containers::{
        ExecutionProof, ExecutionProofEnvelope, PublicInput, SignedExecutionProofEnvelope,
    },
    phase0::primitives::{H256, ValidatorIndex},
};

/// Content identity of the trusted context used to reconstruct an execution proof.
///
/// The beacon root scopes the accepted context; the complete public input captures
/// the reconstructed statement. This identity is content-based and does not depend
/// on snapshot or allocation identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionProofContextIdentity {
    beacon_block_root: H256,
    public_input: PublicInput,
}

impl ExecutionProofContextIdentity {
    /// Constructs an identity from the target root and reconstructed public input.
    ///
    /// The preparation path in this module must supply values derived from the
    /// target's trusted context.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Used by the future execution-proof preparation path"
        )
    )]
    #[must_use]
    const fn new(beacon_block_root: H256, public_input: PublicInput) -> Self {
        Self {
            beacon_block_root,
            public_input,
        }
    }

    #[must_use]
    pub const fn beacon_block_root(&self) -> H256 {
        self.beacon_block_root
    }

    #[must_use]
    pub const fn public_input(&self) -> &PublicInput {
        &self.public_input
    }
}

/// Authenticated envelope plus its locally reconstructed, immutable engine input.
///
/// Preparation does not imply engine verification, Seen admission, verified-proof
/// storage, or a gossip ACCEPT. Fields are private so callers cannot forge the
/// authentication/proof/context association; construction is private to this
/// module so only its validating preparation path can produce a prepared result.
pub struct PreparedExecutionProof {
    signed_envelope: SignedExecutionProofEnvelope,
    execution_proof: ExecutionProof,
    context_identity: ExecutionProofContextIdentity,
}

impl PreparedExecutionProof {
    // Keep construction private to the preparation implementation. This checks consistency
    // only; its preparation path must authenticate and establish trusted context first.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Used by the future execution-proof preparation path"
        )
    )]
    fn from_validated_context(
        signed_envelope: SignedExecutionProofEnvelope,
        execution_proof: ExecutionProof,
        context_identity: ExecutionProofContextIdentity,
    ) -> Option<Self> {
        let envelope = &signed_envelope.message;
        (envelope.beacon_block_root == context_identity.beacon_block_root
            && envelope.proof_type == execution_proof.proof_type
            && envelope.proof_data == execution_proof.proof_data
            && context_identity.public_input == execution_proof.public_input)
            .then_some(Self {
                signed_envelope,
                execution_proof,
                context_identity,
            })
    }

    /// Returns the authenticated message without exposing its `Hc` cached-root cell.
    #[must_use]
    pub fn signed_message(&self) -> &ExecutionProofEnvelope {
        self.signed_envelope.message.as_ref()
    }

    #[must_use]
    pub const fn validator_index(&self) -> ValidatorIndex {
        self.signed_envelope.validator_index
    }

    #[must_use]
    pub const fn execution_proof(&self) -> &ExecutionProof {
        &self.execution_proof
    }

    #[must_use]
    pub const fn context_identity(&self) -> &ExecutionProofContextIdentity {
        &self.context_identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::Hc;
    use types::eip8025::{consts::STATELESS_INPUT_SCHEMA_ID, containers::ProofData};

    fn prepared_execution_proof_fixture() -> (
        SignedExecutionProofEnvelope,
        ExecutionProof,
        ExecutionProofContextIdentity,
    ) {
        // These tests exercise carrier consistency, not authentication or binding.
        // A real prepared result requires both checks in the preparation path.
        let signed_envelope = SignedExecutionProofEnvelope {
            message: Hc::from(ExecutionProofEnvelope {
                proof_data: ProofData::try_from(vec![0x42])
                    .expect("one byte is within the proof-data bound"),
                proof_type: 1,
                beacon_block_root: H256::zero(),
            }),
            validator_index: 7,
            ..SignedExecutionProofEnvelope::default()
        };
        let context_identity = ExecutionProofContextIdentity::new(
            signed_envelope.message.beacon_block_root,
            PublicInput {
                new_payload_request_root: H256::repeat_byte(0x22),
                successful_validation: true,
                chain_id: 1,
                schema_id: STATELESS_INPUT_SCHEMA_ID,
            },
        );
        let execution_proof = ExecutionProof {
            proof_data: signed_envelope.message.proof_data.clone(),
            proof_type: signed_envelope.message.proof_type,
            public_input: context_identity.public_input,
        };

        (signed_envelope, execution_proof, context_identity)
    }

    #[test]
    fn prepared_execution_proof_constructs_and_exposes_immutable_bound_parts() {
        let (signed_envelope, execution_proof, context_identity) =
            prepared_execution_proof_fixture();
        let expected_message = signed_envelope.message.as_ref().clone();
        let prepared = PreparedExecutionProof::from_validated_context(
            signed_envelope.clone(),
            execution_proof.clone(),
            context_identity,
        )
        .expect("consistent carrier parts should refer to the same statement");

        let signed_message: &ExecutionProofEnvelope = prepared.signed_message();
        assert_eq!(signed_message, &expected_message);
        assert_eq!(prepared.validator_index(), signed_envelope.validator_index);
        assert_eq!(prepared.execution_proof(), &execution_proof);
        assert_eq!(
            prepared.context_identity().beacon_block_root(),
            context_identity.beacon_block_root()
        );
        assert_eq!(
            prepared.context_identity().public_input(),
            &prepared.execution_proof().public_input
        );
    }

    #[test]
    fn prepared_execution_proof_rejects_beacon_block_root_mismatch() {
        let (signed_envelope, execution_proof, mut context_identity) =
            prepared_execution_proof_fixture();
        context_identity.beacon_block_root = H256::repeat_byte(0x11);

        assert!(
            PreparedExecutionProof::from_validated_context(
                signed_envelope,
                execution_proof,
                context_identity,
            )
            .is_none()
        );
    }

    #[test]
    fn prepared_execution_proof_rejects_proof_type_mismatch() {
        let (signed_envelope, mut execution_proof, context_identity) =
            prepared_execution_proof_fixture();
        execution_proof.proof_type = 2;

        assert!(
            PreparedExecutionProof::from_validated_context(
                signed_envelope,
                execution_proof,
                context_identity,
            )
            .is_none()
        );
    }

    #[test]
    fn prepared_execution_proof_rejects_proof_data_mismatch() {
        let (signed_envelope, mut execution_proof, context_identity) =
            prepared_execution_proof_fixture();
        execution_proof.proof_data =
            ProofData::try_from(vec![0x43]).expect("one byte is within the proof-data bound");

        assert!(
            PreparedExecutionProof::from_validated_context(
                signed_envelope,
                execution_proof,
                context_identity,
            )
            .is_none()
        );
    }

    #[test]
    fn prepared_execution_proof_rejects_each_public_input_field_mismatch() {
        let (signed_envelope, execution_proof, context_identity) =
            prepared_execution_proof_fixture();

        let mut mismatched_proof = execution_proof.clone();
        mismatched_proof.public_input.new_payload_request_root = H256::repeat_byte(0x23);
        assert!(
            PreparedExecutionProof::from_validated_context(
                signed_envelope.clone(),
                mismatched_proof,
                context_identity,
            )
            .is_none(),
            "new_payload_request_root mismatch must be rejected"
        );

        let mut mismatched_proof = execution_proof.clone();
        mismatched_proof.public_input.successful_validation = false;
        assert!(
            PreparedExecutionProof::from_validated_context(
                signed_envelope.clone(),
                mismatched_proof,
                context_identity,
            )
            .is_none(),
            "successful_validation mismatch must be rejected"
        );

        let mut mismatched_proof = execution_proof.clone();
        mismatched_proof.public_input.chain_id = 2;
        assert!(
            PreparedExecutionProof::from_validated_context(
                signed_envelope.clone(),
                mismatched_proof,
                context_identity,
            )
            .is_none(),
            "chain_id mismatch must be rejected"
        );

        let mut mismatched_proof = execution_proof;
        mismatched_proof.public_input.schema_id = STATELESS_INPUT_SCHEMA_ID + 1;
        assert!(
            PreparedExecutionProof::from_validated_context(
                signed_envelope,
                mismatched_proof,
                context_identity,
            )
            .is_none(),
            "schema_id mismatch must be rejected"
        );
    }

    #[test]
    fn prepared_execution_proof_context_identity_is_content_based() {
        let (_, _, context_identity) = prepared_execution_proof_fixture();
        let equivalent_identity = ExecutionProofContextIdentity {
            beacon_block_root: context_identity.beacon_block_root,
            public_input: PublicInput {
                new_payload_request_root: H256::repeat_byte(0x22),
                successful_validation: true,
                chain_id: 1,
                schema_id: STATELESS_INPUT_SCHEMA_ID,
            },
        };
        assert_eq!(context_identity, equivalent_identity);

        let mut changed_statement = equivalent_identity;
        changed_statement.public_input.new_payload_request_root = H256::repeat_byte(0x23);
        assert_ne!(context_identity, changed_statement);

        let mut changed_target = equivalent_identity;
        changed_target.beacon_block_root = H256::repeat_byte(0x11);
        assert_ne!(context_identity, changed_target);
    }
}
