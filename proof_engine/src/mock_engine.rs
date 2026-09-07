use types::{
    eip8025::{
        containers::{ExecutionProof, ProofAttributes, SszNewPayloadRequest},
        primitives::ProofType,
    },
    phase0::primitives::H256,
    preset::Preset,
};

use crate::engine::{ProofEngine, ProofEngineError};

/// A [`ProofEngine`] fake for tests.
///
/// Mirrors [`MockExecutionEngine`](execution_engine::MockExecutionEngine):
/// `execution_proof_valid` drives the happy + reject paths of
/// [`verify_execution_proof`](ProofEngine::verify_execution_proof) with no
/// real verifier. The prover-role methods stay reject-stubs, except that a
/// canned proof (set with [`with_canned_proof`](Self::with_canned_proof))
/// makes [`get_proof`](ProofEngine::get_proof) succeed, so tests can cover
/// both the canned-proof and the rejection paths.
#[derive(Clone, Debug, Default)]
pub struct MockProofEngine {
    execution_proof_valid: bool,
    canned_proof: Option<ExecutionProof>,
}

impl MockProofEngine {
    #[must_use]
    pub const fn new(execution_proof_valid: bool) -> Self {
        Self {
            execution_proof_valid,
            canned_proof: None,
        }
    }

    #[must_use]
    pub fn with_canned_proof(mut self, proof: ExecutionProof) -> Self {
        self.canned_proof = Some(proof);
        self
    }
}

impl<P: Preset> ProofEngine<P> for MockProofEngine {
    const IS_NULL: bool = false;

    fn verify_execution_proof(&self, _execution_proof: ExecutionProof) -> bool {
        self.execution_proof_valid
    }

    fn request_proofs(
        &self,
        _new_payload_request: SszNewPayloadRequest<P>,
        _chain_id: u64,
        _schema_id: u16,
        _proof_attributes: ProofAttributes,
    ) -> Result<H256, ProofEngineError> {
        Err(ProofEngineError::Unsupported)
    }

    fn get_proof(
        &self,
        _new_payload_request_root: H256,
        _proof_type: ProofType,
    ) -> Result<ExecutionProof, ProofEngineError> {
        self.canned_proof
            .clone()
            .ok_or(ProofEngineError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use types::{
        eip8025::containers::{ProofData, PublicInput},
        preset::Minimal,
    };

    use super::*;

    fn test_proof() -> ExecutionProof {
        ExecutionProof {
            proof_data: ProofData::try_from(vec![1, 2, 3])
                .expect("small proof data should be within bounds"),
            proof_type: 1,
            public_input: PublicInput {
                new_payload_request_root: H256::default(),
                successful_validation: true,
                chain_id: 5,
                schema_id: 0x1501,
            },
        }
    }

    #[test]
    fn mock_engine_is_not_null() {
        assert!(!<MockProofEngine as ProofEngine<Minimal>>::IS_NULL);
    }

    #[test]
    fn verify_follows_the_configured_flag() {
        assert!(
            <MockProofEngine as ProofEngine<Minimal>>::verify_execution_proof(
                &MockProofEngine::new(true),
                test_proof(),
            )
        );
        assert!(
            !<MockProofEngine as ProofEngine<Minimal>>::verify_execution_proof(
                &MockProofEngine::new(false),
                test_proof(),
            )
        );
    }

    #[test]
    fn request_proofs_rejects() {
        let error = <MockProofEngine as ProofEngine<Minimal>>::request_proofs(
            &MockProofEngine::new(true),
            SszNewPayloadRequest::default(),
            5,
            0x1501,
            ProofAttributes {
                proof_types: vec![1],
            },
        )
        .expect_err("mock engine should reject proof generation");

        assert!(matches!(error, ProofEngineError::Unsupported));
    }

    #[test]
    fn get_proof_returns_the_canned_proof_or_rejects() {
        let proof = test_proof();

        let returned = <MockProofEngine as ProofEngine<Minimal>>::get_proof(
            &MockProofEngine::new(true).with_canned_proof(proof.clone()),
            H256::default(),
            1,
        )
        .expect("mock engine should return the canned proof");

        assert_eq!(returned, proof);

        let error = <MockProofEngine as ProofEngine<Minimal>>::get_proof(
            &MockProofEngine::new(true),
            H256::default(),
            1,
        )
        .expect_err("mock engine without a canned proof should reject");

        assert!(matches!(error, ProofEngineError::Unsupported));
    }
}
