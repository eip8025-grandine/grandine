use types::eip8025::containers::ExecutionProof;

use crate::engine::ProofEngine;

/// A [`ProofEngine`] fake for tests.
///
/// Mirrors `execution_engine::MockExecutionEngine`:
/// `execution_proof_valid` drives the happy + reject paths of
/// [`verify_execution_proof`](ProofEngine::verify_execution_proof) with no
/// real verifier.
#[derive(Clone, Debug, Default)]
pub struct MockProofEngine {
    execution_proof_valid: bool,
}

impl MockProofEngine {
    #[must_use]
    pub const fn new(execution_proof_valid: bool) -> Self {
        Self {
            execution_proof_valid,
        }
    }
}

impl ProofEngine for MockProofEngine {
    fn is_null(&self) -> bool {
        false
    }

    fn verify_execution_proof(&self, _execution_proof: ExecutionProof) -> bool {
        self.execution_proof_valid
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::test_proof;

    use super::*;

    #[test]
    fn mock_engine_is_not_null() {
        assert!(!MockProofEngine::new(true).is_null());
    }

    #[test]
    fn verify_follows_the_configured_flag() {
        assert!(MockProofEngine::new(true).verify_execution_proof(test_proof()));
        assert!(!MockProofEngine::new(false).verify_execution_proof(test_proof()));
    }
}
