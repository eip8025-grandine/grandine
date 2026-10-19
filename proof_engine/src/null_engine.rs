use types::eip8025::containers::ExecutionProof;

use crate::engine::ProofEngine;

/// The opt-out [`ProofEngine`].
///
/// The task short-circuits on [`is_null`](ProofEngine::is_null) before any
/// pipeline work, so the fail-closed
/// [`verify_execution_proof`](ProofEngine::verify_execution_proof) is
/// unreachable in practice.
#[derive(Clone, Copy, Default, Debug)]
pub struct NullProofEngine;

impl ProofEngine for NullProofEngine {
    fn is_null(&self) -> bool {
        true
    }

    fn verify_execution_proof(&self, _execution_proof: ExecutionProof) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::test_proof;

    use super::*;

    #[test]
    fn null_engine_reports_itself_as_null() {
        assert!(NullProofEngine.is_null());
    }

    #[test]
    fn verify_is_fail_closed() {
        assert!(!NullProofEngine.verify_execution_proof(test_proof()));
    }
}
