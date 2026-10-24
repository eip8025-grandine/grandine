use types::eip8025::containers::ExecutionProof;

use crate::engine::{ProofEngine, ProofVerdict};

/// A [`ProofEngine`] fake for tests.
///
/// Mirrors `execution_engine::MockExecutionEngine`: `verdict` drives every
/// path of [`verify_execution_proof`](ProofEngine::verify_execution_proof)
/// with no real verifier.
///
/// This is a stub for callers whose tests do not depend on proof
/// contents. It is not zkboost mock verification, which
/// [`ZkvmProofEngine`](crate::ZkvmProofEngine) performs for proof types
/// configured as [`BackendSpec::ZkboostMock`](crate::BackendSpec::ZkboostMock).
#[derive(Clone, Debug)]
pub struct MockProofEngine {
    verdict: ProofVerdict,
}

impl MockProofEngine {
    #[must_use]
    pub const fn new(verdict: ProofVerdict) -> Self {
        Self { verdict }
    }
}

impl ProofEngine for MockProofEngine {
    fn is_null(&self) -> bool {
        false
    }

    fn verify_execution_proof(&self, _execution_proof: ExecutionProof) -> ProofVerdict {
        self.verdict
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{VERDICTS, test_proof};

    use super::*;

    #[test]
    fn mock_engine_is_not_null() {
        for verdict in VERDICTS {
            assert!(!MockProofEngine::new(verdict).is_null());
        }
    }

    #[test]
    fn verify_returns_the_configured_verdict() {
        for verdict in VERDICTS {
            assert_eq!(
                MockProofEngine::new(verdict).verify_execution_proof(test_proof()),
                verdict,
            );
        }
    }
}
