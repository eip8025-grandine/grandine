use types::{
    eip8025::{
        containers::{ExecutionProof, ProofAttributes, SszNewPayloadRequest},
        primitives::ProofType,
    },
    phase0::primitives::H256,
    preset::Preset,
};

use crate::engine::{ProofEngine, ProofEngineError};

/// A [`ProofEngine`] that does nothing.
///
/// Used by nodes that opt out of execution-proof verification: the gossip
/// task short-circuits on [`IS_NULL`](ProofEngine::IS_NULL) to `Ignore`
/// before any pipeline work (and such nodes subscribe to nothing), so the
/// fail-closed [`verify_execution_proof`](ProofEngine::verify_execution_proof)
/// below is unreachable in practice.
#[derive(Clone, Copy, Default, Debug)]
pub struct NullProofEngine;

impl<P: Preset> ProofEngine<P> for NullProofEngine {
    const IS_NULL: bool = true;

    fn verify_execution_proof(&self, _execution_proof: ExecutionProof) -> bool {
        false
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
        Err(ProofEngineError::Unsupported)
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
    fn null_engine_reports_itself_as_null() {
        assert!(<NullProofEngine as ProofEngine<Minimal>>::IS_NULL);
    }

    #[test]
    fn verify_is_fail_closed() {
        assert!(
            !<NullProofEngine as ProofEngine<Minimal>>::verify_execution_proof(
                &NullProofEngine,
                test_proof(),
            )
        );
    }

    #[test]
    fn prover_methods_reject() {
        let error = <NullProofEngine as ProofEngine<Minimal>>::request_proofs(
            &NullProofEngine,
            SszNewPayloadRequest::default(),
            5,
            0x1501,
            ProofAttributes::default(),
        )
        .expect_err("null engine should reject proof generation");

        assert!(matches!(error, ProofEngineError::Unsupported));

        let error = <NullProofEngine as ProofEngine<Minimal>>::get_proof(
            &NullProofEngine,
            H256::default(),
            1,
        )
        .expect_err("null engine should reject proof retrieval");

        assert!(matches!(error, ProofEngineError::Unsupported));
    }
}
