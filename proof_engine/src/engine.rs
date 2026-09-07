use std::sync::{Arc, Mutex};

use types::{
    eip8025::{
        containers::{ExecutionProof, ProofAttributes, SszNewPayloadRequest},
        primitives::ProofType,
    },
    phase0::primitives::H256,
    preset::Preset,
};

/// The implementation-dependent proof engine protocol.
///
/// Mirrors the `ProofEngine` protocol in
/// [`proof-engine.md`](https://github.com/ethereum/consensus-specs/blob/7d6bd46a015a7dd316c5df855bd89e57c4aa6700/specs/_features/eip8025/proof-engine.md#proof-engine):
/// proof verification plus asynchronous proof generation. Generation and
/// retrieval are prover-role only; implementations without generation support
/// reject them. Grandine is verifier-only for now, so only
/// [`verify_execution_proof`](Self::verify_execution_proof) is ever wired.
pub trait ProofEngine<P: Preset> {
    const IS_NULL: bool;

    /// [`verify_execution_proof`](https://github.com/ethereum/consensus-specs/blob/7d6bd46a015a7dd316c5df855bd89e57c4aa6700/specs/_features/eip8025/proof-engine.md#new-verify_execution_proof)
    fn verify_execution_proof(&self, execution_proof: ExecutionProof) -> bool;

    /// [`request_proofs`](https://github.com/ethereum/consensus-specs/blob/7d6bd46a015a7dd316c5df855bd89e57c4aa6700/specs/_features/eip8025/proof-engine.md#new-request_proofs)
    fn request_proofs(
        &self,
        new_payload_request: SszNewPayloadRequest<P>,
        chain_id: u64,
        schema_id: u16,
        proof_attributes: ProofAttributes,
    ) -> Result<H256, ProofEngineError>;

    /// [`get_proof`](https://github.com/ethereum/consensus-specs/blob/7d6bd46a015a7dd316c5df855bd89e57c4aa6700/specs/_features/eip8025/proof-engine.md#new-get_proof)
    fn get_proof(
        &self,
        new_payload_request_root: H256,
        proof_type: ProofType,
    ) -> Result<ExecutionProof, ProofEngineError>;
}

impl<P: Preset, E: ProofEngine<P>> ProofEngine<P> for &E {
    const IS_NULL: bool = E::IS_NULL;

    fn verify_execution_proof(&self, execution_proof: ExecutionProof) -> bool {
        (*self).verify_execution_proof(execution_proof)
    }

    fn request_proofs(
        &self,
        new_payload_request: SszNewPayloadRequest<P>,
        chain_id: u64,
        schema_id: u16,
        proof_attributes: ProofAttributes,
    ) -> Result<H256, ProofEngineError> {
        (*self).request_proofs(new_payload_request, chain_id, schema_id, proof_attributes)
    }

    fn get_proof(
        &self,
        new_payload_request_root: H256,
        proof_type: ProofType,
    ) -> Result<ExecutionProof, ProofEngineError> {
        (*self).get_proof(new_payload_request_root, proof_type)
    }
}

impl<P: Preset, E: ProofEngine<P>> ProofEngine<P> for Arc<E> {
    const IS_NULL: bool = E::IS_NULL;

    fn verify_execution_proof(&self, execution_proof: ExecutionProof) -> bool {
        self.as_ref().verify_execution_proof(execution_proof)
    }

    fn request_proofs(
        &self,
        new_payload_request: SszNewPayloadRequest<P>,
        chain_id: u64,
        schema_id: u16,
        proof_attributes: ProofAttributes,
    ) -> Result<H256, ProofEngineError> {
        self.as_ref()
            .request_proofs(new_payload_request, chain_id, schema_id, proof_attributes)
    }

    fn get_proof(
        &self,
        new_payload_request_root: H256,
        proof_type: ProofType,
    ) -> Result<ExecutionProof, ProofEngineError> {
        self.as_ref()
            .get_proof(new_payload_request_root, proof_type)
    }
}

impl<P: Preset, E: ProofEngine<P>> ProofEngine<P> for Mutex<E> {
    const IS_NULL: bool = E::IS_NULL;

    fn verify_execution_proof(&self, execution_proof: ExecutionProof) -> bool {
        self.lock()
            .expect("proof engine mutex is poisoned")
            .verify_execution_proof(execution_proof)
    }

    fn request_proofs(
        &self,
        new_payload_request: SszNewPayloadRequest<P>,
        chain_id: u64,
        schema_id: u16,
        proof_attributes: ProofAttributes,
    ) -> Result<H256, ProofEngineError> {
        self.lock()
            .expect("proof engine mutex is poisoned")
            .request_proofs(new_payload_request, chain_id, schema_id, proof_attributes)
    }

    fn get_proof(
        &self,
        new_payload_request_root: H256,
        proof_type: ProofType,
    ) -> Result<ExecutionProof, ProofEngineError> {
        self.lock()
            .expect("proof engine mutex is poisoned")
            .get_proof(new_payload_request_root, proof_type)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProofEngineError {
    #[error("proof engine method not supported")]
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Proof types serialize as strings, following the
    // `string_or_native_sequence` house convention for numeric sequences.
    #[test]
    fn proof_attributes_json_round_trip() {
        let attributes = ProofAttributes {
            proof_types: vec![1, 2, 3],
        };

        let json = serde_json::to_string(&attributes).expect("attributes should be serializable");

        assert_eq!(json, r#"{"proof_types":["1","2","3"]}"#);

        let decoded: ProofAttributes =
            serde_json::from_str(&json).expect("attributes should be deserializable");

        assert_eq!(decoded, attributes);
    }

    #[test]
    fn proof_attributes_accepts_native_integers() {
        let decoded: ProofAttributes = serde_json::from_str(r#"{"proof_types":[1,2]}"#)
            .expect("native integers should be accepted");

        assert_eq!(decoded.proof_types, vec![1, 2]);
    }
}
