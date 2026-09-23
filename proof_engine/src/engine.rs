use types::{
    eip8025::{
        containers::{ExecutionProof, ProofAttributes, SszNewPayloadRequest},
        primitives::ProofType,
    },
    phase0::primitives::H256,
    preset::Preset,
};

/// Verification half of the EIP-8025 `ProofEngine` protocol.
///
/// Non-generic and object-safe: `verify_execution_proof` receives an already
/// reconstructed `ExecutionProof`, so it needs no `P: Preset`.
pub trait ProofVerifier: Send + Sync + 'static {
    /// Whether this verifier opts out of execution-proof verification.
    fn is_null(&self) -> bool;

    /// [`verify_execution_proof`](https://github.com/ethereum/consensus-specs/blob/7fa044833194cbea2908f76c0de102d168d88fb0/specs/_features/eip8025/proof-engine.md#new-verify_execution_proof)
    fn verify_execution_proof(&self, execution_proof: ExecutionProof) -> bool;
}

/// Generation half of the EIP-8025 `ProofEngine` protocol.
///
/// Generic over `P` because `request_proofs` takes the full
/// `SszNewPayloadRequest<P>`. Unwired for now: Grandine is verifier-only.
pub trait ProofProver<P: Preset>: Send + Sync + 'static {
    /// [`request_proofs`](https://github.com/ethereum/consensus-specs/blob/7fa044833194cbea2908f76c0de102d168d88fb0/specs/_features/eip8025/proof-engine.md#new-request_proofs)
    fn request_proofs(
        &self,
        new_payload_request: SszNewPayloadRequest<P>,
        chain_id: u64,
        schema_id: u16,
        proof_attributes: ProofAttributes,
    ) -> Result<H256, ProofEngineError>;

    /// [`get_proof`](https://github.com/ethereum/consensus-specs/blob/7fa044833194cbea2908f76c0de102d168d88fb0/specs/_features/eip8025/proof-engine.md#new-get_proof)
    fn get_proof(
        &self,
        new_payload_request_root: H256,
        proof_type: ProofType,
    ) -> Result<ExecutionProof, ProofEngineError>;
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
