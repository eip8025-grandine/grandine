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
