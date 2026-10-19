use types::eip8025::containers::ExecutionProof;

/// The EIP-8025 [`ProofEngine`](https://github.com/ethereum/consensus-specs/blob/d9663f85be248c4fd0ae95806da6070e17c2442b/specs/_features/eip8025/proof-engine.md#proof-engine)
/// protocol.
///
/// The spec protocol is validation-only, so
/// [`verify_execution_proof`](Self::verify_execution_proof) is all of it.
/// [`is_null`](Self::is_null) is a Grandine extension the spec does not have.
///
/// Non-generic and object-safe: `verify_execution_proof` receives an already
/// reconstructed `ExecutionProof`, so it needs no `P: Preset`.
pub trait ProofEngine: Send + Sync + 'static {
    /// Whether this engine opts out of execution-proof verification.
    fn is_null(&self) -> bool;

    /// [`verify_execution_proof`](https://github.com/ethereum/consensus-specs/blob/d9663f85be248c4fd0ae95806da6070e17c2442b/specs/_features/eip8025/proof-engine.md#new-verify_execution_proof)
    fn verify_execution_proof(&self, execution_proof: ExecutionProof) -> bool;
}
