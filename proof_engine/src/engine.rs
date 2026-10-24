use types::eip8025::containers::ExecutionProof;

/// The outcome of [`ProofEngine::verify_execution_proof`].
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProofVerdict {
    /// The proof verifies and binds the given `PublicInput`.
    Valid,
    /// Given the trusted inputs, `proof_data` fails verification or binding.
    Invalid,
    /// This node reached no verdict about the proof.
    ///
    /// The cause is local, such as a proof type with no configured
    /// backend or a verifier panic. It must never be treated as
    /// [`Valid`](Self::Valid), and it says nothing against the proof.
    Undetermined,
}

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
    ///
    /// The spec's `True` is [`ProofVerdict::Valid`] and its `False` is
    /// [`ProofVerdict::Invalid`]. [`ProofVerdict::Undetermined`] is a
    /// Grandine extension for local failures, which the spec cannot report.
    fn verify_execution_proof(&self, execution_proof: ExecutionProof) -> ProofVerdict;
}
