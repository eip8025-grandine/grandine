use ere_verifier_core::{codec::Decode as _, zkVMVerifier};

use crate::{
    backend::{Backend, Binding},
    zkvm_engine::Rejection,
};

/// Real verification of ere-encoded proofs with one ere verifier.
///
/// The verifier is bound to one guest's verifying key. A new zkVM needs
/// a Cargo feature, a `BackendSpec` variant and a binding rule.
pub struct EreBackend<V> {
    verifier: V,
    binding: Binding,
}

impl<V: zkVMVerifier> EreBackend<V> {
    #[must_use]
    pub const fn new(verifier: V, binding: Binding) -> Self {
        Self { verifier, binding }
    }
}

impl<V: zkVMVerifier> Backend for EreBackend<V> {
    fn public_values(&self, proof_data: &[u8]) -> Result<Vec<u8>, Rejection> {
        let proof = V::Proof::decode_from_slice(proof_data)
            .map_err(|error| Rejection::Decode(error.into()))?;

        let public_values = self
            .verifier
            .verify(&proof)
            .map_err(|error| Rejection::Verify(error.into()))?;

        Ok(public_values.into())
    }

    fn binding(&self) -> Binding {
        self.binding
    }
}
