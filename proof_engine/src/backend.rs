use crate::zkvm_engine::Rejection;

/// How the public values a proof commits to bind a `PublicInput`.
///
/// Backends differ here: zkVMs with fixed-size public values zero-pad
/// them, so they will need a padding rule of their own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Binding {
    /// The committed public values are exactly the SSZ serialization of
    /// the `PublicInput`, with no padding.
    Exact,
}

impl Binding {
    #[must_use]
    pub fn matches(self, public_values: &[u8], serialized_public_input: &[u8]) -> bool {
        match self {
            Self::Exact => public_values == serialized_public_input,
        }
    }
}

/// Verifies the proofs of one proof type.
///
/// A backend never sees the `PublicInput`. It only recovers the public
/// values a proof commits to, and the engine compares them under the
/// backend's [`Binding`].
pub trait Backend: Send + Sync {
    /// Decodes `proof_data`, verifies it if the backend is real, and
    /// returns the public values it commits to.
    ///
    /// Fails only with [`Rejection::Decode`] or [`Rejection::Verify`].
    fn public_values(&self, proof_data: &[u8]) -> Result<Vec<u8>, Rejection>;

    fn binding(&self) -> Binding;
}
