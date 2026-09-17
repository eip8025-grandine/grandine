/// Identifies the proof system, guest program, and version that
/// produced an execution proof.
pub type ProofType = u8;

/// The type-level bound on
/// [`ProofData`](crate::eip8025::containers::ProofData).
///
/// `MAX_PROOF_SIZE` is derived from this so the constant and
/// type-level bound stay in sync. The bound does not affect SSZ
/// merkleization.
pub type MaxProofSize = typenum::U4194304;
