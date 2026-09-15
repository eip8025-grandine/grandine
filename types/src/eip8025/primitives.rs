/// The identifier of the proof system that produced an execution proof.
pub type ProofType = u8;

/// The type-level bound on [`ProofData`](crate::eip8025::containers::ProofData).
///
/// `MAX_PROOF_SIZE` is derived from this so the constant and the bound cannot drift apart.
/// Merkleization ignores the bound, so changing it does not change any root.
pub type MaxProofSize = typenum::U4194304;
