/// Identifies the proof system, guest program, and version that
/// produced an execution proof.
///
/// Like the spec's `Uint8`, every value decodes. Whether a type is
/// supported is a validation check, not a type invariant.
pub type ProofType = u8;

/// The type-level bound on
/// [`ProofData`](crate::eip8025::containers::ProofData).
///
/// `MAX_PROOF_SIZE` is derived from this so the constant and
/// type-level bound stay in sync. The bound is the `ByteList` limit,
/// so it affects SSZ merkleization.
pub type MaxProofSize = typenum::U4194304;
