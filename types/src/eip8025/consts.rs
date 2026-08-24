//! Constants from [EIP-8025].
//!
//! Where consensus-specs and the EIP text disagree, these follow consensus-specs.
//! `MAX_PROOF_SIZE` is 400 KiB in the EIP and is marked "not definitive" in consensus-specs.
//!
//! `DOMAIN_EXECUTION_PROOF` is deliberately absent. Signing is out of scope for this milestone,
//! and the two sources disagree about its value: consensus-specs uses `0x0F000000`, the EIP uses
//! `0x0D000000`, which collides with the Gloas `DOMAIN_PROPOSER_PREFERENCES` assignment at the
//! pinned revision. That has to be resolved upstream.
//!
//! [EIP-8025]: https://github.com/ethereum/consensus-specs/blob/a08d8a6e2b45f0b8c0d379abc15583427c643689/specs/_features/eip8025/beacon-chain.md

use typenum::Unsigned as _;

use crate::eip8025::primitives::MaxProofSize;

/// The maximum length of [`ProofData`](crate::eip8025::containers::ProofData) in bytes, 4 MiB.
///
/// The spec type is unbounded, so this bound is not part of merkleization. `ProofData` enforces
/// it explicitly on construction and on decoding, and carries it as
/// [`MaxProofSize`](crate::eip8025::primitives::MaxProofSize) so the same limit also holds at the
/// type level.
pub const MAX_PROOF_SIZE: usize = MaxProofSize::USIZE;

/// The maximum size of an encoded
/// [`SignedExecutionProof`](crate::eip8025::containers::SignedExecutionProof).
///
/// Gossip must bound incoming messages by this *before* decoding them, since decoding a
/// progressive list allocates in proportion to its input. That is a requirement on the later
/// gossip work; nothing in this crate enforces it.
///
/// This is the fixed part of `SignedExecutionProof` (an offset, a `ValidatorIndex` and a
/// `BLSSignature`), plus the fixed part of `ExecutionProof` (an offset, a `ProofType` and a
/// `PublicInput`), plus a maximum-length `ProofData`.
pub const MAX_SIGNED_EXECUTION_PROOF_SIZE: usize = 108 + 37 + MAX_PROOF_SIZE;
