//! Constants from [EIP-8025].
//!
//! Where consensus-specs and the EIP text disagree, these follow
//! consensus-specs. The EIP sets `MAX_PROOF_SIZE` to 400 KiB;
//! consensus-specs sets it to 4 MiB and marks it "not definitive".
//!
//! `DOMAIN_EXECUTION_PROOF` is deliberately absent because signing is
//! not implemented here. consensus-specs uses `0x0F000000`; the EIP
//! uses `0x0D000000`, which is also assigned to Gloas
//! `DOMAIN_PROPOSER_PREFERENCES`.
//!
//! [EIP-8025]: https://github.com/frisitano/consensus-specs/blob/7d6bd46a015a7dd316c5df855bd89e57c4aa6700/specs/_features/eip8025/beacon-chain.md

use typenum::Unsigned as _;

use crate::eip8025::primitives::MaxProofSize;

/// The maximum length of
/// [`ProofData`](crate::eip8025::containers::ProofData) in bytes, 4
/// MiB.
///
/// The spec type is unbounded, so this bound is not part of
/// merkleization. `ProofData` enforces it explicitly on construction
/// and on decoding, and carries it as
/// [`MaxProofSize`](crate::eip8025::primitives::MaxProofSize) so the
/// same limit also holds at the type level.
pub const MAX_PROOF_SIZE: usize = MaxProofSize::USIZE;

/// The schema identifier of the stateless guest input, `0x1501`.
///
/// It encodes the Amsterdam protocol fork (`0x15`) and schema
/// revision (`0x01`). The EIP text instead uses `0x0001` and prefixes
/// it to the serialized guest input; consensus-specs makes it the
/// value of
/// [`PublicInput::schema_id`](crate::eip8025::containers::PublicInput::schema_id),
/// which is what this follows.
pub const STATELESS_INPUT_SCHEMA_ID: u16 = 0x1501;

/// The maximum size of an encoded
/// [`SignedExecutionProofEnvelope`](crate::eip8025::containers::SignedExecutionProofEnvelope).
///
/// Incoming messages must be bounded by this value before decoding,
/// since decoding a progressive list allocates in proportion to its
/// input. Nothing in this crate enforces that bound.
///
/// This is the fixed part of `SignedExecutionProofEnvelope` (an
/// offset, a `ValidatorIndex` and a `BLSSignature`), plus the fixed
/// part of `ExecutionProofEnvelope` (an offset, a `ProofType` and a
/// `Root`), plus a maximum-length `ProofData`.
pub const MAX_SIGNED_EXECUTION_PROOF_ENVELOPE_SIZE: usize = 108 + 37 + MAX_PROOF_SIZE;
