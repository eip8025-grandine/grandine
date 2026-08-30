//! Constants from the [EIP-8025 consensus spec].
//!
//! Where the EIP and consensus-specs differ, these follow
//! consensus-specs. In particular, `MAX_PROOF_SIZE` is 4 MiB rather
//! than 400 KiB.
//!
//! [EIP-8025 consensus spec]: https://github.com/ethereum/consensus-specs/blob/7fa044833194cbea2908f76c0de102d168d88fb0/specs/_features/eip8025/beacon-chain.md

use hex_literal::hex;
use typenum::Unsigned as _;

use crate::eip8025::primitives::MaxProofSize;
use crate::phase0::primitives::{DomainType, H32};

/// The maximum length of
/// [`ProofData`](crate::eip8025::containers::ProofData): 4 MiB.
///
/// The spec type is unbounded, so this limit is not part of SSZ
/// merkleization. `ProofData` enforces it during construction and
/// decoding.
pub const MAX_PROOF_SIZE: usize = MaxProofSize::USIZE;

/// The schema identifier of the stateless guest input, `0x1501`.
///
/// Encodes the Amsterdam protocol fork (`0x15`) and schema revision
/// (`0x01`), and is used as
/// [`PublicInput::schema_id`](crate::eip8025::containers::PublicInput::schema_id).
pub const STATELESS_INPUT_SCHEMA_ID: u16 = 0x1501;

/// The maximum encoded size of a
/// [`SignedExecutionProofEnvelope`](crate::eip8025::containers::SignedExecutionProofEnvelope).
///
/// Incoming messages must be bounded by this value before decoding,
/// because decoding a progressive list allocates in proportion to its
/// input. This crate does not enforce that bound.
///
/// This is the fixed-size portion of the outer
/// `SignedExecutionProofEnvelope`, plus the fixed-size portion of its
/// `ExecutionProofEnvelope`, plus a maximum-length `ProofData`.
///
/// Each fixed-size portion includes the SSZ offset for its
/// variable-size field.
pub const MAX_SIGNED_EXECUTION_PROOF_ENVELOPE_SIZE: usize = 108 + 37 + MAX_PROOF_SIZE;

/// The domain used for signing execution proofs.
pub const DOMAIN_EXECUTION_PROOF: DomainType = H32(hex!("0F000000"));
