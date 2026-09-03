use ssz::ReadError;
use thiserror::Error;

use crate::nonstandard::Phase;

#[derive(Debug, Error)]
pub enum PayloadBindingError {
    #[error(
        "execution payload of phase {phase} cannot be bound; \
         EIP-8025 binds the Gloas shape of SSZNewPayloadRequest"
    )]
    PayloadPhaseNotSupported { phase: Phase },
    #[error(
        "execution payload params without Gloas execution requests cannot be bound; \
         EIP-8025 binds the Gloas shape of SSZNewPayloadRequest"
    )]
    ExecutionRequestsNotGloas,
    #[error("too many versioned hashes to bind")]
    VersionedHashesTooLong(#[source] ReadError),
}
