use ssz::ReadError;
use thiserror::Error;

use crate::nonstandard::Phase;

#[derive(Debug, Error)]
pub enum PayloadBindingError {
    #[error(
        "execution payload of phase {phase} cannot be bound; \
         EIP-8025 builds on the Electra shape of NewPayloadRequest"
    )]
    PayloadPhaseNotSupported { phase: Phase },
    #[error(
        "execution payload params without execution requests cannot be bound; \
         EIP-8025 builds on the Electra shape of NewPayloadRequest"
    )]
    ExecutionRequestsMissing,
    #[error("too many versioned hashes to bind")]
    VersionedHashesTooLong(#[source] ReadError),
}
