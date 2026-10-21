use ssz::{ByteList, Ssz, SszReadDefault as _};
use types::eip8025::primitives::MaxProofSize;

use crate::{
    backend::{Backend, Binding},
    zkvm_engine::Rejection,
};

/// The `proof_data` of a zkboost mock proof.
///
/// zkboost and ethereum-package send this in mock mode. It has no spec
/// status. `proof` holds arbitrary bytes in place of a real proof and is
/// never read.
///
/// Both fields are variable-size, so standard SSZ offsets give `proof`
/// every byte after `public_values`. A mock proof therefore cannot have
/// trailing bytes: appended bytes lengthen `proof`.
#[derive(Clone, PartialEq, Eq, Default, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct MockProof {
    pub public_values: ByteList<MaxProofSize>,
    pub proof: ByteList<MaxProofSize>,
}

/// Mock verification of zkboost [`MockProof`]s.
///
/// Performs no cryptography: it returns the public values a mock proof
/// claims. The engine refuses it on mainnet.
#[derive(Clone, Copy, Default, Debug)]
pub struct ZkboostMockBackend;

impl Backend for ZkboostMockBackend {
    fn public_values(&self, proof_data: &[u8]) -> Result<Vec<u8>, Rejection> {
        let mock_proof = MockProof::from_ssz_default(proof_data)
            .map_err(|error| Rejection::Decode(error.into()))?;

        Ok(mock_proof.public_values.as_bytes().to_vec())
    }

    // zkboost commits the unpadded 43-byte serialization.
    fn binding(&self) -> Binding {
        Binding::Exact
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use ssz::SszWrite as _;

    use super::*;

    // zkboost `b83a23f9` `crates/types/src/execution_proof.rs`,
    // `test_mock_proof_layout`: the offsets of both lists, then the
    // public values and the proof.
    const ZKBOOST_MOCK_PROOF: [u8; 13] = hex!("08000000 0b000000 aaaaaa bbbb");

    #[test]
    fn decodes_zkboost_vector() {
        let mock_proof = MockProof::from_ssz_default(ZKBOOST_MOCK_PROOF)
            .expect("zkboost's vector should decode");

        assert_eq!(mock_proof.public_values.as_bytes(), [0xaa; 3]);
        assert_eq!(mock_proof.proof.as_bytes(), [0xbb; 2]);
        assert_eq!(
            mock_proof
                .to_ssz()
                .expect("mock proof should be serializable"),
            ZKBOOST_MOCK_PROOF,
        );
        assert_eq!(
            ZkboostMockBackend
                .public_values(&ZKBOOST_MOCK_PROOF)
                .expect("zkboost's vector should decode"),
            [0xaa; 3],
        );
    }

    #[test]
    fn appended_bytes_lengthen_proof() {
        let mut bytes = ZKBOOST_MOCK_PROOF.to_vec();
        bytes.push(0xcc);

        let mock_proof = MockProof::from_ssz_default(&bytes).expect("appended bytes should decode");

        assert_eq!(mock_proof.public_values.as_bytes(), [0xaa; 3]);
        assert_eq!(mock_proof.proof.as_bytes(), [0xbb, 0xbb, 0xcc]);
    }
}
