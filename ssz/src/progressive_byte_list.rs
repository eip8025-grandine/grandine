use core::fmt::{Debug, Formatter, Result as FmtResult};

use derivative::Derivative;
use derive_more::From;
use ethereum_types::H256;
use serde::{Deserialize, Deserializer, Serialize};
use typenum::{U1, Unsigned};

use crate::{
    byte_list::ByteList,
    error::{ReadError, WriteError},
    merkle_tree::{self, ProgressiveMerkleTree},
    porcelain::{SszHash, SszRead, SszSize, SszWrite},
    size::Size,
};

// TODO(gloas): in spec, ProgressiveByteList is an unbounded container, and its
// limits are enforced in user-site. This would require careful refactoring, so
// for easier transition, limits are kept as-is for now.
//
// Serialization is identical to `ByteList`. Only merkleization differs:
// the packed byte chunks are hashed with a progressive Merkle tree (EIP-7916)
// instead of a fixed-depth binary tree.
//
// `N` bounds decoding and construction only. `hash_tree_root` does not depend
// on `N`, so a given byte string has the same root under every `N`. A limit
// that must not influence the root can be expressed as `N` for the decode
// bound and still leave merkleization limit-independent.
#[derive(From, Derivative, Serialize)]
#[derivative(
    Clone(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = ""),
    Default(bound = "")
)]
#[serde(bound = "", transparent)]
pub struct ProgressiveByteList<N>(ByteList<N>);

impl<N> ProgressiveByteList<N> {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<N: Unsigned> TryFrom<Vec<u8>> for ProgressiveByteList<N> {
    type Error = ReadError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, ReadError> {
        ByteList::try_from(bytes).map(Self)
    }
}

impl<N> Debug for ProgressiveByteList<N> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        self.0.fmt(formatter)
    }
}

impl<'de, N: Unsigned> Deserialize<'de> for ProgressiveByteList<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ByteList::deserialize(deserializer).map(Self)
    }
}

impl<N> SszSize for ProgressiveByteList<N> {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<C, N: Unsigned> SszRead<C> for ProgressiveByteList<N> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        ByteList::from_ssz_unchecked(context, bytes).map(Self)
    }
}

impl<N> SszWrite for ProgressiveByteList<N> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.0.write_variable(bytes)
    }
}

impl<N> SszHash for ProgressiveByteList<N> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let root = ProgressiveMerkleTree::merkleize_bytes(self.as_bytes());
        merkle_tree::mix_in_length(root, self.as_bytes().len())
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;
    use typenum::{U4, U4096, U1048576};

    use crate::porcelain::SszReadDefault as _;

    use super::*;

    type TestList = ProgressiveByteList<U4096>;

    // The expected roots below were produced by an independent implementation
    // of `mix_in_length(merkleize_progressive(pack(value)), len(value))`
    // transcribed from ethereum/ssz-specs v0.0.1.dev2.
    //
    // These vectors have not been cross-checked against the pyspec.
    //
    // The lengths straddle the subtree boundaries at 32, 160, 672 and 2720
    // bytes.
    #[test_case(0, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b")]
    #[test_case(1, "e832d263aaa8f9417d9f45a702834f6961ee7b15ad4d3d27f2b0f4fe79d33031")]
    #[test_case(31, "f61288058d4c106ffe81545ba11e23c5e5b97a4cc5f0bbe03b2983cdc6a02ec4")]
    #[test_case(32, "c96b7e311178900fb54e96a5b7f0d6776024018bb48f7eeaa0d9bb2fd6066a8d")]
    #[test_case(33, "43cd474d3b097438f5185868b2d6622d73ef7fa200719864508c0f3f24854cf2")]
    #[test_case(
        159,
        "c22a16e517bd4080d9e1711628bb08d2b61eaab56fa54e39eb45240504adc649"
    )]
    #[test_case(
        160,
        "98b87fafb12cfec4e79a31e73eff183c4f3e05d47fc9f70c3ccfc73af80cfcbe"
    )]
    #[test_case(
        161,
        "078c011197ebff63d41d23b4eb7233af5c5477c2dcb721210a4468f7169919a9"
    )]
    #[test_case(
        671,
        "96a766dfce7af1b9472a97dc6dd041e2e60c1f22afb4efda75480def065752eb"
    )]
    #[test_case(
        672,
        "6e216b54a93f932620e6268dfb2878d25ecf87077e15599d3df30c941549e483"
    )]
    #[test_case(
        673,
        "372f45acae960e89a1a726f62448ca3be320d43d90e99621ad2a3d0c9de27fea"
    )]
    #[test_case(
        2720,
        "e8b620135aee1eafd15ead6d6746e0585bb9ccd2850cdd16243b6c981ac9d12b"
    )]
    fn hash_tree_root_matches_reference(length: usize, expected: &str) {
        let list = test_list(length);

        assert_eq!(list.hash_tree_root(), h256(expected));
    }

    // An empty list still mixes in a length of 0, so its root is not the zero
    // hash.
    #[test]
    fn empty_list_root_is_not_zero() {
        let root = TestList::default().hash_tree_root();

        assert_ne!(root, H256::zero());
        assert_eq!(root, test_list(0).hash_tree_root());
    }

    // The root must not depend on the type-level bound. This is what lets a
    // caller express a provisional limit as `N` without the limit leaking into
    // the root.
    #[test]
    fn root_does_not_depend_on_n() {
        let snug = TestList::try_from(test_bytes(200)).expect("list should fit in N");
        let roomy = ProgressiveByteList::<U1048576>::try_from(test_bytes(200))
            .expect("list should fit in N");

        assert_eq!(snug.as_bytes(), roomy.as_bytes());
        assert_eq!(snug.hash_tree_root(), roomy.hash_tree_root());
    }

    // `N` is the half of the behaviour that merkleization ignores: it bounds decoding.
    #[test]
    fn decoding_is_bounded_by_n() {
        assert!(ProgressiveByteList::<U4>::from_ssz_default(&[0, 1, 2, 3]).is_ok());
        assert!(ProgressiveByteList::<U4>::from_ssz_default(&[0, 1, 2, 3, 4]).is_err());
    }

    #[test_case(0)]
    #[test_case(1)]
    #[test_case(32)]
    #[test_case(33)]
    #[test_case(673)]
    fn ssz_round_trip(length: usize) {
        let list = test_list(length);

        let ssz_bytes = list.to_ssz().expect("list should be serializable");

        assert_eq!(ssz_bytes.len(), length);
        assert_eq!(ssz_bytes.as_slice(), list.as_bytes());

        let decoded = TestList::from_ssz_default(&ssz_bytes).expect("list should be decodable");

        assert_eq!(decoded, list);
    }

    #[test_case(0, "0x")]
    #[test_case(1, "0x00")]
    #[test_case(4, "0x00010203")]
    fn json_round_trip(length: usize, expected: &str) {
        let list = test_list(length);

        let json = serde_json::to_string(&list).expect("list should be serializable");

        assert_eq!(json, format!("\"{expected}\""));

        let decoded = serde_json::from_str::<TestList>(&json).expect("list should be decodable");

        assert_eq!(decoded, list);
    }

    fn test_list(length: usize) -> TestList {
        TestList::try_from(test_bytes(length)).expect("list should fit in N")
    }

    // Matches `test_bytes` in the reference implementation.
    fn test_bytes(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| u8::try_from(index % 256).expect("value modulo 256 should fit in u8"))
            .collect()
    }

    fn h256(digits: &str) -> H256 {
        H256::from_slice(&hex::decode(digits).expect("test vector should be valid hex"))
    }
}
