use core::{fmt::Debug, hash::Hash};

use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use ethereum_types::H256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use try_from_iterator::TryFromIterator;
use typenum::{U1, Unsigned};

use crate::{
    ContiguousList, ReadError, Size, SszHash, SszList, SszRead, SszSize, SszWrite, WriteError,
    merkle_tree::{self, ProgressiveMerkleTree},
};

type PrettyBigU = typenum::U4294967296;

// TODO(gloas): in spec, ProgressiveList is unbounded container, and its limits
// are enforced in user-site. This would require careful refactoring, so for
// easier transition, limits are kept as-is for now.
//
// `N` is the maximum length, enforced on construction and decoding. It does not
// affect merkleization, matching a progressive list that declares a `LIMIT`
// (ethereum/ssz-specs#225). Types that do not declare a limit keep the default.
#[derive(Deref, DerefMut, Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    Hash(bound = "T: Hash"),
    Default(bound = ""),
    Debug(bound = "T: Debug", transparent = "true")
)]
pub struct ProgressiveList<T, N = PrettyBigU>(ContiguousList<T, N>);

impl<T, N> ProgressiveList<T, N> {
    #[must_use]
    pub fn full(element: T) -> Self
    where
        T: Clone,
        N: Unsigned,
    {
        Self(ContiguousList::full(element))
    }

    #[must_use]
    pub fn map<U>(self, function: impl FnMut(T) -> U) -> ProgressiveList<U, N> {
        ProgressiveList(self.0.map(function))
    }

    #[must_use]
    pub fn into_inner(self) -> ContiguousList<T, N> {
        self.0
    }
}

// Only for the default limit, which no `ContiguousList` in use exceeds. A
// smaller limit would make this conversion panic, so it is left to
// `TryFromIterator`.
impl<T, N: Unsigned> From<ContiguousList<T, N>> for ProgressiveList<T> {
    fn from(list: ContiguousList<T, N>) -> Self {
        Self(ContiguousList::try_from_iter(list).expect("list should fit in ProgressiveList"))
    }
}

impl<T, M: Unsigned, N: Unsigned> From<ProgressiveList<T, M>> for ContiguousList<T, N> {
    fn from(list: ProgressiveList<T, M>) -> Self {
        Self::try_from_iter(list).expect("list should fit in target ContiguousList")
    }
}

impl<T, N> AsRef<[T]> for ProgressiveList<T, N> {
    fn as_ref(&self) -> &[T] {
        self.0.as_ref()
    }
}

impl<T, N: Unsigned> TryFrom<Vec<T>> for ProgressiveList<T, N> {
    type Error = ReadError;

    fn try_from(vec: Vec<T>) -> Result<Self, Self::Error> {
        ContiguousList::try_from(vec).map(Self)
    }
}

impl<T, N: Unsigned, const SIZE: usize> TryFrom<[T; SIZE]> for ProgressiveList<T, N> {
    type Error = ReadError;

    fn try_from(array: [T; SIZE]) -> Result<Self, Self::Error> {
        ContiguousList::try_from(array).map(Self)
    }
}

impl<T, N> IntoIterator for ProgressiveList<T, N> {
    type Item = T;
    type IntoIter = <ContiguousList<T, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'list, T, N> IntoIterator for &'list ProgressiveList<T, N> {
    type Item = &'list T;
    type IntoIter = <&'list ContiguousList<T, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&self.0).into_iter()
    }
}

impl<T, N: Unsigned> TryFromIterator<T> for ProgressiveList<T, N> {
    type Error = ReadError;

    fn try_from_iter(elements: impl IntoIterator<Item = T>) -> Result<Self, Self::Error> {
        ContiguousList::try_from_iter(elements).map(Self)
    }
}

impl<T: Serialize, N> Serialize for ProgressiveList<T, N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>, N: Unsigned> Deserialize<'de> for ProgressiveList<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ContiguousList::deserialize(deserializer).map(Self)
    }
}

impl<T: SszSize, N> SszSize for ProgressiveList<T, N> {
    const SIZE: Size = Size::Variable { minimum_size: 0 };
}

impl<C, T: SszRead<C>, N: Unsigned> SszRead<C> for ProgressiveList<T, N> {
    fn from_ssz_unchecked(context: &C, bytes: &[u8]) -> Result<Self, ReadError> {
        ContiguousList::from_ssz_unchecked(context, bytes).map(Self)
    }
}

impl<T: SszWrite, N> SszWrite for ProgressiveList<T, N> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        self.0.write_variable(bytes)
    }
}

impl<T, N> SszHash for ProgressiveList<T, N>
where
    T: SszHash + SszWrite + Send + Sync + Debug,
{
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        let root = if T::PackingFactor::USIZE == 1 {
            let chunks = self.0.as_ref().iter().map(SszHash::hash_tree_root);
            ProgressiveMerkleTree::merkleize_progressive(chunks)
        } else {
            ProgressiveMerkleTree::merkleize_packed(&self.0)
        };
        merkle_tree::mix_in_length(root, self.0.as_ref().len())
    }
}

impl<T, N> SszList<T> for ProgressiveList<T, N>
where
    T: SszHash + SszWrite + Send + Sync + Debug,
    N: Unsigned + Send + Sync,
{
    fn len_usize(&self) -> usize {
        self.0.as_ref().len()
    }

    fn len_u64(&self) -> u64 {
        u64::try_from(self.0.as_ref().len()).expect("list length fits in u64")
    }

    fn get(&self, index: u64) -> Result<&T, crate::IndexError> {
        let index =
            usize::try_from(index).map_err(|_| crate::IndexError::DoesNotFitInUsize { index })?;
        let length = self.0.as_ref().len();

        self.0
            .as_ref()
            .get(index)
            .ok_or(crate::IndexError::OutOfBounds { length, index })
    }

    fn iter<'a>(&'a self) -> Box<dyn ExactSizeIterator<Item = &'a T> + 'a> {
        Box::new(self.0.as_ref().iter())
    }

    fn clone_boxed(&self) -> Box<dyn SszList<T>>
    where
        T: Clone + 'static,
    {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use typenum::U4;

    use crate::{SszReadDefault as _, SszWrite as _};

    use super::*;

    type LimitedList = ProgressiveList<u64, U4>;

    #[test]
    fn limit_is_enforced_on_construction() {
        let expected = ReadError::ListTooLong {
            maximum: 4,
            actual: 5,
        };

        assert_eq!(LimitedList::try_from(vec![0; 5]), Err(expected));
        assert_eq!(LimitedList::try_from([0; 5]), Err(expected));
        assert_eq!(LimitedList::try_from_iter(0..5), Err(expected));

        LimitedList::try_from(vec![0; 4]).expect("list at the limit should be accepted");
    }

    #[test]
    fn limit_is_enforced_on_decoding() {
        let bytes = ProgressiveList::<u64>::try_from_iter(0..5)
            .expect("list should be within the default limit")
            .to_ssz()
            .expect("list should be serializable");

        assert_eq!(
            LimitedList::from_ssz_default(bytes),
            Err(ReadError::ListTooLong {
                maximum: 4,
                actual: 5,
            }),
        );
    }

    #[test]
    fn limit_is_enforced_on_deserialization() {
        let error = serde_json::from_str::<LimitedList>("[0, 1, 2, 3, 4]")
            .expect_err("list over the limit should be rejected");

        assert!(error.to_string().contains("no more than 4"), "{error}");
    }

    // The limit is checked on construction and decoding but never reaches the
    // root, for both packed and unpacked elements.
    #[test]
    fn root_does_not_depend_on_limit() {
        for length in 0..=4 {
            let limited =
                LimitedList::try_from_iter(0..length).expect("list should be within the limit");
            let unlimited = ProgressiveList::<u64>::try_from_iter(0..length)
                .expect("list should be within the default limit");

            assert_eq!(limited.hash_tree_root(), unlimited.hash_tree_root());

            let limited = ProgressiveList::<H256, U4>::try_from_iter(
                (0..length).map(|byte| H256::repeat_byte(byte.try_into().expect("fits in u8"))),
            )
            .expect("list should be within the limit");
            let unlimited = ProgressiveList::<H256>::try_from_iter(
                (0..length).map(|byte| H256::repeat_byte(byte.try_into().expect("fits in u8"))),
            )
            .expect("list should be within the default limit");

            assert_eq!(limited.hash_tree_root(), unlimited.hash_tree_root());
        }
    }
}
