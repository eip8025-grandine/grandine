// TODO(32-bit support): Review all uses of `typenum::Unsigned::USIZE`.

// Here's a visual aid to help understand the algorithms used here:
// ```text
//                                                  ┊
// height 4                                         0
//                              ┌───────────────────┴───────────────────┐
// height 3                     0                                       1
//                    ┌─────────┴─────────┐                   ┌─────────┴─────────┐
// height 2           0                   1                   2                   3
//               ┌────┴────┐         ┌────┴────┐         ┌────┴────┐         ┌────┴────┐
// height 1      0         1         2         3         4         5         6         7
//             ┌─┴─┐     ┌─┴─┐     ┌─┴─┐     ┌─┴─┐     ┌─┴─┐     ┌─┴─┐     ┌─┴─┐     ┌─┴─┐
// height 0    0   1     2   3     4   5     6   7     8   9    10   11   12   13   14   15
//           0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111
// ```

use core::ops::Range;

use bit_field::BitField as _;
use byteorder::LittleEndian;
use derivative::Derivative;
use ethereum_types::H256;
use generic_array::{ArrayLength, GenericArray};
use hashing::ZERO_HASHES;
use itertools::Itertools as _;
use serde::{Deserialize, Serialize};
use ssz_derive::Ssz;
use static_assertions::assert_type_eq_all;
use typenum::{Add1, Unsigned as _};

use crate::{
    consts::{BYTES_PER_CHUNK, Endianness},
    contiguous_vector::ContiguousVector,
    porcelain::{SszHash, SszWrite},
    type_level::{ContiguousVectorElements, MerkleElements, ProofSize},
};

#[derive(Derivative, Deserialize, Serialize, Ssz)]
#[derivative(
    Clone(bound = ""),
    Copy(bound = "D::ArrayType: Copy"),
    Default(bound = ""),
    Debug(bound = "")
)]
#[serde(bound = "", deny_unknown_fields)]
#[ssz(
    bound = "D: ContiguousVectorElements<H256> + MerkleElements<H256>",
    bound_for_read = "D: ContiguousVectorElements<H256> + MerkleElements<H256>",
    internal,
    transparent
)]
pub struct MerkleTree<D: ArrayLength<H256>> {
    // The elements of `MerkleTree.sibling_hashes` are initialized to 0x00…00.
    // The initial values are meaningless and never used as long as correct indices are passed.
    sibling_hashes: ContiguousVector<H256, D>,
}

impl<D: ArrayLength<H256>, A: Into<GenericArray<H256, D>>> From<A> for MerkleTree<D> {
    fn from(array: A) -> Self {
        let sibling_hashes = array.into().into();
        Self { sibling_hashes }
    }
}

impl<D: ArrayLength<H256>> MerkleTree<D> {
    pub fn merkleize_bytes(bytes: impl AsRef<[u8]>) -> H256 {
        let chunks = bytes.as_ref().chunks(BYTES_PER_CHUNK).map(|partial_chunk| {
            let mut chunk = H256::zero();
            chunk[..partial_chunk.len()].copy_from_slice(partial_chunk);
            chunk
        });

        Self::merkleize_chunks(chunks)
    }

    pub fn merkleize_packed<T: SszHash + SszWrite>(values: &[T]) -> H256 {
        let size = T::SIZE.fixed_part();

        let chunks = values.chunks(T::PackingFactor::USIZE).map(|pack| {
            let mut hash = H256::zero();

            hash.as_bytes_mut()
                .chunks_exact_mut(size)
                .zip(pack)
                .for_each(|(destination, element)| element.write_fixed(destination));

            hash
        });

        Self::merkleize_chunks(chunks)
    }

    pub fn merkleize_chunks(
        chunks: impl IntoIterator<
            IntoIter = impl DoubleEndedIterator<Item = H256> + ExactSizeIterator<Item = H256>,
        >,
    ) -> H256 {
        let mut chunks = chunks.into_iter();

        match chunks.next_back() {
            Some(last_chunk) => {
                let last_index = chunks.len();

                let mut merkle_tree = Self::default();

                for (index, chunk) in chunks.enumerate() {
                    merkle_tree.push(index, chunk);
                }

                merkle_tree.push_and_compute_root(last_index, last_chunk)
            }
            None => ZERO_HASHES[D::USIZE],
        }
    }

    pub fn push(&mut self, index: usize, chunk: H256) -> (usize, H256) {
        // TODO(32-bit support): either remove `assert!` or change index type to `u64`
        let index_u64: u64 = index.try_into().expect("usize should fit in u64");
        assert!(index_u64 < 1 << D::U64);

        let sibling_to_update = binary_carry_sequence(index);

        let mut hash = chunk;

        for height in 0..sibling_to_update {
            hash = hashing::hash_256_256(self.sibling_hashes[height], hash);
        }

        if sibling_to_update < D::USIZE {
            self.sibling_hashes[sibling_to_update] = hash;
        }

        (sibling_to_update, hash)
    }

    pub fn push_and_compute_root(&mut self, index: usize, chunk: H256) -> H256 {
        let (updated_sibling, mut hash) = self.push(index, chunk);

        #[expect(
            clippy::needless_range_loop,
            reason = "The suggested rewrite is not an improvement."
        )]
        for height in updated_sibling..D::USIZE {
            // `self.sibling_hashes[updated_sibling]` will not be accessed during this call.
            // The first iteration of the loop always takes the else branch.
            if index.get_bit(height) {
                hash = hashing::hash_256_256(self.sibling_hashes[height], hash);
            } else {
                hash = hashing::hash_256_256(hash, ZERO_HASHES[height]);
            }
        }

        hash
    }

    // See other implementations:
    // - <https://github.com/ethereum/research/blob/88eb03288a6ccd2f3e1f4b6bfd785bc52d10697b/spec_pythonizer/utils/merkle_minimal.py>
    // - <https://github.com/ethereum/research/blob/a4a600f2869feed5bfaab24b13ca1692069ef312/beacon_chain_impl/progressive_merkle_tree.py>
    // - <https://eips.ethereum.org/EIPS/eip-4881#reference-implementation>
    // Ours is not directly based on any of them, so don't expect similarities.
    //
    // Using `Range<usize>` makes it impossible to construct proofs for chunks with index `u32::MAX`
    // on 32 bit machines. `RangeInclusive<usize>` or `impl RangeBounds<usize>` would solve that,
    // but `Range<usize>` is more convenient in a lot of ways. This is not likely to be a problem in
    // practice. Also, we do not test on 32 bit machines (physical or virtual), so getting the logic
    // right may be difficult.
    pub fn extend_and_construct_proofs(
        &mut self,
        chunks: impl IntoIterator<IntoIter = impl ExactSizeIterator<Item = H256>>,
        chunk_indices: Range<usize>,
        proof_indices: Range<usize>,
    ) -> impl Iterator<Item = ProofWithLength<D>>
    where
        D: ProofSize,
    {
        assert!(chunk_indices.start <= proof_indices.start);
        assert!(proof_indices.start < proof_indices.end);
        assert!(proof_indices.end <= chunk_indices.end);
        assert!(chunk_indices.end <= 1 << D::USIZE);

        let mut chunks = chunks.into_iter();

        assert_eq!(chunks.len(), chunk_indices.len());

        let indices_at_height = move |height: usize| {
            // `min_index` is always the index of a left node. It refers to an element of
            // `self.sibling_hashes` when `chunk_indices.start.get_bit(height)` is `true`.
            let min_index = chunk_indices.start >> height & !1;
            let max_index = chunk_indices.end.saturating_sub(1) >> height;
            (min_index, max_index)
        };

        // Nodes past a certain height do not need to be computed because they are
        // neither included in proofs nor used to update `self.sibling_hashes`.
        let cutoff_height = chunk_indices
            .end
            .ilog2()
            .saturating_add(1)
            .min(D::U32)
            .try_into()
            .expect("number of bits in usize should fit in usize");

        let mut nodes = GenericArray::<Box<[H256]>, D>::default();

        for height in 0..cutoff_height {
            let (min_index, max_index) = indices_at_height(height);
            let node_count = max_index.saturating_sub(min_index).saturating_add(1);

            let mut nodes_at_height = Vec::with_capacity(node_count);

            if chunk_indices.start.get_bit(height) {
                nodes_at_height.push(self.sibling_hashes[height]);
            }

            if height == 0 {
                nodes_at_height.extend(chunks.by_ref());
            } else {
                let right_subtree_empty = !chunk_indices
                    .end
                    .saturating_sub(1)
                    .get_bit(height.saturating_sub(1));

                let padding = right_subtree_empty.then_some(ZERO_HASHES[height.saturating_sub(1)]);
                let lower = nodes[height.saturating_sub(1)]
                    .iter()
                    .copied()
                    .chain(padding);

                nodes_at_height.extend(
                    lower
                        .tuples()
                        .map(|(left, right)| hashing::hash_256_256(left, right)),
                );
            }

            assert_eq!(nodes_at_height.len(), node_count);

            nodes[height] = nodes_at_height.into_boxed_slice();
        }

        // `next_in_right_subtree.count_ones()` is an upper bound for the
        // number of elements in `self.sibling_hashes` that have to be updated.
        let next_in_right_subtree = chunk_indices.end;

        // ```text
        // input     0    1    2    3    4    5    6    7    8    9   10   11   12   13   14   15
        //         0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111
        //         1111 1111 1111 1111 1111 1111 1111 1111 0111 0111 0111 0111 0011 0011 0001 0000
        // output   15   15   15   15   15   15   15   15    7    7    7    7    3    3    1    0
        // ```
        // See <https://oeis.org/A003817>.
        //
        // `usize::saturating_shr` does not exist as of Rust 1.95.0.
        let filled_left_subtree = usize::MAX
            .checked_shr(chunk_indices.start.leading_ones())
            .unwrap_or_default();

        let siblings_to_update = next_in_right_subtree & filled_left_subtree;

        for height in 0..D::USIZE {
            if siblings_to_update.get_bit(height) {
                let (min_index, max_index) = indices_at_height(height);
                let last_new_sibling_at_height = max_index & !1;

                self.sibling_hashes[height] =
                    nodes[height][last_new_sibling_at_height.saturating_sub(min_index)];
            }
        }

        proof_indices.map(move |proof_index| {
            let mut proof = ContiguousVector::default();

            for height in 0..D::USIZE {
                let (min_index, max_index) = indices_at_height(height);
                let proven_node_index = proof_index >> height;

                assert!(min_index <= proven_node_index);
                assert!(proven_node_index <= max_index);

                let proof_node_index = proven_node_index ^ 1;

                proof[height] = nodes[height]
                    .get(proof_node_index.saturating_sub(min_index))
                    .copied()
                    .unwrap_or(ZERO_HASHES[height]);
            }

            // The last element of the proof corresponds to the tree node added by `mix_in_length`.
            proof[D::USIZE] = hash_of_length(chunk_indices.end);

            proof
        })
    }
}

pub type ProofWithLength<N> = ContiguousVector<H256, Add1<N>>;

/// [`merkleize_progressive`](https://github.com/ethereum/consensus-specs/blob/a08d8a6e2b45f0b8c0d379abc15583427c643689/ssz/simple-serialize.md#merkleization)
///
/// Splits `chunks` into consecutive subtrees of 1, 4, 16, 64… leaves and combines their roots
/// from right to left. The result does not depend on any capacity, which is what makes this
/// usable for types that have no length bound.
///
/// [`MerkleTree`] cannot be used for the subtrees because it takes its depth from the type level,
/// whereas the depth of a progressive subtree depends on the number of chunks passed in.
#[must_use]
pub fn merkleize_progressive(
    chunks: impl IntoIterator<IntoIter = impl ExactSizeIterator<Item = H256>>,
) -> H256 {
    let mut chunks = chunks.into_iter();
    let mut subtree_roots = Vec::new();
    let mut depth = 0;

    while chunks.len() > 0 {
        let leaves = 1 << depth;

        subtree_roots.push(merkleize_chunks_with_depth(
            chunks.by_ref().take(leaves),
            depth,
        ));

        depth = depth.saturating_add(2);
    }

    // The recursion in the specification is right-leaning and bottoms out at a zero value.
    subtree_roots
        .into_iter()
        .rev()
        .fold(H256::zero(), |right, left| {
            hashing::hash_256_256(left, right)
        })
}

/// [`MerkleTree::merkleize_chunks`] with the depth of the tree passed in at runtime.
///
/// The chunks are padded to `1 << depth` virtually, as in [`MerkleTree`].
fn merkleize_chunks_with_depth(
    chunks: impl IntoIterator<IntoIter = impl ExactSizeIterator<Item = H256>>,
    depth: usize,
) -> H256 {
    let chunks = chunks.into_iter();
    let chunk_count = chunks.len();

    if chunk_count == 0 {
        return ZERO_HASHES[depth];
    }

    assert!(chunk_count <= 1 << depth);

    let last_index = chunk_count.saturating_sub(1);

    let mut sibling_hashes = vec![H256::zero(); depth];
    let mut root = H256::zero();

    for (index, chunk) in chunks.enumerate() {
        let sibling_to_update = binary_carry_sequence(index);

        let mut hash = chunk;

        for sibling_hash in sibling_hashes.iter().take(sibling_to_update) {
            hash = hashing::hash_256_256(*sibling_hash, hash);
        }

        if index < last_index {
            if sibling_to_update < depth {
                sibling_hashes[sibling_to_update] = hash;
            }

            continue;
        }

        for height in sibling_to_update..depth {
            hash = if index.get_bit(height) {
                hashing::hash_256_256(sibling_hashes[height], hash)
            } else {
                hashing::hash_256_256(hash, ZERO_HASHES[height])
            };
        }

        root = hash;
    }

    root
}

/// [`mix_in_length`](https://github.com/ethereum/consensus-specs/blob/4c54bddb6cd144ca8a0a01b7155f43b295c70458/ssz/simple-serialize.md#merkleization)
///
/// The SSZ specification does not state that `length` should be limited to `u64`.
/// Using `usize` simplifies the implementation of this crate.
#[must_use]
pub fn mix_in_length(root: H256, length: usize) -> H256 {
    hashing::hash_256_256(root, hash_of_length(length))
}

fn hash_of_length(length: usize) -> H256 {
    assert_type_eq_all!(Endianness, LittleEndian);

    let mut hash = H256::zero();
    hash[..size_of::<usize>()].copy_from_slice(&length.to_le_bytes());
    hash
}

// One element of `MerkleTree.sibling_hashes` has to be updated for later calculations every time
// a chunk is added (except for the last one). This calculates the position of that element. See:
// - <https://oeis.org/A007814>
// - <https://mathworld.wolfram.com/BinaryCarrySequence.html>
fn binary_carry_sequence(index: usize) -> usize {
    index
        .saturating_add(1)
        .trailing_zeros()
        .try_into()
        .expect("number of bits in usize should fit in usize")
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use test_case::test_case;
    use typenum::{U0, U2, U3, U4, Unsigned};

    use super::*;

    #[test]
    fn depth_0_merkle_tree_merkleize_bytes_handles_zero_chunks() {
        assert_eq!(MerkleTree::<U0>::merkleize_bytes([]), H256::zero());
    }

    #[test]
    fn depth_0_merkle_tree_merkleize_bytes_handles_single_chunk() {
        assert_eq!(
            MerkleTree::<U0>::merkleize_bytes(H256::zero()),
            H256::zero(),
        );
    }

    #[test]
    fn depth_0_merkle_tree_merkleize_packed_handles_zero_values() {
        assert_eq!(
            MerkleTree::<U0>::merkleize_packed::<H256>(&[]),
            H256::zero(),
        );
    }

    #[test]
    fn depth_0_merkle_tree_merkleize_packed_handles_single_value() {
        assert_eq!(
            MerkleTree::<U0>::merkleize_packed(&[H256::zero()]),
            H256::zero(),
        );
    }

    #[test]
    fn depth_0_merkle_tree_merkleize_chunks_handles_single_chunk() {
        assert_eq!(
            MerkleTree::<U0>::merkleize_chunks([H256::zero()]),
            H256::zero(),
        );
    }

    #[test]
    fn depth_0_merkle_tree_push_handles_single_chunk() {
        assert_eq!(
            MerkleTree::<U0>::default().push(0, H256::default()),
            (0, H256::zero()),
        );
    }

    #[test]
    fn depth_0_merkle_tree_push_and_compute_root_handles_single_chunk() {
        assert_eq!(
            MerkleTree::<U0>::default().push_and_compute_root(0, H256::default()),
            H256::zero(),
        );
    }

    #[test]
    fn depth_0_merkle_tree_extend_and_construct_proofs_handles_single_chunk() {
        itertools::assert_equal(
            MerkleTree::<U0>::default().extend_and_construct_proofs([H256::default()], 0..1, 0..1),
            [[hash_of_length(1)].into()],
        );
    }

    #[test]
    fn merkle_tree_extend_and_construct_proofs_handles_last_chunk() {
        type Depth = U3;

        let capacity = 1 << Depth::USIZE;

        let ff_hash_0 = H256::repeat_byte(0xff);
        let ff_hash_1 = hashing::hash_256_256(ff_hash_0, ff_hash_0);
        let ff_hash_2 = hashing::hash_256_256(ff_hash_1, ff_hash_1);

        let chunks = core::iter::repeat_n(ff_hash_0, capacity);
        let chunk_indices = 0..capacity;
        let proof_indices = chunk_indices.clone();

        let expected_proof = [ff_hash_0, ff_hash_1, ff_hash_2, hash_of_length(capacity)].into();
        let expected_proofs = core::iter::repeat_n(expected_proof, capacity);

        let mut tree = MerkleTree::<Depth>::default();
        let actual_proofs = tree.extend_and_construct_proofs(chunks, chunk_indices, proof_indices);

        itertools::assert_equal(actual_proofs, expected_proofs);
    }

    // The following is incorrect but works in a lot of cases:
    // ```
    // let filled_left_subtree = usize::MAX - chunk_indices.start;
    // ```
    // No other test in the codebase catches this.
    #[test]
    fn merkle_tree_extend_and_construct_proofs_handles_range_spanning_two_subtrees_of_height_1() {
        type Depth = U2;

        // The chunks have to be different to catch the bug described above.
        let chunk_0 = H256::repeat_byte(1);
        let chunk_1 = H256::repeat_byte(2);
        let chunk_2 = H256::repeat_byte(3);
        let chunk_3 = H256::repeat_byte(4);

        let expected_proof_0 = [ZERO_HASHES[0], ZERO_HASHES[1], hash_of_length(1)].into();

        let expected_proof_1 = [
            chunk_0,
            hashing::hash_256_256(chunk_2, ZERO_HASHES[0]),
            hash_of_length(3),
        ]
        .into();

        let expected_proof_2 = [
            ZERO_HASHES[0],
            hashing::hash_256_256(chunk_0, chunk_1),
            hash_of_length(3),
        ]
        .into();

        let expected_proof_3 = [
            chunk_2,
            hashing::hash_256_256(chunk_0, chunk_1),
            hash_of_length(4),
        ]
        .into();

        let mut merkle_tree = MerkleTree::<Depth>::default();

        itertools::assert_equal(
            merkle_tree.extend_and_construct_proofs([chunk_0], 0..1, 0..1),
            [expected_proof_0],
        );

        itertools::assert_equal(
            merkle_tree.extend_and_construct_proofs([chunk_1, chunk_2], 1..3, 1..3),
            [expected_proof_1, expected_proof_2],
        );

        itertools::assert_equal(
            merkle_tree.extend_and_construct_proofs([chunk_3], 3..4, 3..4),
            [expected_proof_3],
        );
    }

    // This could be checked statically using `#[cfg(any(target_pointer_width = …))]`,
    // but that's too verbose.
    #[test]
    fn usize_fits_in_h256() {
        hash_of_length(usize::MIN);
        hash_of_length(usize::MAX);
    }

    // The expected roots below were produced by an independent implementation of
    // `merkleize_progressive` transcribed from `ssz/simple-serialize.md` at the pinned
    // `consensus-specs` revision.
    //
    // They are NOT cross-checked against the pyspec, which design 0001 requires and which
    // cannot be run here. That verification gap is still open.
    //
    // The chunk counts straddle the subtree boundaries, which fall at 1, 5, 21 and 85 chunks.
    #[test_case(0, hex!("0000000000000000000000000000000000000000000000000000000000000000"))]
    #[test_case(1, hex!("037d6dfb3a369a41e01100fdd53c35ee3fb69ddec5830d61e1138d066a4c2285"))]
    #[test_case(2, hex!("2dfe47da19ad9ff11afe44dd8de4db8517cefd5a9bddffe6652b26a1b91ea5ac"))]
    #[test_case(4, hex!("860e625c823ed369bad6d7cde0b59908637627f73df2eff13b4e56a4b3a049ac"))]
    #[test_case(5, hex!("3fd53b812118ddea60b9deab5c72d32b0c4dcfd2c94deda753e6e1d548fbc274"))]
    #[test_case(6, hex!("2e2a2abd4d0e28498ec0cdd817c715b246aa15e7b34767061b7632337188429e"))]
    #[test_case(20, hex!("31dd06398738f5e83c63b4dd34040b0b9d51fb527168cdc68565c4033eb81692"))]
    #[test_case(21, hex!("f148f679afbfebfe5616080a45461aee3d1f4ce2cc752ce824c3f067d2707623"))]
    #[test_case(22, hex!("040be60071c540aafc1d44f366239ab6a41bf8740a38f9d52ab0bbd9cd974c45"))]
    #[test_case(85, hex!("24ea21562226364be74fd2696d0824a4347cfac7dd4b2ae28cd0e9cc22bc341d"))]
    #[test_case(86, hex!("b73c4c427974f47c74c2812d353c966f5dadae70c44f6fe9a15e179b86914977"))]
    fn merkleize_progressive_matches_reference(chunk_count: usize, expected: [u8; 32]) {
        let chunks = test_chunks(chunk_count);

        assert_eq!(merkleize_progressive(chunks), H256(expected));
    }

    #[test]
    fn merkleize_progressive_handles_zero_chunks() {
        assert_eq!(merkleize_progressive([]), H256::zero());
    }

    // A single chunk is merkleized as a subtree of one leaf, then combined with the zero value
    // that the recursion bottoms out at.
    #[test]
    fn merkleize_progressive_handles_single_chunk() {
        let chunk = H256::repeat_byte(1);

        assert_eq!(
            merkleize_progressive([chunk]),
            hashing::hash_256_256(chunk, H256::zero()),
        );
    }

    // `MerkleTree` is already covered by `consensus-spec-tests`, so agreeing with it pins the
    // binary part of progressive merkleization to something independently tested.
    #[test]
    fn merkleize_chunks_with_depth_matches_merkle_tree() {
        assert_matches_merkle_tree::<U0>();
        assert_matches_merkle_tree::<U2>();
        assert_matches_merkle_tree::<U3>();
        assert_matches_merkle_tree::<U4>();
    }

    fn assert_matches_merkle_tree<D: ArrayLength<H256>>() {
        for chunk_count in 0..=1 << D::USIZE {
            let chunks = test_chunks(chunk_count);

            assert_eq!(
                merkleize_chunks_with_depth(chunks.iter().copied(), D::USIZE),
                MerkleTree::<D>::merkleize_chunks(chunks.iter().copied()),
                "depth {} with {chunk_count} chunks",
                D::USIZE,
            );
        }
    }

    fn test_chunks(chunk_count: usize) -> Vec<H256> {
        (0..chunk_count).map(test_chunk).collect()
    }

    // Matches `chunk` in the reference implementation.
    fn test_chunk(index: usize) -> H256 {
        let byte =
            u8::try_from(index.saturating_add(1) % 256).expect("value modulo 256 should fit in u8");

        H256::repeat_byte(byte)
    }
}
