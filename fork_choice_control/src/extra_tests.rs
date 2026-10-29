// Some of the tests cause validators to violate slashing conditions.
// The tests should pass despite this, as slashing is outside the purview of the fork choice store.
//
// Some of the tests are taken from Lighthouse but adapted to make sense in our implementation.
// The original ones test implementation details specific to Lighthouse, test cases that could never
// occur according to `consensus-specs`, and don't bother constructing valid blocks or attestations.
//
// Some of the tests had to be adapted for `consensus-specs` version 1.3.0-rc.4 because of the
// addition of unrealized checkpoints and changes to how viability is determined.

#![expect(clippy::similar_names)]
#![expect(clippy::too_many_lines)]

use std::sync::Arc;

#[cfg(feature = "eth2-cache")]
use eth2_cache_utils::medalla;
#[cfg(feature = "eth2-cache")]
use eth2_libp2p::GossipId;
use helper_functions::{accessors, misc};
use itertools::Itertools as _;
use spec_test_utils::BlsSetting;
#[cfg(feature = "eth2-cache")]
use std_ext::ArcExt as _;
use types::{
    combined::Attestation,
    gloas::consts::{PAYLOAD_STATUS_EMPTY, PAYLOAD_STATUS_FULL},
    nonstandard::{PayloadStatus, Phase},
    phase0::{
        consts::{GENESIS_EPOCH, GENESIS_SLOT},
        containers::{
            AttestationData, AttesterSlashing as Phase0AttesterSlashing, Checkpoint,
            IndexedAttestation,
        },
        primitives::H256,
    },
    preset::Minimal,
    traits::{BeaconState as _, SignedBeaconBlock as _},
};
#[cfg(feature = "eth2-cache")]
use types::{config::Config, preset::Medalla};

use fork_choice_store::PayloadPresence;

use crate::{
    helpers::{Context, Status, epoch_at_slot, is_at_start_of_epoch, start_of_epoch},
    messages::P2pMessage,
    storage::StoredBlock,
};

#[cfg(feature = "eth2-cache")]
use crate::specialized::TestController;

// This test was added to reproduce the bug described in
// <https://github.com/ethereum/consensus-specs/issues/1887>.
// The bug would only manifest starting with the first slot of the next epoch.
#[test]
#[cfg(feature = "eth2-cache")]
fn processes_old_attestations_from_medalla_in_a_future_slot() {
    let config = Arc::new(Config::medalla());
    let genesis_state = medalla::GENESIS_BEACON_STATE.force().clone_arc();
    let genesis_block = medalla::GENESIS_BEACON_BLOCK.force().clone_arc();
    let last_slot = 224;

    let next_epoch = misc::compute_epoch_at_slot::<Medalla>(last_slot) + 1;
    let first_slot_of_next_epoch = misc::compute_start_slot_at_epoch::<Medalla>(next_epoch);

    let (controller, _mutator_handle) = TestController::quiet(config, genesis_block, genesis_state);

    controller.on_slot(first_slot_of_next_epoch);
    controller.wait_for_tasks();

    for block in medalla::beacon_blocks(1..=last_slot, 4) {
        controller.on_requested_block(block.clone_arc(), None);
        controller.wait_for_tasks();

        let head = controller.head().value;

        assert_eq!(head.slot(), block.message().slot());
        assert_eq!(head.block_root, block.message().hash_tree_root());
    }
}

#[test]
#[cfg(feature = "eth2-cache")]
fn processes_blocks_from_medalla_in_their_slots() {
    let config = Arc::new(Config::medalla());
    let genesis_state = medalla::GENESIS_BEACON_STATE.force().clone_arc();
    let genesis_block = medalla::GENESIS_BEACON_BLOCK.force().clone_arc();
    let last_slot = 224;

    let (controller, _mutator_handle) = TestController::quiet(config, genesis_block, genesis_state);

    for block in medalla::beacon_blocks(1..=last_slot, 4) {
        controller.on_slot(block.message().slot());
        controller.wait_for_tasks();
        controller.on_gossip_block(block.clone_arc(), GossipId::default());
        controller.wait_for_tasks();

        let head = controller.head().value;

        assert_eq!(head.slot(), block.message().slot());
        assert_eq!(head.block_root, block.message().hash_tree_root());
    }
}

// Based on the only fork choice test we had in the repository from 2019.
#[test]
fn handles_happy_path_with_3_blocks_and_height_difference_of_1() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::repeat_byte(1));
    let (block_2, state_2) = context.empty_block(&state_0, 2, H256::repeat_byte(2));
    let (block_3, state_3) = context.empty_block(&state_0, 3, H256::repeat_byte(3));

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());
    assert!(block_2.message().hash_tree_root() < block_3.message().hash_tree_root());

    context.on_slot(start_of_epoch(2));

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_singular_attestation(&state_2, 1, 0);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_singular_attestation(&state_1, 1, 1);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_singular_attestation(&state_1, 1, 2);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(2),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_singular_attestation(&state_3, 1, 3);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(2),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_singular_attestation(&state_3, 1, 4);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(2),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });
}

#[test]
fn best_child_is_updated_when_it_falls_behind_the_2nd_best_one() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) = context.empty_block(&state_0, start_of_epoch(1), H256::default());

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());

    // At this point the block tree looks like this:
    //
    //          block_0(0) HEAD
    //
    // I.e., there's a single block in slot 0 with attesting balance 0.
    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_slot(start_of_epoch(2));

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);

    // At this point the block tree looks like this:
    //
    //          block_0(0)
    //            / \
    //           /   \
    //          /     \
    //         /       \
    //      block_1(0)  |
    //                  |
    //               block_2(0) HEAD
    //
    // `block_2` is the head because
    // `block_1.message().hash_tree_root() < block_2.message().hash_tree_root()`.
    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_singular_attestation(&state_1, 1, 0);
    context.on_acceptable_singular_attestation(&state_1, 1, 1);
    context.on_acceptable_singular_attestation(&state_1, 1, 2);

    //          block_0(0)
    //            / \
    //           /   \
    //          /     \
    //         /       \
    // HEAD block_1(3)  |
    //                  |
    //               block_2(0)
    //
    // We use the number of attesting validators as a shorthand for the attesting balance.
    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(3),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_slot(start_of_epoch(3));

    context.on_acceptable_singular_attestation(&state_2, 2, 1);
    context.on_acceptable_singular_attestation(&state_2, 2, 2);

    //          block_0(0)
    //            / \
    //           /   \
    //          /     \
    //         /       \
    //      block_1(1)  |
    //                  |
    //               block_2(2) HEAD
    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(2),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });
}

// ```text
//   0
//  / \
// |   4  block at the start of epoch 2,
// |   |  justified between epochs 2 and 3 by blocks 5 and 6,
// |   |  finalized between epochs 3 and 4 by blocks 6 and 7
// |   |
// |   5  block at the end of epoch 2,
// |   |  with attestations justifying block 4 in epoch 2
// |   |
// |   6  block at the end of epoch 3,
// |   |  with attestations justifying block 5 in epoch 3 and finalizing block 4 in epoch 2,
// |   |  causing attestations added by block 5 to be processed
// |   |
// |   7  block at the start of epoch 4,
// |   |  causing attestations added by block 6 to be processed
// |   |
// 1   |  block at the start of epoch 4,
// |   |  justified between epochs 4 and 5 by blocks 2 and 3
// |   |
// 2   |  block at the end of epoch 4,
// |   |  with attestations justifying block 1 in epoch 4
// |   |
// 3   |  block at the start of epoch 5,
//     |  causing attestations added by block 2 to be processed
//     |
//     8  block at the end of epoch 5,
//        with attestations justifying block 7 in epoch 5
// ```
//
// This test predates `consensus-specs` v1.3.0-rc.4.
// Some of the blocks may no longer be necessary due to the addition of unrealized checkpoints.
//
// This scenario can only happen if 1/3 of the validators make slashable attestations.
// The 2nd supermajority link on the 4-7 fork is surrounded by the one on the 1-3 fork.
//
// Processing block 6 causes checkpoints in the fork choice store to become inconsistent.
// A fully compliant implementation should return an orphaned block as the head when that happens.
// Our implementation cannot do so because it prunes orphaned blocks as soon as possible.
// The checkpoints become consistent again when block 8 is processed.
//
// This edge case was introduced to the Fork choice specification in `consensus-specs` v1.3.0-rc.4.
// [Pull request #3290] removed the atomic checkpoint update implemented in [pull request #2727].
// The edge case was touched on in the [comments for pull request #3290].
// djrtwo's comment appears to be incorrect.
// It does not consider blocks arriving in an unusual order like in this test.
//
// We [reported this as a bug], but it turned out to be a known limitation:
// > The issue (https://notes.ethereum.org/1gK1XfrDSpiFSFwSnJ-dAw) is known to us, and the design decision to allow inconsistent Store.justified_checkpoint & Store.finalized_checkpoint updates is intentional.
// >
// > Admittedly, the documentation for this behavior is lacking. It is however, specified in fork-choice.md (https://github.com/ethereum/consensus-specs/blame/c90d724392c619c0fd3dbd471567d2bba9921bef/specs/phase0/fork-choice.md#L345-L359) and acknowledged in these test cases:
// > - test_new_finalized_slot_is_justified_checkpoint_ancestor (https://github.com/ethereum/consensus-specs/blob/c90d724392c619c0fd3dbd471567d2bba9921bef/tests/core/pyspec/eth2spec/test/phase0/fork_choice/test_on_block.py#L443-L444)
// > - test_new_finalized_slot_is_not_justified_checkpoint_ancestor (https://github.com/ethereum/consensus-specs/blob/c90d724392c619c0fd3dbd471567d2bba9921bef/tests/core/pyspec/eth2spec/test/phase0/fork_choice/test_on_block.py#L364-L368) (due to limitations in client testing infrastructure, we cannot execute this spec test in clients)
// >
// > Here’s the rationale for the design decision - we have a choice between two properties:
// > P1. monotonicity (https://docs.google.com/document/d/1DltBHQ_-jEi0N4qu5Pu5LtSaBruTj_Uqq_z47E1LelQ/edit#bookmark=id.9v8oqstpww8e) of Store.justified_checkpoint
// > P2. consistency between Store.justified_checkpoint & Store.finalized_checkpoint
// >
// > Note that:
// > - P1 breaks under asynchrony and without slashing. If we don't fix P1, we can end up with validator voting deadlock ("self-slashability").
// > - P2 can break only when >1/3 slashable.
// >
// > In the fork choice upgrade (https://github.com/ethereum/consensus-specs/pull/3290), we preferred to preserve P1 over P2, because the risk of encountering asynchronous network conditions was deemed larger than >1/3 validators producing slashable messages.
//
// [Pull request #3290]:              https://github.com/ethereum/consensus-specs/pull/3290
// [pull request #2727]:              https://github.com/ethereum/consensus-specs/pull/2727
// [comments for pull request #3290]: https://github.com/ethereum/consensus-specs/pull/3290/files#r1135866084
// [reported this as a bug]:          https://notes.ethereum.org/1gK1XfrDSpiFSFwSnJ-dAw
#[test]
fn survives_and_recovers_from_justified_block_being_pruned() {
    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, start_of_epoch(4), H256::default());
    let (block_2, state_2) = context.block_justifying_current_epoch(&state_1, 4, H256::default());
    let (block_3, _) = context.empty_block(&state_2, start_of_epoch(5), H256::default());
    let (block_4, state_4) = context.empty_block(&state_0, start_of_epoch(2), H256::default());
    let (block_5, state_5) = context.block_justifying_current_epoch(&state_4, 2, H256::default());
    let (block_6, state_6) = context.block_justifying_current_epoch(&state_5, 3, H256::default());
    let (block_7, state_7) = context.empty_block(&state_6, start_of_epoch(4), H256::default());
    let (block_8, _) = context.block_justifying_current_epoch(&state_7, 5, H256::default());

    context.on_slot(start_of_epoch(6));

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);
    context.on_acceptable_block(&block_5);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 4,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 5,
    });

    context.on_acceptable_block(&block_6);

    assert_eq!(context.anchor_block(), block_4);

    context.assert_status(Status {
        head: &block_4,
        attesting_validators: None,
        store_justified_epoch: 4,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 2,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_7);

    assert_eq!(context.anchor_block(), block_4);

    context.assert_status(Status {
        head: &block_4,
        attesting_validators: None,
        store_justified_epoch: 4,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 2,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_8);

    context.assert_status(Status {
        head: &block_8,
        attesting_validators: Some(0),
        store_justified_epoch: 5,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 2,
        unfinalized_block_count_in_fork: 4,
        unfinalized_block_count_total: 4,
    });
}

// 0
//  \
//   1
//   |\
//   2 3
//     |\
//     4 5
//     |\
//     6 \
//     |\ \
//     7 \ \
//        \ \
//         8 \
//         |  |
//         9 10
//            |
//           11
//            |\
//           12 |
//              |
//             13  block that gets finalized
//              |
//             14  block with attestations justifying block 13
//              |
//             15  block with attestations finalizing block 13
//              |
//             16  block that causes attestations added by block 15 to be processed
//
// - 1 2 3 4  5 6  segments
//
// Block 0 is not in any segment because it's the genesis block.
#[test]
fn finalizes_and_prunes_many_segments_correctly() {
    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.empty_block(&state_1, 2, H256::repeat_byte(0));
    let (block_3, state_3) = context.empty_block(&state_1, 2, H256::repeat_byte(1));
    let (block_4, state_4) = context.empty_block(&state_3, 3, H256::repeat_byte(0));
    let (block_5, _) = context.empty_block(&state_3, 3, H256::repeat_byte(1));
    let (block_6, state_6) = context.empty_block(&state_4, 4, H256::repeat_byte(0));
    let (block_7, _) = context.empty_block(&state_6, 5, H256::repeat_byte(0));
    let (block_8, state_8) = context.empty_block(&state_6, 5, H256::repeat_byte(1));
    let (block_9, _) = context.empty_block(&state_8, 6, H256::default());
    let (block_10, state_10) = context.empty_block(&state_4, 6, H256::repeat_byte(2));
    let (block_11, state_11) = context.empty_block(&state_10, 7, H256::default());
    let (block_12, _) = context.empty_block(&state_11, 8, H256::repeat_byte(0));
    let (block_13, state_13) =
        context.empty_block(&state_11, start_of_epoch(2), H256::repeat_byte(2));
    let (block_14, state_14) =
        context.block_justifying_current_epoch(&state_13, 2, H256::default());
    let (block_15, state_15) =
        context.block_justifying_current_epoch(&state_14, 3, H256::default());
    let (block_16, _) = context.empty_block(&state_15, start_of_epoch(4), H256::default());

    assert!(block_2.message().hash_tree_root() < block_3.message().hash_tree_root());
    assert!(block_4.message().hash_tree_root() > block_5.message().hash_tree_root());
    assert!(block_6.message().hash_tree_root() < block_10.message().hash_tree_root());
    assert_ne!(
        block_7.message().hash_tree_root(),
        block_8.message().hash_tree_root(),
    );
    assert!(block_12.message().hash_tree_root() < block_13.message().hash_tree_root());

    context.on_slot(start_of_epoch(4));

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);
    context.on_acceptable_block(&block_5);
    context.on_acceptable_block(&block_6);
    context.on_acceptable_block(&block_7);
    context.on_acceptable_block(&block_8);
    context.on_acceptable_block(&block_9);
    context.on_acceptable_block(&block_10);
    context.on_acceptable_block(&block_11);
    context.on_acceptable_block(&block_12);
    context.on_acceptable_block(&block_13);

    context.assert_status(Status {
        head: &block_13,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 6,
        fork_count_total: 6,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 6,
        unfinalized_block_count_total: 13,
    });

    context.on_acceptable_block(&block_14);

    context.assert_status(Status {
        head: &block_14,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 6,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 7,
        unfinalized_block_count_total: 14,
    });

    context.on_acceptable_block(&block_15);

    context.assert_status(Status {
        head: &block_15,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 7,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_16);

    context.assert_status(Status {
        head: &block_16,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 7,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });
}

// This covers a bug we found in `Store::unload_old_states` while implementing in-memory mode.
// The bug would cause blocks to become anchors while having unloaded post-states, making it
// impossible to access their post-states or compute the post-states of their descendants.
//
// ```text
// | epoch 0| epoch 1| epoch 2| epoch 3| epoch 4|
// |□-------|--------|□------▣|-------▣|□-------|
// |0       |        |1      2|       3|4       |
// ```
//
// | symbol | meaning                                            |
// | :----: | -------------------------------------------------- |
// | □      | block without attestations                         |
// | ▣      | block with enough attestations to justify an epoch |
// | -      | slot that may contain a block                      |
//
// Block 1 becomes justified after processing block 3 (or block 2 with unrealized justification).
// Block 1 becomes the anchor after processing block 4 (or block 3 with unrealized justification).
// Before the fix, its post-state could be unloaded after block 2 became the justified block.
//
// Block 2 delivers attestations that justify block 1.
// Block 2 becomes justified after processing block 4 (or block 3 with unrealized justification).
// Before the fix, block 2 becoming justified would leave block 1 unprotected from unloading.
//
// Block 3 triggers epoch processing that justifies block 1.
// Block 3 delivers attestations that justify block 2 and finalize block 1.
//
// Block 4 triggers epoch processing that justifies block 2 and finalizes block 1.
// Block 4 causes the post-state of block 1 to be unloaded from memory.
// Block 4 causes block 0 to be archived, making block 1 the anchor.
//
// Block 4 is not strictly necessary due to unrealized justification.
// However, unrealized justification is a recent addition.
// It was not present in historical designs of the consensus layer that are commonly taught.
// Other specifications do not use it, though Lighthouse seems to use it at the p2p level.
#[test]
fn does_not_unload_states_that_may_become_anchors() {
    let mut context = Context::bellatrix_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, start_of_epoch(2), H256::default());
    let (block_2, state_2) = context.block_justifying_current_epoch(&state_1, 2, H256::default());
    let (block_3, state_3) = context.block_justifying_current_epoch(&state_2, 3, H256::default());
    let (block_4, _) = context.empty_block(&state_3, start_of_epoch(4), H256::default());

    assert!(
        is_at_start_of_epoch(&block_1),
        "block 1 must be at the start of an epoch to become the anchor",
    );
    assert!(
        GENESIS_EPOCH + 1 < epoch_at_slot(block_2.message().slot()),
        "block 2 must be in epoch 2 or later to have its attestations processed",
    );
    assert!(
        GENESIS_EPOCH + 1 < epoch_at_slot(block_3.message().slot()),
        "block 3 must be in epoch 2 or later to have its attestations processed",
    );
    assert!(
        epoch_at_slot(block_2.message().slot()) < epoch_at_slot(block_3.message().slot()),
        "block 3 must be in an epoch after block 2 to trigger epoch processing",
    );
    assert!(
        epoch_at_slot(block_3.message().slot()) < epoch_at_slot(block_4.message().slot()),
        "block 4 must be in an epoch after block 3 to trigger epoch processing",
    );
    assert!(
        is_at_start_of_epoch(&block_4),
        "block 4 must be at the start of an epoch to trigger unloading",
    );
    assert!(
        block_4.message().slot() - block_1.message().slot()
            >= context.unfinalized_states_in_memory(),
        "block 1 and block 4 must be sufficiently far apart to unload the post-state of block 1",
    );

    context.on_slot(block_4.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);

    assert_eq!(context.anchor_state(), state_1);
    assert_eq!(context.last_finalized_state(), state_1);
    assert_eq!(context.justified_state(), state_2);
}

// 0
//  \
//   \
//   |\
//   1 2
//     |\
//     3 |
//       |
//       4  block that gets finalized
//       |
//       5  block with attestations justifying block 4
//       |
//       6  block with attestations finalizing block 4
//       |
//       7  block that causes attestations added by block 6 to be processed
//
// - 1 2 3  segments
//
// This test was added to reproduce a bug we encountered while testing in Pyrmont.
// It was caused by a block just like block 3 being pruned incorrectly, leading to a panic in
// `Store::propagate_and_dissolve_differences` later, when processing attestations found in a block.
//
// When block 4 is finalized, both segment 1 and segment 2 should be removed.
// Segment 1 should be pruned in its entirety.
// Segment 2 should be partially finalized and partially pruned.
#[test]
fn handles_attestations_for_previously_known_blocks() {
    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) = context.empty_block(&state_0, 2, H256::default());
    let (block_3, state_3) = context.empty_block(&state_2, 3, H256::default());
    let (block_4, state_4) = context.empty_block(&state_2, 4, H256::default());
    let (block_5, state_5) = context.block_justifying_current_epoch(&state_4, 2, H256::default());
    let (block_6, state_6) = context.block_justifying_current_epoch(&state_5, 3, H256::default());
    let (block_7, state_7) = context.empty_block(&state_6, start_of_epoch(4), H256::default());

    context.on_slot(start_of_epoch(2));

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);

    // The validators used here are picked from committees in the last slot of epoch 3. This is
    // needed to prevent attestations delivered in block 6 from overwriting the `LatestMessage`s
    // corresponding to the validators. Note that attestations in block 5 are not used for fork
    // choice because they're older than the previous epoch by the time block 5 is added.
    context.on_acceptable_singular_attestation(&state_1, 1, 1);
    context.on_acceptable_singular_attestation(&state_2, 1, 2);
    context.on_acceptable_singular_attestation(&state_3, 1, 4);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 3,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 4,
    });

    context.on_slot(start_of_epoch(4));

    context.on_acceptable_block(&block_5);
    context.on_acceptable_block(&block_6);
    context.on_acceptable_block(&block_7);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 3,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });

    context.on_slot(start_of_epoch(5));

    context.on_acceptable_singular_attestation(&state_7, 4, 1);
    context.on_acceptable_singular_attestation(&state_7, 4, 2);
    context.on_acceptable_singular_attestation(&state_7, 4, 4);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(3),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 3,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });
}

// We ignore attestations that vote for old blocks to prevent denial of service (malicious or not).
// The number of allowed empty slots is configurable through `max_empty_slots`.
// This is a deviation from the Fork Choice specification.
// Other implementations appear to do something similar.
// See <https://medium.com/offchainlabs/post-mortem-report-ethereum-mainnet-finality-05-11-2023-95e271dfd8b2>.
#[test]
fn ignores_attestations_that_vote_for_old_blocks() {
    let attestation_epoch = 5;
    let head_slot = misc::compute_start_slot_at_epoch::<Minimal>(attestation_epoch + 1);

    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.empty_block(&state_0, head_slot, H256::default());

    context.on_slot(start_of_epoch(attestation_epoch + 1));

    context.on_acceptable_block(&block_1);

    context.assert_forward_synced(false);

    context.on_ignorable_singular_attestation(&state_1, attestation_epoch, 0);

    context.on_acceptable_block(&block_2);

    context.assert_forward_synced(true);

    context.on_ignorable_singular_attestation(&state_1, attestation_epoch, 0);
}

// 0
//  \
//   1
//   |\
//   2 |
//     |
//     3  block with attestations justifying block 1
//     |
//     4  block that causes attestations added by block 3 to be processed
//
// - 1 2  segments
//
// This test was added to reproduce a bug we encountered while testing in Pyrmont.
// It was caused by an oversight in `Store::update_head_segment_id`.
//
// This could be done with just 1 block in segment 2 by delivering the attestations in block 1.
#[test]
fn non_viable_parent_segment_is_ignored_even_when_it_has_a_higher_score() {
    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) = context.empty_block(&state_1, start_of_epoch(1), H256::repeat_byte(0));
    let (block_3, state_3) =
        context.block_justifying_current_epoch(&state_1, 2, H256::repeat_byte(1));
    let (block_4, _) = context.empty_block(&state_3, start_of_epoch(3), H256::default());

    assert!(block_2.message().hash_tree_root() > block_3.message().hash_tree_root());

    context.on_slot(start_of_epoch(3));

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);

    context.on_acceptable_singular_attestation(&state_2, 2, 0);

    context.assert_status(Status {
        head: &block_4,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 4,
    });
}

//   0
//  / \
// |   2  block that gets finalized
// |   |
// |   3  block with attestations justifying block 2
// |   |
// 1   |  block that gets orphaned and added again
//     |
//     4  block with attestations finalizing block 2
//     |
//     5  block that causes attestations added by block 4 to be processed
//
// This test was added to reproduce a panic we encountered while testing in Pyrmont.
// `Store::validate_block` would accept orphaned blocks if their parents were finalized blocks.
// Combined with the lack of pruning for `Store.state_roots_to_block_roots` this led to a panic in
// `Store::insert_block` later, when inserting roots into `Store.state_roots_to_block_roots`.
#[test]
fn handles_orphan_block_that_was_previously_known() {
    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, _) = context.empty_block(&state_0, start_of_epoch(2) + 1, H256::default());
    let (block_2, state_2) = context.empty_block(&state_0, 2, H256::default());
    let (block_3, state_3) = context.block_justifying_current_epoch(&state_2, 2, H256::default());
    let (block_4, state_4) = context.block_justifying_current_epoch(&state_3, 3, H256::default());
    let (block_5, _) = context.empty_block(&state_4, start_of_epoch(4), H256::default());

    context.on_slot(start_of_epoch(4));

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_4);

    context.assert_status(Status {
        head: &block_4,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 2,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_5);

    context.assert_status(Status {
        head: &block_5,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 2,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });

    context.on_ignorable_block(&block_1);

    context.assert_status(Status {
        head: &block_5,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 2,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });
}

// Based on the test `ffg_case_01` from Lighthouse.
// The name is taken from Prysm. It's called `TestFFGUpdates_OneBranch` there.
//
// A chain with just 4 blocks cannot finalize epoch 1. The 2-block finalization rules
// (rule 2 and rule 4) require the previous checkpoint to have been finalized in its own epoch.
// However, `process_justification_and_finalization` is not run in epoch 1.
// We use finalization rule 4 to finalize epoch 2 instead.
// We could also finalize epoch 1 using finalization rule 3, but that would require 5 blocks.
#[test]
fn lighthouse_ffg_updates_one_branch() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.block_justifying_current_epoch(&state_0, 2, H256::default());
    let (block_2, state_2) = context.block_justifying_current_epoch(&state_1, 3, H256::default());
    let (block_3, _) = context.empty_block(&state_2, start_of_epoch(4), H256::default());

    context.on_slot(start_of_epoch(4));

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });
}

//   0
//  / \
// 1   2  blocks at the start of epoch 2,
// |   |  with attestations justifying block 0 in epoch 1
// |   |
// 7   8  blocks at the start of epoch 3,
// |   |  with attestations justifying blocks 1 and 2 in epoch 2
// |   |
// 9  10  blocks at the start of epoch 4,
//        causing attestations added by blocks 7 and 8 to be processed
//
// Based on the `ffg_case_02` test from Lighthouse.
// The name is taken from Prysm. It's called `TestFFGUpdates_TwoBranches` there.
//
// Blocks 3 to 6 in the original test serve no purpose and have been removed.
#[test]
fn lighthouse_ffg_updates_two_branches_starting_with_lower_in_a_future_slot() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_justifying_previous_epoch(&state_0, 2, H256::repeat_byte(0));
    let (block_2, state_2) =
        context.block_justifying_previous_epoch(&state_0, 2, H256::repeat_byte(2));
    let (block_7, state_7) = context.block_justifying_previous_epoch(&state_1, 3, H256::default());
    let (block_8, state_8) = context.block_justifying_previous_epoch(&state_2, 3, H256::default());
    let (block_9, _) = context.empty_block(&state_7, start_of_epoch(4), H256::default());
    let (block_10, _) = context.empty_block(&state_8, start_of_epoch(4), H256::default());

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());

    context.on_slot(start_of_epoch(4));

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 1,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 1,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_7);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_8);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 4,
    });

    context.on_acceptable_block(&block_9);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 5,
    });

    context.on_acceptable_block(&block_10);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 6,
    });
}

//   0
//  / \
// 1   2  blocks at the start of epoch 2,
// |   |  with attestations justifying block 0 in epoch 1
// |   |
// 7   8  blocks at the start of epoch 3,
// |   |  with attestations justifying blocks 1 and 2 in epoch 2
// |   |
// 9  10  blocks at the start of epoch 4,
//        causing attestations added by blocks 7 and 8 to be processed
//
// Based on the `ffg_case_02` test from Lighthouse.
// The name is taken from Prysm. It's called `TestFFGUpdates_TwoBranches` there.
//
// Blocks 3 to 6 in the original test serve no purpose and have been removed.
#[test]
fn lighthouse_ffg_updates_two_branches_starting_with_higher_in_a_future_slot() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_justifying_previous_epoch(&state_0, 2, H256::repeat_byte(0));
    let (block_2, state_2) =
        context.block_justifying_previous_epoch(&state_0, 2, H256::repeat_byte(2));
    let (block_7, state_7) = context.block_justifying_previous_epoch(&state_1, 3, H256::default());
    let (block_8, state_8) = context.block_justifying_previous_epoch(&state_2, 3, H256::default());
    let (block_9, _) = context.empty_block(&state_7, start_of_epoch(4), H256::default());
    let (block_10, _) = context.empty_block(&state_8, start_of_epoch(4), H256::default());

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());

    context.on_slot(start_of_epoch(4));

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 1,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 1,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_8);

    context.assert_status(Status {
        head: &block_8,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_7);

    context.assert_status(Status {
        head: &block_8,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 4,
    });

    context.on_acceptable_block(&block_10);

    context.assert_status(Status {
        head: &block_10,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 5,
    });

    context.on_acceptable_block(&block_9);

    context.assert_status(Status {
        head: &block_10,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 6,
    });
}

//   0
//  / \
// 1   2  blocks at the start of epoch 2,
// |   |  with attestations justifying block 0 in epoch 1
// |   |
// 7   8  blocks at the start of epoch 3,
// |   |  with attestations justifying blocks 1 and 2 in epoch 2
// |   |
// 9  10  blocks at the start of epoch 4,
//        causing attestations added by blocks 7 and 8 to be processed
//
// Based on the `ffg_case_02` test from Lighthouse.
// The name is taken from Prysm. It's called `TestFFGUpdates_TwoBranches` there.
//
// Blocks 3 to 6 in the original test serve no purpose and have been removed.
#[test]
fn lighthouse_ffg_updates_two_branches_starting_with_lower_in_real_time() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_justifying_previous_epoch(&state_0, 2, H256::repeat_byte(0));
    let (block_2, state_2) =
        context.block_justifying_previous_epoch(&state_0, 2, H256::repeat_byte(2));
    let (block_7, state_7) = context.block_justifying_previous_epoch(&state_1, 3, H256::default());
    let (block_8, state_8) = context.block_justifying_previous_epoch(&state_2, 3, H256::default());
    let (block_9, _) = context.empty_block(&state_7, start_of_epoch(4), H256::default());
    let (block_10, _) = context.empty_block(&state_8, start_of_epoch(4), H256::default());

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_slot(start_of_epoch(2));

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_slot(start_of_epoch(3));

    context.on_acceptable_block(&block_7);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(0),
        store_justified_epoch: 1,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_8);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(0),
        store_justified_epoch: 1,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 4,
    });

    context.on_slot(start_of_epoch(4));

    context.on_acceptable_block(&block_9);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 5,
    });

    context.on_acceptable_block(&block_10);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 6,
    });
}

// Based on the `no_votes` test from Lighthouse.
#[test]
fn lighthouse_no_votes() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) = context.empty_block(&state_0, 2, H256::default());
    let (block_3, _) = context.empty_block(&state_1, 3, H256::default());
    let (block_4, state_4) = context.block_justifying_current_epoch(&state_2, 2, H256::default());
    let (block_5, state_5) = context.empty_block(&state_4, start_of_epoch(3), H256::default());
    let (block_6, _) = context.empty_block(&state_5, start_of_epoch(3) + 1, H256::default());

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());

    context.on_slot(start_of_epoch(3) + 1);

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_4);

    context.assert_status(Status {
        head: &block_4,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 4,
    });

    context.on_acceptable_block(&block_5);

    context.assert_status(Status {
        head: &block_5,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 5,
    });

    context.on_acceptable_block(&block_6);

    context.assert_status(Status {
        head: &block_6,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 4,
        unfinalized_block_count_total: 6,
    });
}

// ```text
// 0
//  \
//   \
//   |\
//   | 1
//   | |
//   2 |
//     |
//     3
//     |
//     4
//     |\
//     5 |
//     | |
//     7 6
//     |
//     8
//     |\
//     | \
//     |  \
//     9  10
//     |
//     11
//     |
//     12
//
// - 1 2 3 4  segments
// ```
//
// Based on the `votes` test from Lighthouse.
//
// The test is quite a bit different from the original one because we cannot arbitrarily alter the
// validators' balances or set the justified and finalized epochs.
//
// We use block 5 to deliver the attestations justifying epoch 2 and block 6 to process them, unlike
// the original, which pretends to process them with block 5. It appears to be impossible to both
// justify epoch 2 with block 5 and finalize the chain up to exactly block 4. We use block 11 along
// with one not present in the original test (block 12) to finalize the chain up to block 4.
#[test]
fn lighthouse_votes() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) = context.empty_block(&state_0, 2, H256::default());
    let (block_3, state_3) = context.empty_block(&state_1, 3, H256::default());
    let (block_4, state_4) = context.empty_block(&state_3, 4, H256::default());
    let (block_5, state_5) =
        context.block_justifying_current_epoch(&state_4, 2, H256::repeat_byte(4));
    let (block_6, _) = context.empty_block(&state_4, start_of_epoch(3), H256::default());
    let (block_7, state_7) = context.empty_block(&state_5, start_of_epoch(3), H256::default());
    let (block_8, state_8) = context.empty_block(&state_7, start_of_epoch(3) + 1, H256::default());
    let (block_9, state_9) =
        context.empty_block(&state_8, start_of_epoch(3) + 2, H256::repeat_byte(1));
    let (block_10, state_10) =
        context.empty_block(&state_8, start_of_epoch(3) + 2, H256::repeat_byte(0));
    let (block_11, state_11) = context.block_justifying_current_epoch(&state_9, 3, H256::default());
    let (block_12, _) = context.empty_block(&state_11, start_of_epoch(4), H256::default());

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());
    assert!(block_5.message().hash_tree_root() < block_6.message().hash_tree_root());
    assert!(block_9.message().hash_tree_root() < block_10.message().hash_tree_root());

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });

    context.on_slot(start_of_epoch(1));

    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_singular_attestation(&state_1, 0, 0);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_singular_attestation(&state_2, 0, 1);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_slot(start_of_epoch(2));

    context.on_acceptable_singular_attestation(&state_3, 1, 0);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_singular_attestation(&state_3, 1, 1);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(2),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 3,
    });

    context.on_acceptable_block(&block_4);

    context.assert_status(Status {
        head: &block_4,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 4,
    });

    context.on_slot(start_of_epoch(3));

    context.on_acceptable_block(&block_5);

    context.assert_status(Status {
        head: &block_5,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 4,
        unfinalized_block_count_total: 5,
    });

    context.on_acceptable_block(&block_6);

    context.assert_status(Status {
        head: &block_5,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 4,
        unfinalized_block_count_total: 6,
    });

    context.on_slot(start_of_epoch(4));

    context.on_acceptable_singular_attestation(&state_5, 3, 0);
    context.on_acceptable_singular_attestation(&state_5, 3, 1);

    context.assert_status(Status {
        head: &block_5,
        attesting_validators: Some(2),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 4,
        unfinalized_block_count_total: 6,
    });

    context.on_acceptable_block(&block_7);

    context.assert_status(Status {
        head: &block_7,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 5,
        unfinalized_block_count_total: 7,
    });

    context.on_acceptable_block(&block_8);
    context.on_acceptable_block(&block_9);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 7,
        unfinalized_block_count_total: 9,
    });

    context.on_slot(start_of_epoch(5));

    context.on_acceptable_singular_attestation(&state_9, 4, 0);
    context.on_acceptable_singular_attestation(&state_9, 4, 1);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(2),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 7,
        unfinalized_block_count_total: 9,
    });

    context.on_acceptable_block(&block_10);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(2),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 4,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 7,
        unfinalized_block_count_total: 10,
    });

    context.on_acceptable_singular_attestation(&state_10, 4, 2);
    context.on_acceptable_singular_attestation(&state_10, 4, 3);

    context.assert_status(Status {
        head: &block_10,
        attesting_validators: Some(2),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 4,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 7,
        unfinalized_block_count_total: 10,
    });

    context.on_acceptable_singular_attestation(&state_9, 4, 4);
    context.on_acceptable_singular_attestation(&state_9, 4, 5);

    context.assert_status(Status {
        head: &block_9,
        attesting_validators: Some(4),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 4,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 7,
        unfinalized_block_count_total: 10,
    });

    context.on_acceptable_block(&block_11);

    context.assert_status(Status {
        head: &block_11,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 4,
        unfinalized_block_count_in_fork: 5,
        unfinalized_block_count_total: 7,
    });

    context.on_acceptable_block(&block_12);

    context.assert_status(Status {
        head: &block_12,
        attesting_validators: Some(0),
        store_justified_epoch: 3,
        store_finalized_epoch: 2,
        fork_count_viable: 1,
        fork_count_total: 3,
        finalized_block_count: 4,
        unfinalized_block_count_in_fork: 6,
        unfinalized_block_count_total: 8,
    });
}

// This was added to reproduce an off-by-one bug in `Segment::iter_up_to`.
#[test]
fn controller_blocks_by_range_can_access_all_blocks_in_a_segment() {
    let mut context = Context::minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, _) = context.empty_block(&state_0, 1, H256::default());

    context.on_slot(block_1.message().slot());

    context.on_acceptable_block(&block_1);

    let expected_blocks = [block_0, block_1];

    let actual_blocks = context
        .stored_blocks_by_range(GENESIS_SLOT..u64::MAX)
        .expect("arguments passed to stored_blocks_by_range are valid")
        .into_iter()
        .map(|block_with_root| match block_with_root.block {
            StoredBlock::Full(block) => block,
            StoredBlock::Blinded(_) => panic!("blocks in the fork choice store are never blinded"),
        });

    itertools::assert_equal(actual_blocks, expected_blocks);
}

#[test]
fn head_falls_back_to_previous_block_if_last_block_of_single_fork_is_invalidated() {
    let mut context = Context::bellatrix_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));

    context.on_slot(block_2.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 2,
    });

    context.on_notified_invalid_payload(&block_2, None);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });
}

#[test]
fn head_falls_back_to_justified_block_if_every_segment_is_invalidated() {
    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, _) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));

    context.on_slot(block_1.message().slot());

    context.on_acceptable_block(&block_1);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_notified_invalid_payload(&block_1, None);

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });
}

// The [Optimistic Sync specification] says:
// > When a block transitions from `NOT_VALIDATED` -> `VALID`,
// > all *ancestors* of the block MUST also transition from `NOT_VALIDATED` -> `VALID`.
//
// [Optimistic Sync specification]: https://github.com/ethereum/consensus-specs/blob/a1e46d1ae47dd9d097725801575b46907c12a1f8/sync/optimistic.md#how-to-optimistically-import-blocks
#[test]
fn confirming_a_block_confirms_its_ancestors() {
    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_2, state_2) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));
    let (block_3, _) =
        context.block_with_payload(&state_2, 3, H256::default(), H256::repeat_byte(3));

    let status = Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    };

    context.on_slot(block_3.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_status(status);
    context.assert_payload_status(&block_0, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Optimistic));

    context.on_notified_valid_payload(&block_2);

    context.assert_status(status);
    context.assert_payload_status(&block_0, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Optimistic));
}

// The [Optimistic Sync specification] says:
// > When a block transitions from `NOT_VALIDATED` -> `INVALIDATED`,
// > all *descendants* of the block MUST also transition from `NOT_VALIDATED` -> `INVALIDATED`.
//
// [Optimistic Sync specification]: https://github.com/ethereum/consensus-specs/blob/a1e46d1ae47dd9d097725801575b46907c12a1f8/sync/optimistic.md#how-to-optimistically-import-blocks
#[test]
fn invalidating_a_block_invalidates_its_descendants() {
    let mut context = Context::bellatrix_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_2, state_2) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));
    let (block_3, _) =
        context.block_with_payload(&state_2, 3, H256::default(), H256::repeat_byte(3));

    context.on_slot(block_3.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });

    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Optimistic));

    context.on_notified_invalid_payload(&block_2, None);

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Invalid));
}

// ```text
// 0
//  \
//   1      latest_valid_hash
//   |\
//   2 \    first invalid block
//   |\ \
//   3 | |  execution_block_hash
//     | |
//     4 |  block in another fork that should also be invalidated
//       |
//       5  block whose payload status should remain unknown
//
// - 1 2 3  segments
// ```
//
// See the following for how to determine the first invalid block:
// - [Optimistic Sync specification]
// - [Engine API specification]
//
// [Optimistic Sync specification]: https://github.com/ethereum/consensus-specs/blob/a1e46d1ae47dd9d097725801575b46907c12a1f8/sync/optimistic.md#how-to-apply-latestvalidhash-when-payload-status-is-invalid
// [Engine API specification]:      https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#payload-validation
#[test]
fn all_descendants_of_first_invalid_block_are_invalidated() {
    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_2, state_2) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));
    let (block_3, _) =
        context.block_with_payload(&state_2, 3, H256::default(), H256::repeat_byte(3));
    let (block_4, _) =
        context.block_with_payload(&state_2, 4, H256::default(), H256::repeat_byte(4));
    let (block_5, _) =
        context.block_with_payload(&state_1, 5, H256::default(), H256::repeat_byte(5));

    context.on_slot(block_5.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);
    context.on_acceptable_block(&block_5);

    context.assert_payload_status(&block_0, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_4, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_5, Some(PayloadStatus::Optimistic));

    context.on_notified_invalid_payload(&block_3, Some(&block_1));

    context.assert_payload_status(&block_0, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_4, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_5, Some(PayloadStatus::Optimistic));
}

// The execution engine syncs and only learns at `engine_forkchoiceUpdated` that 3 is invalid.
// The verdict must invalidate it the same way `engine_newPayload` would.
#[test]
fn forkchoice_updated_invalid_verdict_invalidates_payloads_after_latest_valid_hash() {
    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_2, state_2) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));
    let (block_3, _) =
        context.block_with_payload(&state_2, 3, H256::default(), H256::repeat_byte(3));

    context.on_slot(block_3.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_head(3, block_3.message().hash_tree_root());
    context.assert_head_optimistic(true);

    context.on_notified_invalid_fork_choice_update(&block_3, Some(&block_1));

    context.assert_payload_status(&block_0, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Invalid));
    context.assert_head(1, block_1.message().hash_tree_root());
}

// No `latest_valid_hash` means only the head payload is known to be invalid.
#[test]
fn forkchoice_updated_invalid_verdict_without_latest_valid_hash_invalidates_head() {
    let mut context = Context::bellatrix_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));

    context.on_slot(block_2.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);

    context.assert_head(2, block_2.message().hash_tree_root());

    context.on_notified_invalid_fork_choice_update(&block_2, None);

    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
    context.assert_head(1, block_1.message().hash_tree_root());
}

// ```text
// 0
//  \
//   1    latest_valid_hash (0x00…00)
//   |\
//   2 |  merge transition block whose payload status is unknown
//     |
//     3  merge transition block whose payload is invalid
//     |
//     4  execution_block_hash
//
// - 1 2  segments
// ```
//
// See the following for how to determine the first invalid block:
// - [Optimistic Sync specification]
// - [Engine API specification]
//
// [Optimistic Sync specification]: https://github.com/ethereum/consensus-specs/blob/a1e46d1ae47dd9d097725801575b46907c12a1f8/sync/optimistic.md#how-to-apply-latestvalidhash-when-payload-status-is-invalid
// [Engine API specification]:      https://github.com/ethereum/execution-apis/blob/b7c5d3420e00648f456744d121ffbd929862924d/src/engine/paris.md#payload-validation
#[test]
fn payload_statuses_are_updated_if_latest_valid_hash_is_all_zeros() {
    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));
    let (block_3, state_3) =
        context.block_with_payload(&state_1, 3, H256::default(), H256::repeat_byte(3));
    let (block_4, _) =
        context.block_with_payload(&state_3, 4, H256::default(), H256::repeat_byte(4));

    context.on_slot(block_4.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_acceptable_block(&block_4);

    context.assert_payload_status(&block_0, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_4, Some(PayloadStatus::Optimistic));

    context.on_notified_invalid_payload(&block_4, Some(&block_1));

    context.assert_payload_status(&block_0, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_4, Some(PayloadStatus::Invalid));
}

#[test]
fn new_descendants_of_an_invalidated_block_are_immediately_invalidated() {
    let mut context = Context::bellatrix_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_2, _) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));

    context.on_slot(block_2.message().slot());

    context.on_acceptable_block(&block_1);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_2, None);

    context.on_notified_invalid_payload(&block_1, None);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_2, None);

    context.on_ignorable_block(&block_2);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
}

// This was originally based on [`NoViableHeadDueToOptimisticSync`] in Hive.
// See [Hive pull request #637] for more information.
//
// Not restoring checkpoints is arguably a bug, but doing it correctly may be impossible.
// The [Optimistic Sync specification] treats this as an acceptable limitation. A more appropriate
// solution would be to never set the checkpoints to optimistic values and not expose the optimistic
// head, but that would break compatibility with Hive and the [Eth Beacon Node API specification].
//
// Note that the block that gets invalidated is not the justified block.
// The block justified between epochs 2 and 3 is the genesis block.
// The invalidated block is the one that delivers the attestations to justify it.
// Starting with `consensus-specs` version 1.3.0-rc.4, it also produces a new unrealized checkpoint.
//
// This version of the test should pass both before and after `consensus-specs` version 1.3.0-rc.4.
// Before version 1.3.0-rc.4, block 1 is not needed but block 3 is.
// Starting with version 1.3.0-rc.4, block 3 is no longer needed, but the store must be in epoch 3.
//
// Block 1 is in slot 17 to prevent it from being justified.
// The store is left without viable forks either way,
// but it's harder to tell if block 1 is justified.
//
// [`NoViableHeadDueToOptimisticSync`]: https://github.com/ethereum/hive/blob/53be3f712d23c7f56a4865848b73230341ed4fce/simulators/eth2/engine/scenarios.go#L1777-L2038
// [Hive pull request #637]:            https://github.com/ethereum/hive/pull/637
// [Optimistic Sync specification]:     https://github.com/ethereum/consensus-specs/blob/a1e46d1ae47dd9d097725801575b46907c12a1f8/sync/optimistic.md#helpers
// [Eth Beacon Node API specification]: https://github.com/ethereum/beacon-APIs/tree/94105bbb1fd35b54eb531d47f9498b8ccf3d17aa
#[test]
fn invalidating_a_block_does_not_restore_checkpoints_and_can_leave_all_forks_unviable() {
    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, start_of_epoch(2) + 1, H256::default());
    let (block_2, state_2) = context.block_with_payload_justifying_current_epoch(
        &state_1,
        2,
        H256::default(),
        H256::repeat_byte(1),
    );
    let (block_3, _) = context.block_with_payload(
        &state_2,
        start_of_epoch(3),
        H256::default(),
        H256::repeat_byte(2),
    );

    context.on_slot(block_3.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 3,
        unfinalized_block_count_total: 3,
    });

    context.on_notified_invalid_payload(&block_2, None);

    // There is some disagreement on what the head should be when all forks are non-viable.
    // A strict interpretation of `consensus-specs` is that it should be the justified block.
    // <https://github.com/ethereum/hive/pull/637#issuecomment-1219219657> claims otherwise.
    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 2,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 1,
    });
}

#[test]
fn blocks_after_the_merge_are_optimistic_until_confirmation() {
    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_2, _) =
        context.block_with_payload(&state_1, 2, H256::default(), H256::repeat_byte(2));

    context.on_slot(block_2.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);

    context.assert_optimistic(&block_0, false);
    context.assert_optimistic(&block_1, true);
    context.assert_optimistic(&block_2, true);

    context.on_notified_valid_payload(&block_1);

    context.assert_optimistic(&block_0, false);
    context.assert_optimistic(&block_1, false);
    context.assert_optimistic(&block_2, true);

    context.on_notified_valid_payload(&block_2);

    context.assert_optimistic(&block_0, false);
    context.assert_optimistic(&block_1, false);
    context.assert_optimistic(&block_2, false);
}

#[test]
fn reorganizing_due_to_invalidation_sends_notifications_if_common_ancestor_is_finalized() {
    let graffiti = H256::repeat_byte(0);

    let mut context = Context::bellatrix_minimal();

    let (block_0, state_0) = context.genesis();
    let (block_1, _) = context.block_with_payload(&state_0, 1, graffiti, H256::repeat_byte(1));
    let (block_2, _) = context.block_with_payload(&state_0, 2, graffiti, H256::repeat_byte(2));

    assert!(block_1.message().hash_tree_root() < block_2.message().hash_tree_root());

    context.on_slot(block_2.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);

    context.assert_head_notification_sent();

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 2,
    });

    context.on_notified_invalid_payload(&block_2, None);

    context.assert_head_notification_sent();

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });

    context.on_notified_invalid_payload(&block_1, None);

    context.assert_head_notification_sent();

    context.assert_status(Status {
        head: &block_0,
        attesting_validators: None,
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 0,
        unfinalized_block_count_total: 0,
    });
}

#[test]
fn reorganizing_due_to_invalidation_sends_notifications_if_common_ancestor_is_unfinalized() {
    let graffiti = H256::repeat_byte(6);

    let mut context = Context::bellatrix_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.block_with_payload(&state_1, 2, graffiti, H256::repeat_byte(2));
    let (block_3, _) = context.block_with_payload(&state_1, 3, graffiti, H256::repeat_byte(3));

    assert!(block_2.message().hash_tree_root() < block_3.message().hash_tree_root());

    context.on_slot(block_3.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_head_notification_sent();

    context.assert_status(Status {
        head: &block_3,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 2,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 3,
    });

    context.on_notified_invalid_payload(&block_3, None);

    context.assert_head_notification_sent();

    context.assert_status(Status {
        head: &block_2,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 2,
        unfinalized_block_count_total: 2,
    });

    context.on_notified_invalid_payload(&block_2, None);

    context.assert_head_notification_sent();

    context.assert_status(Status {
        head: &block_1,
        attesting_validators: Some(0),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 2,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    });
}

#[test]
fn gloas_genesis_accepts_blocks_built_on_it() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.empty_block(&state_1, 2, H256::default());

    context.on_slot(block_2.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_2);
}

// ```text
//   1  R, the head
//  /
// 0
//  \
//   15 S
// ```
//
// Validator 0 votes R in epoch 1, S in epoch 2 and R again in epoch 3.
// The epoch 3 vote arrives before the epoch 2 one.
// The repeated vote for R moves no weight, but it still makes the epoch 2 vote stale.
// The head must not depend on delivery order.
#[test]
fn repeated_vote_for_same_root_makes_older_votes_stale() {
    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_r, state_r) = context.empty_block(&state_0, 1, H256::default());
    let (block_s, state_s) = context.empty_block(&state_0, 15, H256::default());

    context.on_slot(block_s.message().slot());
    context.on_acceptable_block(&block_r);
    context.on_acceptable_block(&block_s);

    context.on_slot(20);
    context.on_acceptable_singular_attestation(&state_r, 1, 0);
    context.assert_head(1, block_r.message().hash_tree_root());

    context.on_slot(30);
    context.on_acceptable_singular_attestation(&state_r, 3, 0);
    context.on_acceptable_singular_attestation(&state_s, 2, 0);
    context.assert_head(1, block_r.message().hash_tree_root());
}

// The same slashing arrives twice, e.g. via gossip and then in a block.
// The slashed validator's vote must be removed once, not once per copy.
#[test]
fn repeated_attester_slashing_removes_vote_once() {
    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());

    context.on_slot(block_1.message().slot());
    context.on_acceptable_block(&block_1);

    context.on_slot(start_of_epoch(2));
    context.on_acceptable_singular_attestation(&state_1, 1, 0);
    context.on_acceptable_singular_attestation(&state_1, 1, 1);

    let attestation_data = |beacon_block_root| AttestationData {
        beacon_block_root,
        target: Checkpoint {
            epoch: 1,
            ..Checkpoint::default()
        },
        ..AttestationData::default()
    };

    let indexed_attestation = |beacon_block_root| IndexedAttestation {
        attesting_indices: [0].try_into().expect("length is under maximum"),
        data: attestation_data(beacon_block_root),
        ..IndexedAttestation::default()
    };

    let attester_slashing = Phase0AttesterSlashing {
        attestation_1: indexed_attestation(H256::repeat_byte(1)),
        attestation_2: indexed_attestation(H256::repeat_byte(2)),
    };

    let expected_status = || Status {
        head: &block_1,
        attesting_validators: Some(1),
        store_justified_epoch: 0,
        store_finalized_epoch: 0,
        fork_count_viable: 1,
        fork_count_total: 1,
        finalized_block_count: 1,
        unfinalized_block_count_in_fork: 1,
        unfinalized_block_count_total: 1,
    };

    context.on_test_attester_slashing(attester_slashing.clone().into(), BlsSetting::Ignored);
    context.assert_status(expected_status());

    context.on_test_attester_slashing(attester_slashing.into(), BlsSetting::Ignored);
    context.assert_status(expected_status());
}

// ```text
// 0 - 1 - 2
// ```
//
// A block root does not cover the signature.
// Anyone can rewrap 1 with a bad signature and send it first.
// That copy is rejected, but it says nothing about the genuine 1.
// 2 arrives before the genuine 1 and must wait for it, not be rejected.
#[test]
fn block_with_invalid_signature_does_not_condemn_its_root() {
    let mut context = Context::minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.empty_block(&state_1, 2, H256::default());

    let (message_1, _) = block_1.as_ref().clone().split();
    let forged_block_1 = Arc::new(message_1.with_zero_signature());

    context.on_slot(block_2.message().slot());

    context.on_block_with_invalid_signature(&forged_block_1);
    context.on_block_with_unknown_parent(&block_2);
    context.on_acceptable_block(&block_1);
    context.assert_delayed_block_accepted();

    context.assert_head(2, block_2.message().hash_tree_root());
}

// Post-Gloas the execution engine judges a block's payload, not the block.
// The tests below check that a rejected payload only takes down what builds on it.
//
// Notation in the diagrams:
// - `-e-` child builds on the parent's empty node (skips the payload).
// - `-f-` child builds on the parent's full node (extends the payload).

// ```text
// 0 -e- 1 -e- 2
// ```
//
// Payload of 1 is rejected.
// 1 survives as an empty node. 2 never touched the payload, so it survives too.
#[test]
fn gloas_invalid_payload_spares_block_and_children_on_empty_node() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.empty_block(&state_1, 2, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    context.on_slot(block_2.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);
    context.on_acceptable_block(&block_2);

    context.assert_head(2, block_2.message().hash_tree_root());

    context.on_notified_invalid_payload(&block_1, None);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Valid));
    context.assert_head(2, block_2.message().hash_tree_root());
}

// ```text
// 0 -e- 1 -f- 2 -e- 3
// ```
//
// Payload of 1 is rejected.
// 2 extends that payload, so 2 is dead.
// 3 skips 2's payload but still builds on dead 2, so 3 is dead too.
// Head falls back to 1, and it has to be the empty node.
#[test]
fn gloas_invalid_payload_kills_children_on_full_node_and_their_descendants() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) =
        context.empty_block_extending_parent_payload(&state_1, 2, H256::default());
    let (block_3, _) = context.empty_block(&state_2, 3, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    context.on_slot(block_3.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_head(3, block_3.message().hash_tree_root());

    context.on_notified_invalid_payload(&block_1, None);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Invalid));
    context.assert_head(1, block_1.message().hash_tree_root());
    context.assert_head_payload_status(PAYLOAD_STATUS_EMPTY);
}

// ```text
// 0 -e- 1 -f- 2 -e- 3
// ```
//
// Same chain as above, but the rejection comes from `engine_forkchoiceUpdated`.
// Head 3 skips 2's payload, so the head payload sent is 1's.
// The verdict must find 1 by that payload and take down 2 and 3.
#[test]
fn gloas_forkchoice_updated_invalid_verdict_invalidates_the_block_carrying_the_head_payload() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) =
        context.empty_block_extending_parent_payload(&state_1, 2, H256::default());
    let (block_3, _) = context.empty_block(&state_2, 3, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    context.on_slot(block_3.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_head(3, block_3.message().hash_tree_root());

    context.on_notified_invalid_fork_choice_update(&block_1, None);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Invalid));
    context.assert_head(1, block_1.message().hash_tree_root());
    context.assert_head_payload_status(PAYLOAD_STATUS_EMPTY);
}

// ```text
// 0 -e- 1
// ```
//
// The execution engine rejects 1's payload after its envelope is applied.
// 1 stays in fork choice on its empty node.
// A vote saying 1's payload is present must be rejected.
#[test]
fn gloas_rejects_attestation_for_invalid_payload() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    context.on_slot(block_1.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);
    context.on_notified_invalid_payload(&block_1, None);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Invalid));
    context.assert_head(1, block_1.message().hash_tree_root());

    context.on_slot(16);
    context.on_rejectable_singular_attestation_for_payload(&state_1, 1, 0);
    context.on_acceptable_singular_attestation(&state_1, 1, 1);
}

// Same chain, but the payload is valid. The same vote is accepted.
#[test]
fn gloas_accepts_attestation_for_valid_payload() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    context.on_slot(block_1.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);

    context.on_slot(16);
    context.on_acceptable_singular_attestation_for_payload(&state_1, 1, 0);
}

// ```text
//       f- 2
//      /
// 0 -e- 1
//      \
//       e- 3
// ```
//
// Payload of 1 is rejected.
// The branch on the full node dies. The branch on the empty node takes over.
#[test]
fn gloas_invalid_payload_switches_head_to_sibling_on_empty_node() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.empty_block_extending_parent_payload(&state_1, 2, H256::default());
    let (block_3, _) = context.empty_block(&state_1, 3, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    context.on_slot(block_3.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.on_notified_invalid_payload(&block_1, None);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Valid));
    context.assert_head(3, block_3.message().hash_tree_root());
}

// ```text
// 0 -e- 1 -f- 2 -e- 4
//       |
//       e- 3
// ```
//
// Payload of 1 is rejected before 2, 3 and 4 arrive.
// Late blocks must get the same verdict as if they had been there all along.
// Dead ones are stored but ignored on gossip, same as pre-Gloas.
#[test]
fn gloas_new_descendants_of_invalid_payload_inherit_the_right_status() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) =
        context.empty_block_extending_parent_payload(&state_1, 2, H256::default());
    let (block_3, _) = context.empty_block(&state_1, 3, H256::default());
    let (block_4, _) = context.empty_block(&state_2, 4, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    context.on_slot(block_4.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);

    context.on_notified_invalid_payload(&block_1, None);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Invalid));

    context.on_ignorable_block(&block_2);
    context.on_acceptable_block(&block_3);
    context.on_ignorable_block(&block_4);

    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_4, Some(PayloadStatus::Invalid));
    context.assert_head(3, block_3.message().hash_tree_root());
}

// ```text
// 0 --- 1 ===== 8 -e- 9
// ```
//
// 1 is pre-Gloas and optimistic. 8 is the first Gloas block. 8 and 9 inherit the optimistic status.
// 8's payload is validated. That proves 1 too.
// 9 skips 8's payload, has none of its own, and builds on a validated chain, so it is valid too.
#[test]
fn gloas_blocks_without_payload_become_valid_when_chain_they_build_on_is_validated() {
    let mut context = Context::gloas_at_epoch_1_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_8, state_8) = context.empty_block(&state_1, 8, H256::default());
    let (block_9, _) = context.empty_block(&state_8, 9, H256::default());

    assert_eq!(block_1.phase(), Phase::Fulu);
    assert_eq!(block_8.phase(), Phase::Gloas);

    let envelope_8 = context.execution_payload_envelope(&block_8, &state_8);

    context.on_slot(block_9.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_8);
    context.on_valid_execution_payload(&envelope_8, BlsSetting::Required);
    context.on_acceptable_block(&block_9);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_8, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_9, Some(PayloadStatus::Optimistic));

    context.on_notified_valid_payload(&block_8);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_8, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_9, Some(PayloadStatus::Valid));
}

// ```text
// 0 --- 1 ===== 8 -e- 9
// ```
//
// 1 is pre-Gloas and optimistic. 8 is the first Gloas block.
// 8's payload is delivered but the execution engine has not ruled on it.
// 1's payload is validated.
// 8 waits for its own verdict. 9 skips 8's payload, so it rests on 1 and is valid.
#[test]
fn gloas_block_on_empty_node_of_unvalidated_payload_becomes_valid_with_payload_below() {
    let mut context = Context::gloas_at_epoch_1_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_8, state_8) = context.empty_block(&state_1, 8, H256::default());
    let (block_9, _) = context.empty_block(&state_8, 9, H256::default());

    let envelope_8 = context.execution_payload_envelope(&block_8, &state_8);

    context.on_slot(block_9.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_8);
    context.on_valid_execution_payload(&envelope_8, BlsSetting::Required);
    context.on_acceptable_block(&block_9);

    context.on_notified_valid_payload(&block_1);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_8, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_9, Some(PayloadStatus::Valid));
}

// ```text
// 0 --- 1 ===== 8 -f- 9
// ```
//
// Same as above, but 9 builds on 8's payload.
// 8's payload is still unvalidated, so 9 must stay optimistic.
#[test]
fn gloas_block_on_full_node_of_unvalidated_payload_stays_optimistic() {
    let mut context = Context::gloas_at_epoch_1_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_8, state_8) = context.empty_block(&state_1, 8, H256::default());
    let (block_9, _) = context.empty_block_extending_parent_payload(&state_8, 9, H256::default());

    let envelope_8 = context.execution_payload_envelope(&block_8, &state_8);

    context.on_slot(block_9.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_acceptable_block(&block_8);
    context.on_valid_execution_payload(&envelope_8, BlsSetting::Required);
    context.on_acceptable_block(&block_9);

    context.on_notified_valid_payload(&block_1);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_8, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_9, Some(PayloadStatus::Optimistic));

    context.on_notified_valid_payload(&block_8);

    context.assert_payload_status(&block_8, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_9, Some(PayloadStatus::Valid));
}

// ```text
//       f- 2
//      /
// 0 -e- 1
//      \
//       e- 3
// ```
//
// 1 inherits a valid status from genesis before its payload arrives.
// That status says nothing about 1's own payload.
// Once the payload is delivered, 1 waits for the execution engine's verdict.
// 2 builds on that payload and waits too. 3 skips it and stays valid.
#[test]
fn gloas_delivered_payload_is_optimistic_until_validated() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.empty_block_extending_parent_payload(&state_1, 2, H256::default());
    let (block_3, _) = context.empty_block(&state_1, 3, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    context.on_slot(block_3.message().slot());

    context.on_acceptable_block(&block_1);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));

    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);
    context.on_acceptable_block(&block_2);
    context.on_acceptable_block(&block_3);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Valid));

    // Duties on 1's empty node do not depend on its payload.
    context.assert_node_payload_status(&block_1, true, Some(PayloadStatus::Optimistic));
    context.assert_node_payload_status(&block_1, false, Some(PayloadStatus::Valid));

    context.on_notified_valid_payload(&block_1);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Valid));
}

// ```text
// 0 -e- 1 -f- 2 -f- 3
//             |
//             e- 4
// ```
//
// 3's payload is rejected, and the execution engine names 1's payload as the latest valid one.
// 2's payload sits in between, so it is rejected too, along with 3 built on it.
// 4 skips 2's payload and rests on 1, so it stays valid.
#[test]
fn gloas_invalid_payload_with_older_latest_valid_hash_invalidates_payloads_in_between() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) =
        context.empty_block_extending_parent_payload(&state_1, 2, H256::default());
    let (block_3, state_3) =
        context.empty_block_extending_parent_payload(&state_2, 3, H256::default());
    let (block_4, _) = context.empty_block(&state_2, 4, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);
    let envelope_2 = context.execution_payload_envelope(&block_2, &state_2);
    let envelope_3 = context.execution_payload_envelope(&block_3, &state_3);

    context.on_slot(block_4.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);
    context.on_acceptable_block(&block_2);
    context.on_valid_execution_payload(&envelope_2, BlsSetting::Required);
    context.on_acceptable_block(&block_3);
    context.on_valid_execution_payload(&envelope_3, BlsSetting::Required);
    context.on_acceptable_block(&block_4);

    context.on_notified_valid_payload(&block_1);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_4, Some(PayloadStatus::Valid));

    context.on_notified_invalid_payload(&block_3, Some(&block_1));

    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_4, Some(PayloadStatus::Valid));
    context.assert_head(4, block_4.message().hash_tree_root());
}

// ```text
// 0 -e- 1 -f- 2 -e- 3 -f- 4
//             |
//             f- 5
// ```
//
// 4's payload is rejected, and the execution engine names 1's payload as the latest valid one.
// 3's payload sits in between, so it is rejected too, along with 4 built on it.
// 4's chain skips 2's payload, so the verdict says nothing about it.
// 2 and 5 built on its payload are untouched.
#[test]
fn gloas_invalid_payload_with_older_latest_valid_hash_skips_payloads_left_out() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) =
        context.empty_block_extending_parent_payload(&state_1, 2, H256::default());
    let (block_3, state_3) = context.empty_block(&state_2, 3, H256::default());
    let (block_4, state_4) =
        context.empty_block_extending_parent_payload(&state_3, 4, H256::default());
    let (block_5, _) = context.empty_block_extending_parent_payload(&state_2, 5, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);
    let envelope_2 = context.execution_payload_envelope(&block_2, &state_2);
    let envelope_3 = context.execution_payload_envelope(&block_3, &state_3);
    let envelope_4 = context.execution_payload_envelope(&block_4, &state_4);

    context.on_slot(block_5.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);
    context.on_acceptable_block(&block_2);
    context.on_valid_execution_payload(&envelope_2, BlsSetting::Required);
    context.on_acceptable_block(&block_3);
    context.on_valid_execution_payload(&envelope_3, BlsSetting::Required);
    context.on_acceptable_block(&block_4);
    context.on_valid_execution_payload(&envelope_4, BlsSetting::Required);
    context.on_acceptable_block(&block_5);

    context.on_notified_valid_payload(&block_1);
    context.on_notified_invalid_payload(&block_4, Some(&block_1));

    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Optimistic));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_4, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_5, Some(PayloadStatus::Optimistic));
}

// ```text
//       f- 2f
//      /
// 0 -e- 1
//      \
//       e- 2e
// ```
//
// 2f and 2e are proposals, not imported. The validator checks them right before signing.
// 1's payload is delivered, but the execution engine has not ruled on it.
// 2f extends that payload, so it must not be signed. Who built 2f's payload does not matter.
// 2e leaves it out and rests on genesis, so it can be signed.
// Once the verdict comes in, 2f can be signed too.
#[test]
fn gloas_proposal_extending_unvalidated_payload_is_not_signable_until_validated() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2f, _) = context.empty_block_extending_parent_payload(&state_1, 2, H256::default());
    let (block_2e, _) = context.empty_block(&state_1, 2, H256::repeat_byte(1));

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    context.on_slot(block_2f.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);

    context.assert_extended_payload_status(&block_2f, Some(PayloadStatus::Optimistic));
    context.assert_extended_payload_status(&block_2e, Some(PayloadStatus::Valid));

    context.on_notified_valid_payload(&block_1);

    context.assert_extended_payload_status(&block_2f, Some(PayloadStatus::Valid));
    context.assert_extended_payload_status(&block_2e, Some(PayloadStatus::Valid));
}

// ```text
//             f- 3f
//            /
// 0 -e- 1 -f- 2
//            \
//             e- 3e
// ```
//
// 3f and 3e are proposals, not imported.
// 2's payload is rejected, and the execution engine names 1's payload as the latest valid one.
// 3f extends the rejected payload, so it must never be signed.
// 3e leaves it out and rests on 1, so it can be signed.
#[test]
fn gloas_proposal_extending_rejected_payload_is_not_signable() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) =
        context.empty_block_extending_parent_payload(&state_1, 2, H256::default());
    let (block_3f, _) = context.empty_block_extending_parent_payload(&state_2, 3, H256::default());
    let (block_3e, _) = context.empty_block(&state_2, 3, H256::repeat_byte(1));

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);
    let envelope_2 = context.execution_payload_envelope(&block_2, &state_2);

    context.on_slot(block_3f.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);
    context.on_acceptable_block(&block_2);
    context.on_valid_execution_payload(&envelope_2, BlsSetting::Required);

    context.on_notified_valid_payload(&block_1);
    context.on_notified_invalid_payload(&block_2, Some(&block_1));

    context.assert_extended_payload_status(&block_3f, Some(PayloadStatus::Invalid));
    context.assert_extended_payload_status(&block_3e, Some(PayloadStatus::Valid));
}

// ```text
// 0 --- 1 ===== 8
// ```
//
// 1 is pre-Gloas and optimistic. 8 is a proposal for the first Gloas slot, not imported.
// A pre-Gloas parent has one node, so 8 extends 1's payload either way.
// It can only be signed once 1's payload is validated.
#[test]
fn gloas_first_proposal_on_unvalidated_pre_gloas_parent_is_not_signable_until_validated() {
    let mut context = Context::gloas_at_epoch_1_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) =
        context.block_with_payload(&state_0, 1, H256::default(), H256::repeat_byte(1));
    let (block_8, _) = context.empty_block(&state_1, 8, H256::default());

    assert_eq!(block_1.phase(), Phase::Fulu);
    assert_eq!(block_8.phase(), Phase::Gloas);

    context.on_slot(block_8.message().slot());

    context.on_acceptable_block(&block_1);

    context.assert_extended_payload_status(&block_8, Some(PayloadStatus::Optimistic));

    context.on_notified_valid_payload(&block_1);

    context.assert_extended_payload_status(&block_8, Some(PayloadStatus::Valid));
}

// An envelope from too far in the future is ignored right away.
// Even if its block is unknown. No point asking peers for that block.
#[test]
fn gloas_envelope_from_far_future_is_ignored_before_looking_up_its_block() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_10, state_10) = context.empty_block(&state_1, 10, H256::default());

    let envelope_10 = context.execution_payload_envelope(&block_10, &state_10);

    context.on_slot(block_1.message().slot());

    context.on_ignorable_execution_payload(&envelope_10, BlsSetting::Required);
}

// ```text
// 0 -e- 1 -f- 2 -f- 3 -f- 4
// ```
//
// 4's payload is rejected, and the execution engine names 1's payload as the latest valid one.
// 2's and 3's payloads sit in between, so they are rejected too.
// Only the deepest of them is invalidated directly. The rest go with it as its descendants.
#[test]
fn gloas_invalid_payload_with_older_latest_valid_hash_invalidates_all_payloads_in_between() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, state_2) =
        context.empty_block_extending_parent_payload(&state_1, 2, H256::default());
    let (block_3, state_3) =
        context.empty_block_extending_parent_payload(&state_2, 3, H256::default());
    let (block_4, state_4) =
        context.empty_block_extending_parent_payload(&state_3, 4, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);
    let envelope_2 = context.execution_payload_envelope(&block_2, &state_2);
    let envelope_3 = context.execution_payload_envelope(&block_3, &state_3);
    let envelope_4 = context.execution_payload_envelope(&block_4, &state_4);

    context.on_slot(block_4.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);
    context.on_acceptable_block(&block_2);
    context.on_valid_execution_payload(&envelope_2, BlsSetting::Required);
    context.on_acceptable_block(&block_3);
    context.on_valid_execution_payload(&envelope_3, BlsSetting::Required);
    context.on_acceptable_block(&block_4);
    context.on_valid_execution_payload(&envelope_4, BlsSetting::Required);

    context.on_notified_valid_payload(&block_1);
    context.on_notified_invalid_payload(&block_4, Some(&block_1));

    context.assert_payload_status(&block_1, Some(PayloadStatus::Valid));
    context.assert_payload_status(&block_2, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_3, Some(PayloadStatus::Invalid));
    context.assert_payload_status(&block_4, Some(PayloadStatus::Invalid));
}

// ```text
// 0 -e- 1 -f- 2
// ```
//
// 1's envelope arrives and the head turns full.
// The execution engine has not ruled on 1's payload yet, so the head is optimistic.
// The envelope comes from gossip, so a `head_v2` event goes out for the full head, optimistic.
// The verdict sends the head events again, no longer optimistic.
// 2 builds on 1's validated payload, so its `head_v2` event is not optimistic from the start.
#[test]
fn gloas_head_v2_events_are_sent_again_when_the_head_is_validated() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.empty_block_extending_parent_payload(&state_1, 2, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    let root_1 = block_1.message().hash_tree_root();
    let root_2 = block_2.message().hash_tree_root();

    context.on_slot(block_1.message().slot());

    context.on_acceptable_block(&block_1);
    context.assert_head_v2_events(&[(root_1, PayloadPresence::Empty, false)]);

    context.assert_head_optimistic(false);

    context.on_valid_gossip_execution_payload(&envelope_1);
    context.assert_head_payload_status(PAYLOAD_STATUS_FULL);
    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_head_v2_events(&[(root_1, PayloadPresence::Full, true)]);
    context.assert_head_optimistic(true);

    context.on_notified_valid_payload(&block_1);
    context.assert_head_v2_events(&[(root_1, PayloadPresence::Full, false)]);
    context.assert_head_optimistic(false);

    context.on_slot(block_2.message().slot());
    context.on_acceptable_block(&block_2);
    context.assert_head_v2_events(&[(root_2, PayloadPresence::Empty, false)]);
}

// ```text
// 0 -e- 1
// ```
//
// 1's envelope arrives and the head turns full.
// The execution engine has not ruled on 1's payload yet, so the head is optimistic.
// Then an attestation votes for 1 without its payload, and the head turns empty.
// The empty node rests on genesis, which is valid, so the head is no longer optimistic.
// 1's own payload is still waiting for its verdict.
#[test]
fn gloas_head_on_empty_node_of_unvalidated_payload_is_not_optimistic() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    context.on_slot(block_1.message().slot());

    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);

    context.assert_head_payload_status(PAYLOAD_STATUS_FULL);
    context.assert_head_optimistic(true);

    context.on_slot(16);
    context.on_acceptable_singular_attestation(&state_1, 1, 0);

    context.assert_head(1, block_1.message().hash_tree_root());
    context.assert_head_payload_status(PAYLOAD_STATUS_EMPTY);
    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_head_optimistic(false);
}

// ```text
// 0 -e- 1
//  \
//   e- 2
// ```
//
// 1's payload is delivered, but the execution engine has not ruled on it.
// 2 arrives on time and takes the head with proposer boost. Nothing in 2 is unvalidated.
// 2 has the larger root, so it keeps the head once the boost is gone.
// Then an attestation votes for 1 without its payload, and the head moves back to 1.
// 1's empty node rests on genesis, so the reorg is not optimistic and is sent at once.
// 1's own payload is still waiting for its verdict. It must not hold the reorg back.
#[test]
fn gloas_reorg_to_empty_node_of_unvalidated_payload_is_sent_at_once() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.empty_block(&state_0, 2, H256::repeat_byte(1));

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    let root_1 = block_1.message().hash_tree_root();
    let root_2 = block_2.message().hash_tree_root();

    assert!(root_1 < root_2);

    context.on_slot(block_1.message().slot());
    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);

    context.on_slot(block_2.message().slot());
    context.on_acceptable_block(&block_2);

    context.assert_head(2, root_2);
    context.assert_chain_reorg_events(&[(root_2, false)]);

    context.on_slot(16);

    // Without votes or boost, the head is the larger root.
    context.assert_head(2, root_2);
    context.assert_chain_reorg_events(&[]);

    context.on_acceptable_singular_attestation(&state_1, 1, 0);

    context.assert_head(1, root_1);
    context.assert_head_payload_status(PAYLOAD_STATUS_EMPTY);
    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_chain_reorg_events(&[(root_1, false)]);
}

// ```text
//       f- 2
//      /
// 0 -e- 1
//      \
//       e- 3
// ```
//
// 3's payload is delivered, but the execution engine has not ruled on it.
// 2 arrives on time and takes the head with proposer boost.
// 2 rests on 1's payload, which is unvalidated, so that reorg is held back.
// Then 1's payload is rejected. 2 dies and the head moves to 3's full node.
// 3's payload is unvalidated, so this reorg is held back too.
// The verdict on 3's payload sends it, no longer optimistic.
#[test]
fn gloas_reorg_to_full_node_of_unvalidated_payload_is_held_until_validated() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.empty_block_extending_parent_payload(&state_1, 3, H256::default());
    let (block_3, state_3) = context.empty_block(&state_1, 2, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);
    let envelope_3 = context.execution_payload_envelope(&block_3, &state_3);

    let root_3 = block_3.message().hash_tree_root();

    context.on_slot(block_1.message().slot());
    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);

    context.on_slot(block_3.message().slot());
    context.on_acceptable_block(&block_3);
    context.on_valid_execution_payload(&envelope_3, BlsSetting::Required);

    context.on_slot(block_2.message().slot());
    context.on_acceptable_block(&block_2);

    context.assert_head(3, block_2.message().hash_tree_root());
    context.assert_chain_reorg_events(&[]);

    context.on_notified_invalid_payload(&block_1, None);

    context.assert_head(2, root_3);
    context.assert_head_payload_status(PAYLOAD_STATUS_FULL);
    context.assert_head_optimistic(true);
    context.assert_chain_reorg_events(&[]);

    context.on_notified_valid_payload(&block_3);

    context.assert_head_optimistic(false);
    context.assert_chain_reorg_events(&[(root_3, false)]);
}

// ```text
// 0 -e- 1
//  \
//   e- 2
// ```
//
// 1's payload is delivered, but the execution engine has not ruled on it.
// 2 arrives on time and takes the head with proposer boost.
// 1 has the larger root, so the head moves back to 1 once the boost is gone.
// Fork choice resolves it to 1's full node, which rests on 1's unvalidated payload.
// That reorg is held back.
// Then an attestation votes for 1 without its payload, and the head turns empty.
// The head block stays the same, but the head is no longer optimistic.
// That sends the held reorg, before 1's own payload gets its verdict.
#[test]
fn gloas_held_reorg_is_sent_when_the_head_turns_empty() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::repeat_byte(1));
    let (block_2, _) = context.empty_block(&state_0, 2, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    let root_1 = block_1.message().hash_tree_root();
    let root_2 = block_2.message().hash_tree_root();

    assert!(root_1 > root_2);

    context.on_slot(block_1.message().slot());
    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);

    context.on_slot(block_2.message().slot());
    context.on_acceptable_block(&block_2);

    context.assert_head(2, root_2);
    context.assert_chain_reorg_events(&[(root_2, false)]);

    context.on_slot(3);

    context.assert_head(1, root_1);
    context.assert_head_payload_status(PAYLOAD_STATUS_FULL);
    context.assert_head_optimistic(true);
    context.assert_chain_reorg_events(&[]);

    context.on_slot(16);
    context.on_acceptable_singular_attestation(&state_1, 1, 0);

    context.assert_head(1, root_1);
    context.assert_head_payload_status(PAYLOAD_STATUS_EMPTY);
    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_head_optimistic(false);
    context.assert_chain_reorg_events(&[(root_1, false)]);
}

// ```text
// 0 -e- 1 -f- 2
//        \
//         e- 3
// ```
//
// 1's payload is delivered, but the execution engine has not ruled on it.
// 1 rests on genesis, so its `block` event is not optimistic.
// 2 builds on 1's unvalidated payload, so its `block` event is optimistic.
// 3 skips 1's payload and rests on genesis, so its `block` event is not optimistic.
#[test]
fn gloas_block_events_are_optimistic_if_the_payload_they_rest_on_is() {
    let mut context = Context::gloas_minimal();

    let (_, state_0) = context.genesis();
    let (block_1, state_1) = context.empty_block(&state_0, 1, H256::default());
    let (block_2, _) = context.empty_block_extending_parent_payload(&state_1, 2, H256::default());
    let (block_3, _) = context.empty_block(&state_1, 3, H256::default());

    let envelope_1 = context.execution_payload_envelope(&block_1, &state_1);

    let root_1 = block_1.message().hash_tree_root();
    let root_2 = block_2.message().hash_tree_root();
    let root_3 = block_3.message().hash_tree_root();

    context.on_slot(block_1.message().slot());
    context.on_acceptable_block(&block_1);
    context.on_valid_execution_payload(&envelope_1, BlsSetting::Required);

    context.assert_block_events(&[(root_1, false)]);

    context.on_slot(block_2.message().slot());
    context.on_acceptable_block(&block_2);

    context.assert_payload_status(&block_1, Some(PayloadStatus::Optimistic));
    context.assert_block_events(&[(root_2, true)]);

    context.on_slot(block_3.message().slot());
    context.on_acceptable_block(&block_3);

    context.assert_block_events(&[(root_3, false)]);
}

// A single attestation correctly signed by a validator outside the committee it names is rejected
// at validation, before it would be forwarded, published or handed to the attestation pool.
#[test]
fn rejects_single_attestation_from_validator_outside_committee() {
    let mut context = Context::electra_minimal();

    let (_, state_0) = context.genesis();

    context.on_slot(1);

    let member = 0;
    let (attestation, subnet_id) =
        context.single_attestation_signed_by(&state_0, GENESIS_EPOCH, member, member);

    let Attestation::Single(single_attestation) = &attestation else {
        unreachable!("single_attestation_signed_by builds a single attestation");
    };

    let committee = accessors::beacon_committee(
        &state_0,
        single_attestation.data.slot,
        single_attestation.committee_index,
    )
    .expect("the committee the attestation names exists in the genesis state");

    let outsider = (0..state_0.validators().len_u64())
        .find(|index| !committee.into_iter().contains(index))
        .expect("the minimal genesis has more validators than one committee");

    assert!(matches!(
        context.on_gossip_attestation(attestation, subnet_id),
        Some(P2pMessage::Accept(_)),
    ));

    let (forged, subnet_id) =
        context.single_attestation_signed_by(&state_0, GENESIS_EPOCH, member, outsider);

    assert!(matches!(
        context.on_gossip_attestation(forged, subnet_id),
        Some(P2pMessage::Reject(_, _)),
    ));
}

#[derive(Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "these fields observe independent control outcomes rather than encode a state machine"
)]
struct ExecutionPayloadControlObservations {
    gossip_accept: bool,
    gossip_reject: bool,
    api_accept: bool,
    accepted_marker: bool,
    selected_envelope: bool,
    available_event: bool,
    gossip_event: bool,
    payload_event: bool,
}

fn run_execution_payload_control_case(
    commitment_count: usize,
    execution_valid: bool,
    use_api: bool,
) -> ExecutionPayloadControlObservations {
    use std::sync::{Arc, Mutex};

    use bls::{SecretKey, SecretKeyBytes, traits::SecretKey as _};
    use eth2_libp2p::GossipId;
    use execution_engine::MockExecutionEngine;
    use futures::{StreamExt as _, channel::mpsc};
    use helper_functions::{misc, signing::SignForSingleFork as _};
    use pubkey_cache::PubkeyCache;
    use ssz::{Hc, ProgressiveList, SszHash as _, SszList as _};
    use std_ext::ArcExt as _;
    use types::{
        config::Config,
        deneb::primitives::KzgCommitment,
        gloas::{
            beacon_state::BeaconState as GloasBeaconState,
            consts::BUILDER_INDEX_SELF_BUILD,
            containers::{
                BeaconBlock as GloasBeaconBlock, BeaconBlockBody as GloasBeaconBlockBody,
                ExecutionPayload as GloasExecutionPayload, ExecutionPayloadBid,
                ExecutionPayloadEnvelope, ExecutionRequests,
                SignedBeaconBlock as GloasSignedBeaconBlock, SignedExecutionPayloadBid,
                SignedExecutionPayloadEnvelope,
            },
        },
        nonstandard::ValidationOutcome,
        phase0::{
            containers::{BeaconBlockHeader, Validator},
            primitives::{ExecutionBlockHash, H256},
        },
        traits::BeaconState as _,
    };

    use crate::{Event, EventChannels, P2pMessage, specialized::TestController};

    let config = Arc::new(Config::minimal().start_and_stay_in(Phase::Gloas));

    let mut key_bytes = SecretKeyBytes::default();
    key_bytes.as_mut()[31] = 1;
    let key: SecretKey = key_bytes
        .try_into()
        .expect("scalar one is a valid test key");
    let execution_requests = ExecutionRequests::<Minimal>::default();
    let mut bid = ExecutionPayloadBid::<Minimal> {
        block_hash: ExecutionBlockHash::repeat_byte(0x44),
        prev_randao: H256::repeat_byte(0x55),
        gas_limit: 30_000_000,
        builder_index: BUILDER_INDEX_SELF_BUILD,
        execution_requests_root: execution_requests.hash_tree_root(),
        ..Default::default()
    };
    bid.blob_kzg_commitments =
        ProgressiveList::try_from(vec![KzgCommitment::repeat_byte(0x66); commitment_count])
            .expect("fixture commitments fit the progressive-list container");
    let body = GloasBeaconBlockBody::<Minimal> {
        signed_execution_payload_bid: SignedExecutionPayloadBid {
            message: bid.clone(),
            signature: <_>::default(),
        },
        ..Default::default()
    };
    let state = types::combined::BeaconState::from(GloasBeaconState::<Minimal> {
        genesis_time: config.min_genesis_time,
        validators: core::iter::once(Validator {
            pubkey: key.to_public_key().into(),
            activation_epoch: 0,
            exit_epoch: types::phase0::consts::FAR_FUTURE_EPOCH,
            ..Default::default()
        })
        .collect(),
        latest_block_header: BeaconBlockHeader {
            body_root: body.hash_tree_root(),
            ..Default::default()
        },
        latest_execution_payload_bid: bid.clone(),
        ..Default::default()
    });
    let block = GloasSignedBeaconBlock {
        message: Hc::from(GloasBeaconBlock {
            state_root: state.hash_tree_root(),
            body,
            ..Default::default()
        }),
        signature: <_>::default(),
    };
    let block_root = block.message.hash_tree_root();
    assert_eq!(accessors::latest_block_root(&state), block_root);
    let timestamp = misc::compute_timestamp_at_slot(&config, &state, state.slot())
        .expect("fixture timestamp should be computable");
    let post_gloas_state = state.post_gloas().expect("fixture state is Gloas");
    let envelope_message = ExecutionPayloadEnvelope {
        payload: GloasExecutionPayload {
            parent_hash: post_gloas_state.latest_block_hash(),
            prev_randao: bid.prev_randao,
            gas_limit: bid.gas_limit,
            timestamp,
            withdrawals: ProgressiveList::try_from(
                post_gloas_state
                    .payload_expected_withdrawals()
                    .iter()
                    .copied()
                    .collect::<Vec<_>>(),
            )
            .expect("expected withdrawals fit in the payload progressive list"),
            block_hash: bid.block_hash,
            slot_number: state.slot(),
            ..Default::default()
        },
        execution_requests,
        builder_index: bid.builder_index,
        beacon_block_root: block_root,
        parent_beacon_block_root: state.latest_block_header().parent_root,
    };
    let envelope = Arc::new(SignedExecutionPayloadEnvelope {
        signature: envelope_message.sign(&config, &state, &key).into(),
        message: envelope_message,
    });
    let block = Arc::new(types::combined::SignedBeaconBlock::<Minimal>::from(block));
    let state = Arc::new(state);

    let event_channels = Arc::new(EventChannels::new(32));
    let mut available_rx = event_channels.execution_payload_available.subscribe();
    let mut gossip_rx = event_channels.execution_payloads_gossip.subscribe();
    let mut payload_rx = event_channels.execution_payloads.subscribe();
    let (p2p_tx, mut p2p_rx) = mpsc::unbounded();
    let execution_engine = Arc::new(Mutex::new(MockExecutionEngine::new(
        execution_valid,
        false,
        None,
    )));
    let (controller, _mutator_handle) = TestController::with_p2p_tx(
        config,
        Arc::new(PubkeyCache::default()),
        block,
        state,
        execution_engine,
        p2p_tx,
        event_channels.clone_arc(),
        Some(1),
    );
    assert_eq!(controller.store_snapshot().phase(), Phase::Gloas);

    let (gossip_accept, gossip_reject, api_accept) = if use_api {
        let (sender, mut receiver) = mpsc::channel(1);
        controller.on_api_execution_payload_envelope(envelope.clone_arc(), sender);
        controller.wait_for_tasks();
        let result = futures::executor::block_on(receiver.next())
            .expect("accepted API payload should receive a terminal response");
        (
            false,
            false,
            matches!(result, Ok(ValidationOutcome::Accept)),
        )
    } else {
        controller.on_gossip_execution_payload(envelope.clone_arc(), GossipId::default());
        controller.wait_for_tasks();
        let response = p2p_rx
            .try_recv()
            .expect("gossip payload should receive a terminal P2P response");
        match response {
            P2pMessage::Accept(_) => (true, false, false),
            P2pMessage::Reject(_, _) => (false, true, false),
            other => panic!("unexpected terminal payload response: {other:?}"),
        }
    };

    let store = controller.store_snapshot();
    let accepted_marker = store.is_payload_verified(block_root);
    let selected_envelope = store
        .cached_execution_payload_envelope_by_root(block_root)
        .is_some_and(|selected| selected.as_ref() == envelope.as_ref());
    let available_event = matches!(
        available_rx.try_recv(),
        Ok(Event::ExecutionPayloadAvailable(event)) if event.block_root == block_root
    );
    let gossip_event = matches!(
        gossip_rx.try_recv(),
        Ok(Event::ExecutionPayloadGossip(event)) if event.block_root == block_root
    );
    let payload_event = matches!(
        payload_rx.try_recv(),
        Ok(Event::ExecutionPayload(event)) if event.block_root == block_root
    );

    ExecutionPayloadControlObservations {
        gossip_accept,
        gossip_reject,
        api_accept,
        accepted_marker,
        selected_envelope,
        available_event,
        gossip_event,
        payload_event,
    }
}

#[test]
fn execution_payload_some_none_and_submission_failure_preserve_control_observables() {
    // The selected binding type accepts at most 4096 versioned hashes. The ordinary mock EL
    // accepts both submissions; the over-limit case forces only post-notification capture to None.
    let some = run_execution_payload_control_case(2, true, false);
    let none = run_execution_payload_control_case(4097, true, false);
    assert_eq!(some, none);
    assert_eq!(
        some,
        ExecutionPayloadControlObservations {
            gossip_accept: true,
            gossip_reject: false,
            api_accept: false,
            accepted_marker: true,
            selected_envelope: true,
            available_event: true,
            gossip_event: true,
            payload_event: true,
        }
    );

    let api = run_execution_payload_control_case(2, true, true);
    let api_none = run_execution_payload_control_case(4097, true, true);
    assert_eq!(api, api_none);
    assert_eq!(
        api,
        ExecutionPayloadControlObservations {
            gossip_accept: false,
            gossip_reject: false,
            api_accept: true,
            accepted_marker: true,
            selected_envelope: true,
            available_event: true,
            gossip_event: true,
            payload_event: true,
        }
    );

    let failed = run_execution_payload_control_case(2, false, false);
    assert_eq!(
        failed,
        ExecutionPayloadControlObservations {
            gossip_accept: false,
            gossip_reject: true,
            api_accept: false,
            accepted_marker: false,
            selected_envelope: false,
            available_event: false,
            gossip_event: false,
            payload_event: false,
        }
    );
}

#[cfg(test)]
mod execution_proof_tests {
    use core::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use std::{
        collections::{HashMap, HashSet},
        sync::{Arc, Mutex, Weak, mpsc},
    };

    use bls::{SecretKey, SecretKeyBytes, traits::SecretKey as _};
    use eth2_libp2p::{GossipId, MessageId, PeerId};
    use execution_engine::MockExecutionEngine;
    use fork_choice_store::{Storage, Store};
    use helper_functions::{
        accessors, misc,
        signing::{SignForSingleFork as _, SignForSingleForkAtSlot},
    };
    use proof_engine::{BackendSpec, ProofEngine, ProofVerdict, ZkvmProofEngine};
    use pubkey_cache::PubkeyCache;
    use ssz::{ByteList, Hc, ProgressiveList, Ssz, SszHash as _, SszList as _, SszWrite as _};
    use std_ext::ArcExt as _;
    use types::{
        config::Config,
        deneb::primitives::KzgCommitment,
        eip8025::{
            containers::{
                ExecutionProof, ExecutionProofEnvelope, ProofData, SignedExecutionProofEnvelope,
            },
            primitives::{MaxProofSize, get_supported_proof_types},
        },
        gloas::{
            beacon_state::BeaconState as GloasBeaconState,
            consts::BUILDER_INDEX_SELF_BUILD,
            containers::{
                BeaconBlock as GloasBeaconBlock, BeaconBlockBody as GloasBeaconBlockBody,
                ExecutionPayload as GloasExecutionPayload, ExecutionPayloadBid,
                ExecutionPayloadEnvelope, ExecutionRequests,
                SignedBeaconBlock as GloasSignedBeaconBlock, SignedExecutionPayloadBid,
                SignedExecutionPayloadEnvelope,
            },
        },
        nonstandard::Phase,
        phase0::{
            consts::FAR_FUTURE_EPOCH,
            containers::{BeaconBlockHeader, Validator},
            primitives::{ExecutionBlockHash, H256},
        },
        preset::{Minimal, Preset},
        traits::BeaconState as _,
    };

    use crate::{
        events::EventChannels,
        messages::P2pMessage,
        specialized::{TestController, TestExecutionEngine},
        unbounded_sink::UnboundedSink,
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);
    const CONFIGURED_PROOF_TYPE: u8 = 1;
    const SUPPORTED_UNCONFIGURED_PROOF_TYPE: u8 = 2;
    const TEST_VALIDATOR_INDEX: u64 = 0;

    #[derive(Ssz)]
    #[ssz(derive_hash = false)]
    struct ZkboostMockProofForTest {
        public_values: ByteList<MaxProofSize>,
        proof: ByteList<MaxProofSize>,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Default)]
    struct StoreObservation {
        seen_roots: HashMap<H256, HashSet<H256>>,
        seen_provers: HashSet<(H256, u8, u64)>,
        execution_proofs: HashMap<H256, HashMap<u8, ExecutionProofEnvelope>>,
    }

    impl StoreObservation {
        fn capture<P: Preset, S: Storage<P>>(store: &Store<P, S>) -> Self {
            Self {
                seen_roots: store
                    .execution_proof_roots()
                    .iter()
                    .map(|(root, roots)| (*root, roots.iter().copied().collect()))
                    .collect(),
                seen_provers: store.execution_proof_provers().iter().copied().collect(),
                execution_proofs: store
                    .execution_proofs()
                    .iter()
                    .map(|(root, proofs)| {
                        (
                            *root,
                            proofs
                                .iter()
                                .map(|(proof_type, envelope)| {
                                    (*proof_type, envelope.as_ref().clone())
                                })
                                .collect(),
                        )
                    })
                    .collect(),
            }
        }
    }

    type ControllerSlot = Arc<Mutex<Option<Weak<TestController<Minimal>>>>>;
    type ExpectedProofSlot = Arc<Mutex<Option<ExpectedProof>>>;

    #[derive(Clone)]
    struct ExpectedProof {
        block_root: H256,
        envelope_root: H256,
        proof_type: u8,
        validator_index: u64,
        envelope: ExecutionProofEnvelope,
        gossip_source: PeerId,
        gossip_message_id: MessageId,
    }

    enum EngineEvent {
        Entered {
            invocation: usize,
            execution_proof: ExecutionProof,
            published_store: Option<Box<StoreObservation>>,
        },
        Returned {
            invocation: usize,
            verdict: ProofVerdict,
        },
    }

    struct ObservingProofEngine {
        concrete: ZkvmProofEngine,
        controller: ControllerSlot,
        events: mpsc::Sender<EngineEvent>,
        invocations: Arc<AtomicUsize>,
    }

    impl ProofEngine for ObservingProofEngine {
        fn is_null(&self) -> bool {
            self.concrete.is_null()
        }

        fn verify_execution_proof(&self, execution_proof: ExecutionProof) -> ProofVerdict {
            let invocation = self
                .invocations
                .fetch_add(1, Ordering::SeqCst)
                .checked_add(1)
                .expect("test verifier invocation count should not overflow");
            // Capture the published paired Seen state before announcing engine entry and before
            // delegating. The wrapper never substitutes or changes the concrete verdict.
            let published_store = capture_controller_store(&self.controller).map(Box::new);
            drop(self.events.send(EngineEvent::Entered {
                invocation,
                execution_proof: execution_proof.clone(),
                published_store,
            }));

            let verdict = self.concrete.verify_execution_proof(execution_proof);
            drop(self.events.send(EngineEvent::Returned {
                invocation,
                verdict,
            }));
            verdict
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum P2pResult {
        Accept,
        Ignore,
        Reject,
        Other,
    }

    struct P2pObservation {
        result: P2pResult,
        gossip_identity: Option<(PeerId, MessageId)>,
        is_proof_response: bool,
        store_at_send: Option<StoreObservation>,
    }

    #[derive(Clone)]
    struct ObservingP2pSink {
        sender: mpsc::Sender<P2pObservation>,
        controller: ControllerSlot,
        expected_proof: ExpectedProofSlot,
    }

    impl UnboundedSink<P2pMessage<Minimal>> for ObservingP2pSink {
        fn clone(&self) -> Self {
            Clone::clone(self)
        }

        fn unbounded_send(&self, message: P2pMessage<Minimal>) -> Result<(), P2pMessage<Minimal>> {
            let (result, gossip_identity) = match &message {
                P2pMessage::Accept(gossip_id) => {
                    (P2pResult::Accept, Some(gossip_identity(gossip_id)))
                }
                P2pMessage::Ignore(gossip_id) => {
                    (P2pResult::Ignore, Some(gossip_identity(gossip_id)))
                }
                P2pMessage::IgnoreWithReason(gossip_id, _) => {
                    (P2pResult::Ignore, gossip_id.as_ref().map(gossip_identity))
                }
                P2pMessage::Reject(gossip_id, _) => {
                    (P2pResult::Reject, gossip_id.as_ref().map(gossip_identity))
                }
                _ => (P2pResult::Other, None),
            };
            let is_proof_response = gossip_identity
                .as_ref()
                .is_some_and(|(source, message_id)| {
                    self.expected_proof
                        .lock()
                        .expect("expected-proof observer mutex should not be poisoned")
                        .as_ref()
                        .is_some_and(|expected| {
                            source == &expected.gossip_source
                                && message_id == &expected.gossip_message_id
                        })
                });
            // Observe publication synchronously at the actual proof terminal send, rather than
            // looking at a later test-thread snapshot.
            let store_at_send = is_proof_response
                .then(|| capture_controller_store(&self.controller))
                .flatten();

            self.sender
                .send(P2pObservation {
                    result,
                    gossip_identity,
                    is_proof_response,
                    store_at_send,
                })
                .map_err(|_| message)
        }
    }

    fn gossip_identity(gossip_id: &GossipId) -> (PeerId, MessageId) {
        (gossip_id.source, gossip_id.message_id.clone())
    }

    fn capture_controller_store(controller: &ControllerSlot) -> Option<StoreObservation> {
        let controller = controller
            .lock()
            .expect("weak-controller observer mutex should not be poisoned")
            .as_ref()?
            .upgrade()?;
        let store = controller.store_snapshot();
        Some(StoreObservation::capture(&store))
    }

    fn test_gossip_id(seed: u8) -> GossipId {
        // A valid non-default sha2-256 multihash and non-empty message id make origin preservation
        // observable without depending on random peer identity generation.
        let mut peer_id_bytes = vec![0x12, 0x20];
        peer_id_bytes.resize(34, seed);
        GossipId {
            source: PeerId::from_bytes(&peer_id_bytes).expect("test peer id should decode"),
            message_id: MessageId::new(&[seed, 0xc2]),
        }
    }

    fn assert_gossip_identity(actual: Option<(PeerId, MessageId)>, expected: &GossipId) {
        let (actual_source, actual_message_id) =
            actual.expect("terminal response should preserve the submitted gossip identity");
        assert_eq!(actual_source, expected.source);
        assert_eq!(actual_message_id, expected.message_id);

        let default = GossipId::default();
        assert_ne!(actual_source, default.source);
        assert_ne!(actual_message_id, default.message_id);
    }

    fn expected_store(expected: &ExpectedProof, include_proof: bool) -> StoreObservation {
        StoreObservation {
            seen_roots: HashMap::from([(
                expected.block_root,
                HashSet::from([expected.envelope_root]),
            )]),
            seen_provers: HashSet::from([(
                expected.block_root,
                expected.proof_type,
                expected.validator_index,
            )]),
            execution_proofs: if include_proof {
                HashMap::from([(
                    expected.block_root,
                    HashMap::from([(expected.proof_type, expected.envelope.clone())]),
                )])
            } else {
                HashMap::new()
            },
        }
    }

    fn mock_proof_data(public_values: Vec<u8>, proof_byte: u8) -> ProofData {
        let mock_proof = ZkboostMockProofForTest {
            public_values: ByteList::try_from(public_values)
                .expect("serialized public values should fit the mock wire field"),
            proof: ByteList::try_from(vec![proof_byte])
                .expect("one mock proof byte should fit the mock wire field"),
        };
        let encoded = mock_proof
            .to_ssz()
            .expect("test mirror of the mock wire shape should serialize");
        ProofData::try_from(encoded).expect("encoded mock proof should fit ProofData")
    }

    fn receive_p2p_response(
        receiver: &mpsc::Receiver<P2pObservation>,
        expected_result: P2pResult,
        expected_gossip_id: &GossipId,
        expected_is_proof_response: bool,
    ) -> P2pObservation {
        let observation = receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("timed out waiting for P2P validation response");
        assert_eq!(observation.result, expected_result);
        assert_gossip_identity(observation.gossip_identity.clone(), expected_gossip_id);
        assert_eq!(observation.is_proof_response, expected_is_proof_response);
        observation
    }

    #[derive(Clone, Copy)]
    enum ProofCase {
        MatchingMock,
        MalformedMock,
        MismatchedPublicValues,
        SupportedUnconfigured,
    }

    fn run_execution_proof_case(case: ProofCase) {
        let mut chain_config = Config::minimal().start_and_stay_in(Phase::Gloas);
        chain_config.deposit_chain_id = 1337;
        let config = Arc::new(chain_config);

        let mut key_bytes = SecretKeyBytes::default();
        key_bytes.as_mut()[31] = 1;
        let key: SecretKey = key_bytes
            .try_into()
            .expect("scalar one is a valid active validator key");
        let execution_requests = ExecutionRequests::<Minimal>::default();
        let mut bid = ExecutionPayloadBid::<Minimal> {
            block_hash: ExecutionBlockHash::repeat_byte(0x44),
            prev_randao: H256::repeat_byte(0x55),
            gas_limit: 30_000_000,
            builder_index: BUILDER_INDEX_SELF_BUILD,
            execution_requests_root: execution_requests.hash_tree_root(),
            ..Default::default()
        };
        bid.blob_kzg_commitments = ProgressiveList::try_from(vec![
            KzgCommitment::repeat_byte(0x66),
            KzgCommitment::repeat_byte(0x66),
        ])
        .expect("fixture commitments fit the progressive-list container");
        let body = GloasBeaconBlockBody::<Minimal> {
            signed_execution_payload_bid: SignedExecutionPayloadBid {
                message: bid.clone(),
                signature: <_>::default(),
            },
            ..Default::default()
        };
        let state = types::combined::BeaconState::from(GloasBeaconState::<Minimal> {
            genesis_time: config.min_genesis_time,
            validators: core::iter::once(Validator {
                pubkey: key.to_public_key().into(),
                activation_epoch: 0,
                exit_epoch: FAR_FUTURE_EPOCH,
                ..Default::default()
            })
            .collect(),
            latest_block_header: BeaconBlockHeader {
                body_root: body.hash_tree_root(),
                ..Default::default()
            },
            latest_execution_payload_bid: bid.clone(),
            ..Default::default()
        });
        let anchor_block = GloasSignedBeaconBlock {
            message: Hc::from(GloasBeaconBlock {
                state_root: state.hash_tree_root(),
                body,
                ..Default::default()
            }),
            signature: <_>::default(),
        };
        let block_root = anchor_block.message.hash_tree_root();
        assert_eq!(accessors::latest_block_root(&state), block_root);
        let timestamp = misc::compute_timestamp_at_slot(&config, &state, state.slot())
            .expect("fixture timestamp should be computable");
        let post_gloas_state = state.post_gloas().expect("fixture state is Gloas");
        let payload_message = ExecutionPayloadEnvelope {
            payload: GloasExecutionPayload {
                parent_hash: post_gloas_state.latest_block_hash(),
                prev_randao: bid.prev_randao,
                gas_limit: bid.gas_limit,
                timestamp,
                withdrawals: ProgressiveList::try_from(
                    post_gloas_state
                        .payload_expected_withdrawals()
                        .iter()
                        .copied()
                        .collect::<Vec<_>>(),
                )
                .expect("expected withdrawals fit in the payload progressive list"),
                block_hash: bid.block_hash,
                slot_number: state.slot(),
                ..Default::default()
            },
            execution_requests,
            builder_index: bid.builder_index,
            beacon_block_root: block_root,
            parent_beacon_block_root: state.latest_block_header().parent_root,
        };
        let payload = Arc::new(SignedExecutionPayloadEnvelope {
            signature: payload_message.sign(&config, &state, &key).into(),
            message: payload_message,
        });

        let controller_slot: ControllerSlot = Arc::new(Mutex::new(None));
        let expected_proof: ExpectedProofSlot = Arc::new(Mutex::new(None));
        let (p2p_sender, p2p_receiver) = mpsc::channel();
        let (engine_sender, engine_receiver) = mpsc::channel();
        let invocations = Arc::new(AtomicUsize::new(0));
        let concrete_engine =
            ZkvmProofEngine::new(&config, [(CONFIGURED_PROOF_TYPE, BackendSpec::ZkboostMock)])
                .expect("one configured zkBoost mock backend is valid on this non-mainnet chain");
        let proof_engine: Arc<dyn ProofEngine> = Arc::new(ObservingProofEngine {
            concrete: concrete_engine,
            controller: controller_slot.clone_arc(),
            events: engine_sender,
            invocations: invocations.clone_arc(),
        });
        let p2p_sink = ObservingP2pSink {
            sender: p2p_sender,
            controller: controller_slot.clone_arc(),
            expected_proof: expected_proof.clone_arc(),
        };
        let execution_engine: TestExecutionEngine<Minimal> =
            Arc::new(Mutex::new(MockExecutionEngine::new(true, false, None)));
        let anchor_block = Arc::new(types::combined::SignedBeaconBlock::<Minimal>::from(
            anchor_block,
        ));
        let state = Arc::new(state);
        let (controller, _mutator_handle) = TestController::with_p2p_tx_and_proof_engine(
            config.clone_arc(),
            Arc::new(PubkeyCache::default()),
            anchor_block,
            state.clone_arc(),
            execution_engine,
            proof_engine,
            p2p_sink,
            Arc::new(EventChannels::new(32)),
            Some(1),
        );
        *controller_slot
            .lock()
            .expect("weak-controller observer mutex should not be poisoned") =
            Some(Arc::downgrade(&controller));

        let payload_gossip_id = test_gossip_id(0x31);
        controller.on_gossip_execution_payload(payload.clone_arc(), payload_gossip_id.clone());
        // This wait is for ordinary payload setup only. Proof completion below is observed through
        // the engine/P2P channels and is deliberately not put in the wait group.
        controller.wait_for_tasks();
        receive_p2p_response(&p2p_receiver, P2pResult::Accept, &payload_gossip_id, false);

        let accepted_store = controller.store_snapshot();
        assert!(accepted_store.is_payload_verified(block_root));
        let selected_payload = accepted_store
            .cached_execution_payload_envelope_by_root(block_root)
            .expect("accepted payload envelope should remain selected");
        assert_eq!(selected_payload.as_ref(), payload.as_ref());

        let proof_type = match case {
            ProofCase::SupportedUnconfigured => SUPPORTED_UNCONFIGURED_PROOF_TYPE,
            ProofCase::MatchingMock
            | ProofCase::MalformedMock
            | ProofCase::MismatchedPublicValues => CONFIGURED_PROOF_TYPE,
        };
        assert!(get_supported_proof_types().contains(&proof_type));
        let mut envelope = ExecutionProofEnvelope {
            proof_data: ProofData::try_from(vec![0x42])
                .expect("non-empty placeholder proof data should fit"),
            proof_type,
            beacon_block_root: block_root,
        };
        let expected_public_input = accepted_store
            .get_execution_proof(state.as_ref(), &envelope, &selected_payload.message)
            .expect("accepted payload and its selected post-state should bind")
            .public_input;
        assert!(expected_public_input.successful_validation);
        assert_eq!(expected_public_input.chain_id, config.deposit_chain_id);
        assert_eq!(expected_public_input.chain_id, 1337);

        let mut public_values = expected_public_input
            .to_ssz()
            .expect("trusted public input should serialize");
        assert_eq!(public_values.len(), 43);
        match case {
            ProofCase::MatchingMock | ProofCase::SupportedUnconfigured => {
                envelope.proof_data = mock_proof_data(public_values, 0xa1);
            }
            ProofCase::MalformedMock => {
                // Non-empty, but too short to encode the mock's two SSZ variable-field offsets.
                envelope.proof_data =
                    ProofData::try_from(vec![0x42]).expect("malformed bytes still fit ProofData");
            }
            ProofCase::MismatchedPublicValues => {
                public_values[0] ^= 1;
                envelope.proof_data = mock_proof_data(public_values, 0xa2);
            }
        }

        // Sign the exact final bare envelope after any proof/public-value mutation, using the
        // real active validator in the accepted target state and that state's slot.
        let signature = SignForSingleForkAtSlot::<Minimal>::sign(
            &envelope,
            &config,
            state.as_ref(),
            state.slot(),
            &key,
        )
        .into();
        let signed_proof = Arc::new(SignedExecutionProofEnvelope {
            message: Hc::from(envelope.clone()),
            validator_index: TEST_VALIDATOR_INDEX,
            signature,
        });
        let proof_gossip_id = test_gossip_id(0x52);
        let expected = ExpectedProof {
            block_root,
            envelope_root: envelope.hash_tree_root(),
            proof_type,
            validator_index: TEST_VALIDATOR_INDEX,
            envelope: envelope.clone(),
            gossip_source: proof_gossip_id.source,
            gossip_message_id: proof_gossip_id.message_id.clone(),
        };
        *expected_proof
            .lock()
            .expect("expected-proof observer mutex should not be poisoned") =
            Some(expected.clone());

        controller.on_gossip_execution_proof(signed_proof, proof_gossip_id.clone());

        let (invocation, actual_input, store_at_entry) = match engine_receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("timed out waiting for concrete proof-engine entry")
        {
            EngineEvent::Entered {
                invocation,
                execution_proof,
                published_store,
            } => (
                invocation,
                execution_proof,
                published_store.map(|store| *store),
            ),
            EngineEvent::Returned { .. } => {
                panic!("proof engine returned before publishing its entry observation")
            }
        };
        assert_eq!(
            invocation, 1,
            "the fresh fixture should invoke one verifier"
        );
        assert_eq!(
            actual_input,
            ExecutionProof {
                proof_data: envelope.proof_data,
                proof_type,
                public_input: expected_public_input,
            },
            "the live service must bind exactly the accepted payload context"
        );
        assert_eq!(store_at_entry, Some(expected_store(&expected, false)));

        let actual_verdict = match engine_receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("timed out waiting for concrete proof-engine verdict")
        {
            EngineEvent::Returned {
                invocation: returned_invocation,
                verdict,
            } => {
                assert_eq!(returned_invocation, invocation);
                verdict
            }
            EngineEvent::Entered { .. } => {
                panic!("unexpected additional proof-engine invocation in fresh fixture")
            }
        };
        let (expected_verdict, expected_response, store_has_proof) = match case {
            ProofCase::MatchingMock => (ProofVerdict::Valid, P2pResult::Accept, true),
            ProofCase::MalformedMock | ProofCase::MismatchedPublicValues => {
                (ProofVerdict::Invalid, P2pResult::Reject, false)
            }
            ProofCase::SupportedUnconfigured => {
                (ProofVerdict::Undetermined, P2pResult::Ignore, false)
            }
        };
        assert_eq!(actual_verdict, expected_verdict);

        let response =
            receive_p2p_response(&p2p_receiver, expected_response, &proof_gossip_id, true);
        assert_eq!(
            response.store_at_send,
            Some(expected_store(&expected, store_has_proof)),
            "terminal P2P send must synchronously observe exact storage and paired Seen state"
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn execution_proof_accepts_matching_zkboost_mock_for_accepted_payload() {
        run_execution_proof_case(ProofCase::MatchingMock);
    }

    #[test]
    fn execution_proof_rejects_nonempty_malformed_zkboost_mock() {
        run_execution_proof_case(ProofCase::MalformedMock);
    }

    #[test]
    fn execution_proof_rejects_mismatched_mock_public_values() {
        run_execution_proof_case(ProofCase::MismatchedPublicValues);
    }

    #[test]
    fn execution_proof_ignores_supported_unconfigured_type_two() {
        run_execution_proof_case(ProofCase::SupportedUnconfigured);
    }
}
