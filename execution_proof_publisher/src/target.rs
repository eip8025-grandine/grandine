use core::future::Future;

use anyhow::Result;
use helper_functions::misc;
use serde::{Deserialize, Serialize};
use types::{
    phase0::primitives::{H256, Slot},
    preset::Preset,
};

use crate::beacon::{BeaconClient, Header};

/// The Beacon API lookups target selection and the eligibility check use.
pub trait ChainView: Sync {
    /// The block Grandine returns for a slot by walking back from its head,
    /// or `None` if the slot is empty on that chain.
    fn header_by_slot(&self, slot: Slot) -> impl Future<Output = Result<Option<Header>>> + Send;

    /// Whether the block's payload envelope is returned with
    /// `execution_optimistic: false`.
    fn has_settled_envelope(&self, block_root: H256) -> impl Future<Output = Result<bool>> + Send;
}

/// The beacon block every message of a run targets.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Target {
    pub block_root: H256,
    pub slot: Slot,
}

/// Selects B: the most recent canonical block in the current epoch that is
/// at least one slot old and whose envelope is not optimistic.
///
/// Candidates come only from the by-slot lookup, so B is canonical in the
/// snapshot that answered it. Returns `None` if there is no such block yet.
pub async fn select<P: Preset>(
    chain: &impl ChainView,
    current_slot: Slot,
) -> Result<Option<Target>> {
    let epoch_start =
        misc::compute_start_slot_at_epoch::<P>(misc::compute_epoch_at_slot::<P>(current_slot));

    let Some(latest) = current_slot.checked_sub(1) else {
        return Ok(None);
    };

    for slot in (epoch_start..=latest).rev() {
        let Some(header) = chain.header_by_slot(slot).await? else {
            continue;
        };

        // Grandine never answers with another slot's block, but a stale
        // answer must not select a block outside the current epoch.
        if header.slot != slot {
            continue;
        }

        if chain.has_settled_envelope(header.root).await? {
            return Ok(Some(Target {
                block_root: header.root,
                slot,
            }));
        }
    }

    Ok(None)
}

/// The result of one eligibility check of B.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Eligibility {
    /// The by-slot lookup returned B and reported `finalized: false`.
    Eligible,
    /// The slot is empty on the chain Grandine resolved.
    SlotEmpty,
    /// The by-slot lookup returned another block.
    NotCanonical { returned_root: H256 },
    /// The by-slot lookup returned B as finalized.
    Finalized,
    /// The by-slot lookup returned B without a `finalized` flag.
    FinalityUnknown,
}

impl Eligibility {
    /// Classifies a by-slot lookup.
    ///
    /// The check passes only on a root match with `finalized: false`. It does
    /// not read `canonical`, which Grandine reports as the constant `true`.
    #[must_use]
    pub fn from_lookup(target: Target, header: Option<Header>) -> Self {
        let Some(header) = header else {
            return Self::SlotEmpty;
        };

        if header.root != target.block_root {
            return Self::NotCanonical {
                returned_root: header.root,
            };
        }

        match header.finalized {
            Some(false) => Self::Eligible,
            Some(true) => Self::Finalized,
            None => Self::FinalityUnknown,
        }
    }

    #[must_use]
    pub const fn is_eligible(self) -> bool {
        matches!(self, Self::Eligible)
    }
}

pub async fn check(chain: &impl ChainView, target: Target) -> Result<Eligibility> {
    let header = chain.header_by_slot(target.slot).await?;
    Ok(Eligibility::from_lookup(target, header))
}

/// The live view over a Grandine node's Beacon API.
pub struct LiveChain<'client, P> {
    pub client: &'client BeaconClient,
    pub phantom: core::marker::PhantomData<P>,
}

impl<P: Preset> ChainView for LiveChain<'_, P> {
    async fn header_by_slot(&self, slot: Slot) -> Result<Option<Header>> {
        self.client.header_by_slot(slot).await
    }

    async fn has_settled_envelope(&self, block_root: H256) -> Result<bool> {
        Ok(self
            .client
            .envelope::<P>(block_root)
            .await?
            .is_some_and(|envelope| envelope.execution_optimistic == Some(false)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use types::preset::Mainnet;

    use super::*;

    // Mainnet epoch 1 is slots 32 to 63.
    const CURRENT_SLOT: Slot = 40;

    #[derive(Default)]
    struct FakeChain {
        // What the by-slot lookup returns, as Grandine resolves it from its head.
        canonical: BTreeMap<Slot, H256>,
        settled: BTreeSet<H256>,
    }

    impl FakeChain {
        fn with_block(mut self, slot: Slot, byte: u8, settled: bool) -> Self {
            let root = H256::repeat_byte(byte);
            self.canonical.insert(slot, root);

            if settled {
                self.settled.insert(root);
            }

            self
        }
    }

    impl ChainView for FakeChain {
        async fn header_by_slot(&self, slot: Slot) -> Result<Option<Header>> {
            Ok(self.canonical.get(&slot).map(|root| Header {
                root: *root,
                slot,
                finalized: Some(false),
            }))
        }

        async fn has_settled_envelope(&self, block_root: H256) -> Result<bool> {
            Ok(self.settled.contains(&block_root))
        }
    }

    async fn selected(chain: &FakeChain) -> Option<Target> {
        select::<Mainnet>(chain, CURRENT_SLOT)
            .await
            .expect("the fake chain does not fail")
    }

    #[tokio::test]
    async fn selects_the_most_recent_settled_block_at_least_one_slot_old() {
        let chain = FakeChain::default()
            .with_block(37, 1, true)
            .with_block(39, 2, true)
            .with_block(CURRENT_SLOT, 3, true);

        assert_eq!(
            selected(&chain).await,
            Some(Target {
                block_root: H256::repeat_byte(2),
                slot: 39,
            }),
        );
    }

    #[tokio::test]
    async fn refuses_a_non_canonical_block() {
        // A settled block at slot 39 that the head's chain skips is never a
        // candidate: the by-slot lookup is the only source.
        let mut chain = FakeChain::default().with_block(37, 1, true);
        chain.settled.insert(H256::repeat_byte(9));

        assert_eq!(
            selected(&chain).await.map(|target| target.block_root),
            Some(H256::repeat_byte(1)),
        );
    }

    #[tokio::test]
    async fn refuses_a_block_from_an_earlier_epoch() {
        let chain = FakeChain::default()
            .with_block(30, 1, true)
            .with_block(31, 2, true);

        assert_eq!(selected(&chain).await, None);

        // At the first slot of an epoch nothing in it is a slot old yet.
        let chain = FakeChain::default().with_block(31, 2, true);

        assert_eq!(
            select::<Mainnet>(&chain, 32)
                .await
                .expect("the fake chain does not fail"),
            None,
        );
    }

    #[tokio::test]
    async fn refuses_an_optimistic_block() {
        let chain = FakeChain::default()
            .with_block(36, 1, true)
            .with_block(39, 2, false);

        assert_eq!(selected(&chain).await.map(|target| target.slot), Some(36),);

        let chain = FakeChain::default().with_block(39, 2, false);

        assert_eq!(selected(&chain).await, None);
    }

    #[test]
    fn eligibility_passes_only_on_a_root_match_with_finalized_false() {
        let target = Target {
            block_root: H256::repeat_byte(1),
            slot: 39,
        };

        let header = |byte, finalized| {
            Some(Header {
                root: H256::repeat_byte(byte),
                slot: 39,
                finalized,
            })
        };

        assert_eq!(
            Eligibility::from_lookup(target, header(1, Some(false))),
            Eligibility::Eligible,
        );
        assert_eq!(
            Eligibility::from_lookup(target, header(1, Some(true))),
            Eligibility::Finalized,
        );
        assert_eq!(
            Eligibility::from_lookup(target, header(1, None)),
            Eligibility::FinalityUnknown,
        );
        assert_eq!(
            Eligibility::from_lookup(target, header(2, Some(false))),
            Eligibility::NotCanonical {
                returned_root: H256::repeat_byte(2),
            },
        );
        assert_eq!(
            Eligibility::from_lookup(target, None),
            Eligibility::SlotEmpty,
        );
    }
}
