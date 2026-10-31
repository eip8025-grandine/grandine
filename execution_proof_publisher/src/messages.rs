use anyhow::Result;
use bls::{SecretKey, traits::SecretKey as _};
use helper_functions::{misc, signing::SignForSingleForkAtSlot};
use ssz::{ByteList, Hc, Ssz, SszWrite as _};
use types::{
    combined::{ExecutionPayload as CombinedExecutionPayload, ExecutionPayloadParams},
    config::Config,
    eip8025::{
        consts::STATELESS_INPUT_SCHEMA_ID,
        containers::{
            ExecutionProofEnvelope, NewPayloadRequest, ProofData, PublicInput,
            SignedExecutionProofEnvelope,
        },
        primitives::{MaxProofSize, ProofType},
    },
    gloas::containers::{ExecutionPayloadBid, ExecutionPayloadEnvelope},
    nonstandard::ForkInfo,
    phase0::primitives::{H256, Slot, ValidatorIndex},
    preset::Preset,
};

/// The proof type the recipe configures as `mock`.
pub const MOCK_PROOF_TYPE: ProofType = 1;

/// The proof type the recipe configures as `sp1` with the fixture's guest VK.
pub const SP1_PROOF_TYPE: ProofType = 2;

/// zkBoost's genuine ethrex SP1 proof, which `proof_engine` pins.
pub const SP1_FIXTURE: &[u8] =
    include_bytes!("../../proof_engine/src/fixtures/stateless-validator-ethrex-sp1-v6.4.0.proof");

/// The first committed public-value byte in [`SP1_FIXTURE`], which step 4
/// flips, as `tampered_public_values_fail_verification` in `proof_engine`
/// does.
pub const TAMPERED_BYTE: usize = 1_272_554;

/// The `proof` bytes of the two mock proofs. They differ, so the two
/// envelopes have different roots.
pub const STEP_1_MOCK_PROOF: &[u8] = b"execution proof publisher step 1";
pub const STEP_2_MOCK_PROOF: &[u8] = b"execution proof publisher step 2";

/// The `proof_data` of a zkBoost mock proof.
///
/// This mirrors `proof_engine`'s private `MockProof`. Its layout is pinned by
/// zkBoost's `test_mock_proof_layout`.
#[derive(Clone, PartialEq, Eq, Default, Debug, Ssz)]
#[ssz(derive_hash = false)]
pub struct MockProof {
    pub public_values: ByteList<MaxProofSize>,
    pub proof: ByteList<MaxProofSize>,
}

/// Builds the `PublicInput` the way `Store::get_execution_proof` builds it
/// for B: the payload, parent root and requests from B's envelope, the
/// versioned hashes from the bid in B's block, the zkBoost-compatible root,
/// the configured chain ID and schema `0x1501`.
pub fn public_input<P: Preset>(
    config: &Config,
    envelope: &ExecutionPayloadEnvelope<P>,
    bid: &ExecutionPayloadBid<P>,
) -> Result<PublicInput> {
    let payload = CombinedExecutionPayload::Gloas(envelope.payload.clone());

    let params = ExecutionPayloadParams::Gloas {
        versioned_hashes: bid
            .blob_kzg_commitments
            .iter()
            .copied()
            .map(misc::kzg_commitment_to_versioned_hash)
            .collect(),
        parent_beacon_block_root: envelope.parent_beacon_block_root,
        execution_requests: envelope.execution_requests.clone(),
    };

    let new_payload_request = NewPayloadRequest::new(&payload, &params)?;

    Ok(PublicInput {
        new_payload_request_root: new_payload_request.zkboost_compatible_root(),
        successful_validation: true,
        chain_id: config.deposit_chain_id,
        schema_id: STATELESS_INPUT_SCHEMA_ID,
    })
}

/// A mock proof that commits to `public_input`, carrying `proof` as its
/// placeholder proof bytes.
pub fn mock_proof_data(public_input: PublicInput, proof: &[u8]) -> Result<ProofData> {
    let mock_proof = MockProof {
        public_values: ByteList::try_from(public_input.to_ssz()?)?,
        proof: ByteList::try_from(proof.to_vec())?,
    };

    Ok(ProofData::try_from(mock_proof.to_ssz()?)?)
}

pub fn sp1_proof_data() -> Result<ProofData> {
    Ok(ProofData::try_from(SP1_FIXTURE.to_vec())?)
}

/// The SP1 fixture with [`TAMPERED_BYTE`] flipped.
pub fn tampered_sp1_proof_data() -> Result<ProofData> {
    let mut bytes = SP1_FIXTURE.to_vec();

    if let Some(byte) = bytes.get_mut(TAMPERED_BYTE) {
        *byte ^= 1;
    }

    Ok(ProofData::try_from(bytes)?)
}

pub const fn envelope(
    proof_data: ProofData,
    proof_type: ProofType,
    beacon_block_root: H256,
) -> ExecutionProofEnvelope {
    ExecutionProofEnvelope {
        proof_data,
        proof_type,
        beacon_block_root,
    }
}

/// Signs an envelope with `helper_functions`' `ExecutionProofEnvelope`
/// signing, the code Grandine verifies with.
///
/// Grandine verifies against B's post-state at `state.slot`, which is B's
/// slot, so `fork_info` must be the fork of that state.
#[must_use]
pub fn sign<P: Preset>(
    config: &Config,
    fork_info: ForkInfo,
    slot: Slot,
    envelope: ExecutionProofEnvelope,
    validator_index: ValidatorIndex,
    secret_key: &SecretKey,
) -> SignedExecutionProofEnvelope {
    let signing_root = SignForSingleForkAtSlot::<P>::signing_root_from_fork_info(
        &envelope, config, fork_info, slot,
    );

    SignedExecutionProofEnvelope {
        message: Hc::from(envelope),
        validator_index,
        signature: secret_key.sign(signing_root).into(),
    }
}
