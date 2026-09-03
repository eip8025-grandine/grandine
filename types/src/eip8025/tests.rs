use bls::SignatureBytes;
use hex_literal::hex;
use ssz::{
    H256, Hc, ProgressiveList, ProgressiveMerkleTree, ReadError, SszHash as _, SszReadDefault as _,
    SszWrite as _, mix_in_active_fields,
};
use test_case::test_case;
use typenum::Unsigned as _;

use crate::{
    bellatrix::containers::ExecutionPayload as BellatrixExecutionPayload,
    capella::containers::Withdrawal,
    combined::{ExecutionPayload as CombinedExecutionPayload, ExecutionPayloadParams},
    eip8025::{
        consts::{
            MAX_PROOF_SIZE, MAX_SIGNED_EXECUTION_PROOF_ENVELOPE_SIZE, STATELESS_INPUT_SCHEMA_ID,
        },
        container_impls::new_payload_request_root,
        containers::{
            ExecutionProof, ExecutionProofEnvelope, ProofData, PublicInput,
            SignedExecutionProofEnvelope, SszNewPayloadRequest,
        },
        error::PayloadBindingError,
        primitives::ProofType,
    },
    gloas::containers::{ExecutionPayload, ExecutionRequests},
    phase0::primitives::ValidatorIndex,
    preset::{Mainnet, Minimal, Preset},
};

// Sample values mirrored exactly in the reference implementation.
const NEW_PAYLOAD_REQUEST_ROOT: H256 = H256(hex!(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
));
const BEACON_BLOCK_ROOT: H256 = H256(hex!(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
));
const PROOF_TYPE: ProofType = 7;
const VALIDATOR_INDEX: ValidatorIndex = 12345;
const CHAIN_ID: u64 = 11_155_111;

// The fixed part of `ExecutionProofEnvelope`: an offset, a
// `ProofType` and a `Root`.
const ENVELOPE_FIXED_PART: usize = 37;

// The fixed part of `ExecutionProof`: an offset, a `ProofType` and a
// serialized `PublicInput`.
const EXECUTION_PROOF_FIXED_PART: usize = 4 + 1 + PUBLIC_INPUT_SIZE;

// `PublicInput` is all-fixed, so a progressive container serializes
// as its active fields concatenated: a `Root`, a `Boolean`, a
// `Uint64` and a `Uint16`.
const PUBLIC_INPUT_SIZE: usize = 32 + 1 + 8 + 2;

// The bound `versioned_hashes` carries into the root. Equal across
// presets, which `container_impls` asserts.
const MAX_VERSIONED_HASHES: usize = <Mainnet as Preset>::MaxBlobCommitmentsPerBlock::USIZE;

// The expected roots below were produced by an independent
// implementation using merkleization primitives from
// `ethereum/ssz-specs` v0.0.1.dev2. The container composition is
// cross-checked against the `ssz-specs` progressive-container
// fixtures and the `ProgressiveByteList` vectors.
//
// They are not cross-checked against the pyspec, and no `ssz_static`
// vectors exist for EIP-8025.

// `PublicInput` is a progressive container, so its root is not its
// first field: the four field roots are merkleized progressively and
// the active-field layout is mixed in.
#[test]
fn public_input_root_matches_reference() {
    let root = test_public_input().hash_tree_root();

    assert_eq!(
        root,
        H256(hex!(
            "7c64b350edd4ae9007b24bf4b2eb8da7fc904936bf099d3165083cbd83eeecb4"
        )),
    );
    assert_ne!(root, NEW_PAYLOAD_REQUEST_ROOT);
}

#[test]
fn public_input_serializes_to_its_fixed_size() {
    let bytes = test_public_input()
        .to_ssz()
        .expect("public input should be serializable");

    assert_eq!(bytes.len(), PUBLIC_INPUT_SIZE);
}

#[test_case(0, hex!("8d021ce4c6cce3f166d34c1d002cfb0b62a103f9e2ddd0c62a40d02e950ee60e"))]
#[test_case(1, hex!("3aa9c5f50a4166a94f912d7187426c0019d3a03d0f4c1494734dd8e6f5c99c2f"))]
#[test_case(32, hex!("f115d877537d594c28df3216f1b3ded2aaf94cefdfa0d304ec14ea148913f991"))]
#[test_case(100, hex!("558eab5f93064596f7b34b4ab3f2bcac5b08d8a961f86ddc5bf63c80ebb1d47b"))]
#[test_case(673, hex!("19985851f36149d302837301b1d1c28ab1c45da881b949ab76b48630bb642d71"))]
fn execution_proof_root_matches_reference(proof_data_length: usize, expected: [u8; 32]) {
    let proof = test_execution_proof(proof_data_length);

    assert_eq!(proof.hash_tree_root(), H256(expected));
}

#[test_case(
    0,
    hex!("9dd59e5816495226e5b198a4f7dc1a40c02a117b20be0cf00cc1862e4d2255c0"),
    hex!("a06e52dc0c4d02a619f36263bd242197947d30f062a6020666ae144ef5e1f0be")
)]
#[test_case(
    1,
    hex!("2f8f72df4cc1c63c07c02efff4cc2d25be7475612b8e560665751bb2534667f2"),
    hex!("5eea02d0a492aa370e3436ccb8fb24e1ee3fe974c869e81f6dc8d12af6ace4af")
)]
#[test_case(
    32,
    hex!("51d2f507ff70b8c3a60bf7ba71e386db72607635edae361478a75b198d36b51e"),
    hex!("77bbdee2036dcc957715c0ede5149d4d6ae594268f4043f15e5b615a8bcfbe8d")
)]
#[test_case(
    100,
    hex!("024c73d1626ebced9a5e284ec4bd9d4f893e36609dd302c6e0a3b41d84ba396d"),
    hex!("d5f91015366a5ff138aec2872f9d0a34f62af2eefac7552e8050db6776f03333")
)]
#[test_case(
    673,
    hex!("441c9cb27913eba1e80b347dfdc0e561b0b3622dd71c3430738d7d97b43d4624"),
    hex!("4614751f3587e4195d0e20ce168045107b6820dfbc1e9f52ce0c5f4f348b09cf")
)]
fn envelope_roots_match_reference(
    proof_data_length: usize,
    expected_envelope_root: [u8; 32],
    expected_signed_root: [u8; 32],
) {
    let signed = test_signed_envelope(proof_data_length);

    assert_eq!(
        signed.message.hash_tree_root(),
        H256(expected_envelope_root),
    );
    assert_eq!(signed.hash_tree_root(), H256(expected_signed_root));
}

// The gossiped object is the envelope, not the proof, so the two must
// not share a root.
#[test]
fn envelope_and_proof_roots_differ() {
    let envelope = ExecutionProofEnvelope::clone(&test_signed_envelope(100).message);

    assert_eq!(
        envelope.proof_data,
        test_execution_proof(100).proof_data,
        "the two carry the same proof data",
    );
    assert_ne!(
        envelope.hash_tree_root(),
        test_execution_proof(100).hash_tree_root(),
    );
}

// The `Hc` wrapper must not change the object root. That root is both
// the gossip de-duplication key and the `object_root` the signing
// root is built from.
#[test]
fn hc_wrapper_preserves_object_root() {
    let signed = test_signed_envelope(100);
    let bare = ExecutionProofEnvelope::clone(&signed.message);

    assert_eq!(signed.message.hash_tree_root(), bare.hash_tree_root());
}

#[test_case(0)]
#[test_case(1)]
#[test_case(673)]
fn signed_execution_proof_envelope_ssz_round_trip(proof_data_length: usize) {
    let signed = test_signed_envelope(proof_data_length);

    let bytes = signed.to_ssz().expect("envelope should be serializable");
    let decoded = SignedExecutionProofEnvelope::from_ssz_default(&bytes)
        .expect("envelope should be decodable");

    assert_eq!(decoded, signed);
    assert_eq!(decoded.hash_tree_root(), signed.hash_tree_root());
}

#[test_case(0)]
#[test_case(1)]
#[test_case(673)]
fn execution_proof_ssz_round_trip(proof_data_length: usize) {
    let proof = test_execution_proof(proof_data_length);

    let bytes = proof.to_ssz().expect("proof should be serializable");
    let decoded = ExecutionProof::from_ssz_default(&bytes).expect("proof should be decodable");

    assert_eq!(decoded, proof);
    assert_eq!(decoded.hash_tree_root(), proof.hash_tree_root());
}

// `MAX_SIGNED_EXECUTION_PROOF_ENVELOPE_SIZE` is the bound gossip must
// apply before decoding, so it must match the encoded size of a
// maximum-sized envelope.
#[test]
fn max_sized_envelope_encodes_to_max_signed_execution_proof_envelope_size() {
    let proof_data =
        ProofData::try_from(vec![0; MAX_PROOF_SIZE]).expect("proof data should be within bounds");

    let signed = SignedExecutionProofEnvelope {
        message: Hc::from(ExecutionProofEnvelope {
            proof_data,
            proof_type: PROOF_TYPE,
            beacon_block_root: BEACON_BLOCK_ROOT,
        }),
        validator_index: VALIDATOR_INDEX,
        signature: test_signature(),
    };

    let bytes = signed.to_ssz().expect("envelope should be serializable");

    assert_eq!(bytes.len(), MAX_SIGNED_EXECUTION_PROOF_ENVELOPE_SIZE);
}

#[test]
fn proof_data_construction_rejects_oversize() {
    let result = ProofData::try_from(vec![0; MAX_PROOF_SIZE + 1]);

    assert_eq!(
        result.expect_err("proof data should be rejected"),
        ReadError::ListTooLong {
            maximum: MAX_PROOF_SIZE,
            actual: MAX_PROOF_SIZE + 1,
        },
    );
}

#[test]
fn proof_data_construction_accepts_max_size() {
    ProofData::try_from(vec![0; MAX_PROOF_SIZE]).expect("proof data should be within bounds");
}

// `ProofData` is a progressive list and therefore unbounded in the
// spec. Decoding must reject oversize `proof_data` explicitly.
#[test]
fn envelope_decoding_rejects_oversize_proof_data() {
    let bytes = encoded_envelope(MAX_PROOF_SIZE + 1);

    let result = ExecutionProofEnvelope::from_ssz_default(&bytes);

    assert_eq!(
        result.expect_err("envelope should be rejected"),
        ReadError::ListTooLong {
            maximum: MAX_PROOF_SIZE,
            actual: MAX_PROOF_SIZE + 1,
        },
    );
}

#[test]
fn envelope_decoding_accepts_max_size_proof_data() {
    let bytes = encoded_envelope(MAX_PROOF_SIZE);

    let envelope =
        ExecutionProofEnvelope::from_ssz_default(&bytes).expect("envelope should be decodable");

    assert_eq!(envelope.proof_data.as_bytes().len(), MAX_PROOF_SIZE);
}

#[test]
fn execution_proof_decoding_rejects_oversize_proof_data() {
    let bytes = encoded_execution_proof(MAX_PROOF_SIZE + 1);

    let result = ExecutionProof::from_ssz_default(&bytes);

    assert_eq!(
        result.expect_err("proof should be rejected"),
        ReadError::ListTooLong {
            maximum: MAX_PROOF_SIZE,
            actual: MAX_PROOF_SIZE + 1,
        },
    );
}

#[test]
fn execution_proof_json_round_trip() {
    let proof = test_execution_proof(100);

    let json = serde_json::to_string(&proof).expect("proof should be serializable");
    let decoded =
        serde_json::from_str::<ExecutionProof>(&json).expect("proof should be deserializable");

    assert_eq!(decoded, proof);
    assert_eq!(decoded.hash_tree_root(), proof.hash_tree_root());
}

#[test]
fn signed_execution_proof_envelope_json_round_trip() {
    let signed = test_signed_envelope(100);

    let json = serde_json::to_string(&signed).expect("envelope should be serializable");
    let decoded = serde_json::from_str::<SignedExecutionProofEnvelope>(&json)
        .expect("envelope should be deserializable");

    assert_eq!(decoded, signed);
    assert_eq!(decoded.hash_tree_root(), signed.hash_tree_root());
}

// The serde path shares the bound with SSZ decoding, so it rejects
// oversize `proof_data` too.
#[test]
fn proof_data_deserialization_rejects_oversize() {
    let json = format!("\"0x{}\"", "00".repeat(MAX_PROOF_SIZE.saturating_add(1)));

    let error =
        serde_json::from_str::<ProofData>(&json).expect_err("proof data should be rejected");

    assert!(error.to_string().contains("no more than"), "{error}");
}

// Hand-built because `ProofData` cannot be constructed oversize
// through the public API.
fn encoded_envelope(proof_data_length: usize) -> Vec<u8> {
    let length = ENVELOPE_FIXED_PART.saturating_add(proof_data_length);

    let mut bytes = Vec::with_capacity(length);

    let offset = u32::try_from(ENVELOPE_FIXED_PART).expect("offset should fit in u32");

    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes.push(PROOF_TYPE);
    bytes.extend_from_slice(BEACON_BLOCK_ROOT.as_bytes());
    bytes.resize(length, 0);

    bytes
}

fn encoded_execution_proof(proof_data_length: usize) -> Vec<u8> {
    let length = EXECUTION_PROOF_FIXED_PART.saturating_add(proof_data_length);

    let mut bytes = Vec::with_capacity(length);

    let offset = u32::try_from(EXECUTION_PROOF_FIXED_PART).expect("offset should fit in u32");

    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes.push(PROOF_TYPE);
    bytes.extend_from_slice(NEW_PAYLOAD_REQUEST_ROOT.as_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&CHAIN_ID.to_le_bytes());
    bytes.extend_from_slice(&STATELESS_INPUT_SCHEMA_ID.to_le_bytes());
    bytes.resize(length, 0);

    bytes
}

fn test_public_input() -> PublicInput {
    PublicInput {
        new_payload_request_root: NEW_PAYLOAD_REQUEST_ROOT,
        successful_validation: true,
        chain_id: CHAIN_ID,
        schema_id: STATELESS_INPUT_SCHEMA_ID,
    }
}

fn test_execution_proof(proof_data_length: usize) -> ExecutionProof {
    ExecutionProof {
        proof_data: test_proof_data(proof_data_length),
        proof_type: PROOF_TYPE,
        public_input: test_public_input(),
    }
}

fn test_signed_envelope(proof_data_length: usize) -> SignedExecutionProofEnvelope {
    SignedExecutionProofEnvelope {
        message: Hc::from(ExecutionProofEnvelope {
            proof_data: test_proof_data(proof_data_length),
            proof_type: PROOF_TYPE,
            beacon_block_root: BEACON_BLOCK_ROOT,
        }),
        validator_index: VALIDATOR_INDEX,
        signature: test_signature(),
    }
}

fn test_proof_data(length: usize) -> ProofData {
    ProofData::try_from(test_bytes(length)).expect("proof data should be within bounds")
}

fn test_signature() -> SignatureBytes {
    SignatureBytes::from_slice(&test_bytes(96))
}

// Matches `test_bytes` in the reference implementation.
fn test_bytes(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index % 256).expect("value modulo 256 should fit in u8"))
        .collect()
}

// `SSZNewPayloadRequest` is a progressive container, so its root is
// the progressive merkleization of the four field roots with the
// active-field layout mixed in — not the fixed-depth merkleization a
// plain container would use. The subtree roots themselves come from
// types already covered by `ssz_static` spec tests, including the
// Gloas `ExecutionPayload` and `ExecutionRequests`.
#[test]
fn new_payload_request_root_is_progressive_merkleization_of_field_roots() {
    let request = test_request::<Mainnet>();

    let field_roots = [
        request.execution_payload.hash_tree_root(),
        request.versioned_hashes.hash_tree_root(),
        request.parent_beacon_block_root.hash_tree_root(),
        request.execution_requests.hash_tree_root(),
    ];

    // The active-field layout word: the low four bits of a 256-bit word, least significant
    // bit first.
    let active_fields = H256(hex!(
        "0f00000000000000000000000000000000000000000000000000000000000000"
    ));

    assert_eq!(
        request.hash_tree_root(),
        mix_in_active_fields(
            ProgressiveMerkleTree::merkleize_progressive(field_roots),
            active_fields,
        ),
    );
}

// Binding is preset-independent under Gloas. Every list that could
// carry a limit into the root is progressive, and the bounds that do
// reach it are equal across presets, so the same logical request must
// hash identically under Mainnet and Minimal.
#[test]
fn root_does_not_depend_on_preset() {
    assert_eq!(
        test_request::<Mainnet>().hash_tree_root(),
        test_request::<Minimal>().hash_tree_root(),
    );
}

// A progressive container root is not the root of its first field,
// and it is not the plain container root either.
#[test]
fn new_payload_request_root_differs_from_execution_payload_root() {
    let request = test_request::<Mainnet>();

    assert_ne!(
        request.hash_tree_root(),
        request.execution_payload.hash_tree_root(),
    );
}

#[test]
fn new_payload_request_ssz_round_trip() {
    let request = test_request::<Mainnet>();

    let bytes = request.to_ssz().expect("request should be serializable");
    let decoded = SszNewPayloadRequest::<Mainnet>::from_ssz_default(&bytes)
        .expect("request should be decodable");

    assert_eq!(decoded, request);
    assert_eq!(decoded.hash_tree_root(), request.hash_tree_root());
}

#[test]
fn new_payload_request_root_matches_constructed_request() {
    let payload = test_combined_payload::<Mainnet>();
    let params = test_params::<Mainnet>();

    let root = new_payload_request_root(&payload, &params).expect("request should be buildable");

    let request = SszNewPayloadRequest::<Mainnet>::new(&payload, &params)
        .expect("request should be buildable");

    assert_eq!(root, request.hash_tree_root());
}

#[test]
fn new_carries_the_fields_it_is_given() {
    let payload = test_combined_payload::<Mainnet>();
    let params = test_params::<Mainnet>();

    let request = SszNewPayloadRequest::<Mainnet>::new(&payload, &params)
        .expect("request should be buildable");

    let ExecutionPayloadParams::Gloas {
        versioned_hashes,
        parent_beacon_block_root,
        execution_requests,
    } = &params
    else {
        panic!("test params should be Gloas");
    };

    assert_eq!(
        request.versioned_hashes.as_ref(),
        versioned_hashes.as_slice()
    );
    assert_eq!(request.parent_beacon_block_root, *parent_beacon_block_root);
    assert_eq!(&request.execution_requests, execution_requests);
}

// EIP-8025 builds on Gloas, which has its own `ExecutionPayload` and
// `ExecutionRequests`. The Electra params carry the Electra
// `ExecutionRequests`, which is a different container with a
// different root, so they cannot be bound either.
#[test]
fn new_rejects_pre_gloas_params() {
    let payload = test_combined_payload::<Mainnet>();

    let params = ExecutionPayloadParams::Deneb {
        versioned_hashes: vec![H256::repeat_byte(1)],
        parent_beacon_block_root: H256::repeat_byte(2),
    };

    let error = SszNewPayloadRequest::<Mainnet>::new(&payload, &params)
        .expect_err("Deneb params should be rejected");

    assert!(
        matches!(error, PayloadBindingError::ExecutionRequestsNotGloas),
        "{error}",
    );
}

#[test]
fn new_rejects_pre_gloas_payload() {
    let payload =
        CombinedExecutionPayload::<Mainnet>::Bellatrix(BellatrixExecutionPayload::default());
    let params = test_params::<Mainnet>();

    let error = SszNewPayloadRequest::<Mainnet>::new(&payload, &params)
        .expect_err("Bellatrix payload should be rejected");

    assert!(
        matches!(error, PayloadBindingError::PayloadPhaseNotSupported { .. }),
        "{error}",
    );
}

// consensus-specs bounds `versioned_hashes` at
// `MAX_BLOB_COMMITMENTS_PER_BLOCK`, but derives it from the Gloas
// `blob_kzg_commitments`, which is a progressive list and therefore
// unbounded. Binding must reject values that exceed the target bound.
#[test]
fn new_rejects_too_many_versioned_hashes() {
    let payload = test_combined_payload::<Mainnet>();
    let params = test_params_with_versioned_hashes::<Mainnet>(MAX_VERSIONED_HASHES + 1);

    let error = SszNewPayloadRequest::<Mainnet>::new(&payload, &params)
        .expect_err("too many versioned hashes should be rejected");

    let PayloadBindingError::VersionedHashesTooLong(source) = error else {
        panic!("{error}");
    };

    assert_eq!(
        source,
        ReadError::ListTooLong {
            maximum: MAX_VERSIONED_HASHES,
            actual: MAX_VERSIONED_HASHES + 1,
        },
    );
}

#[test]
fn new_accepts_max_versioned_hashes() {
    let payload = test_combined_payload::<Mainnet>();
    let params = test_params_with_versioned_hashes::<Mainnet>(MAX_VERSIONED_HASHES);

    let request = SszNewPayloadRequest::<Mainnet>::new(&payload, &params)
        .expect("the maximum number of versioned hashes should be accepted");

    assert_eq!(request.versioned_hashes.as_ref().len(), MAX_VERSIONED_HASHES);
}

fn test_params_with_versioned_hashes<P: Preset>(count: usize) -> ExecutionPayloadParams<P> {
    ExecutionPayloadParams::Gloas {
        versioned_hashes: vec![H256::repeat_byte(1); count],
        parent_beacon_block_root: H256::repeat_byte(3),
        execution_requests: ExecutionRequests::default(),
    }
}

fn test_request<P: Preset>() -> SszNewPayloadRequest<P> {
    SszNewPayloadRequest::new(&test_combined_payload::<P>(), &test_params::<P>())
        .expect("request should be buildable")
}

fn test_combined_payload<P: Preset>() -> CombinedExecutionPayload<P> {
    CombinedExecutionPayload::Gloas(ExecutionPayload {
        block_number: 42,
        withdrawals: ProgressiveList::try_from(vec![Withdrawal::default()])
            .expect("one withdrawal fits in a progressive list"),
        ..Default::default()
    })
}

fn test_params<P: Preset>() -> ExecutionPayloadParams<P> {
    ExecutionPayloadParams::Gloas {
        versioned_hashes: vec![H256::repeat_byte(1), H256::repeat_byte(2)],
        parent_beacon_block_root: H256::repeat_byte(3),
        execution_requests: ExecutionRequests::default(),
    }
}
