use bls::SignatureBytes;
use hex_literal::hex;
use ssz::{
    ContiguousList, H256, Hc, ProgressiveByteList, ProgressiveList, ProgressiveMerkleTree,
    ReadError, SszHash as _, SszReadDefault as _, SszWrite as _, mix_in_active_fields,
};
use test_case::test_case;
use try_from_iterator::TryFromIterator as _;
use typenum::Unsigned as _;

use crate::{
    bellatrix::containers::ExecutionPayload as BellatrixExecutionPayload,
    capella::containers::Withdrawal,
    combined::{ExecutionPayload as CombinedExecutionPayload, ExecutionPayloadParams},
    eip8025::{
        consts::{
            MAX_PROOF_SIZE, MAX_SIGNED_EXECUTION_PROOF_ENVELOPE_SIZE, STATELESS_INPUT_SCHEMA_ID,
        },
        containers::{
            ExecutionProof, ExecutionProofEnvelope, NewPayloadRequest, ProofAttributes, ProofData,
            PublicInput, SignedExecutionProofEnvelope,
        },
        error::PayloadBindingError,
        primitives::{MaxProofSize, ProofType},
    },
    gloas::containers::{ExecutionPayload, ExecutionRequests},
    phase0::primitives::ValidatorIndex,
    preset::{Mainnet, Minimal, Preset},
};

// Sample values matching the reference implementation.
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

// `PublicInput` is all fixed-size, so its progressive-container
// encoding is the concatenation of its active fields: a `Root`, a
// `Boolean`, a `Uint64`, and a `Uint16`.
const PUBLIC_INPUT_SIZE: usize = 32 + 1 + 8 + 2;

// The `versioned_hashes` limit applies on construction and decoding,
// and is equal across presets, as asserted in `container_impls`.
const MAX_VERSIONED_HASHES: usize = <Mainnet as Preset>::MaxBlobCommitmentsPerBlock::USIZE;

// The expected `PublicInput` root below uses a fixed
// `new_payload_request_root` and was computed using merkleization
// primitives from `ethereum/ssz-specs`. This checks the container
// schema, but does not constitute independent root verification.
//
// UNVERIFIED: every other expected root in this file was produced by
// this implementation, after `ProofData` became a `ByteList` and
// `versioned_hashes` a progressive list. They pin current behaviour
// only. The `ExecutionProof`, `ExecutionProofEnvelope` and
// `SignedExecutionProofEnvelope` roots, and the payload-derived
// `PublicInput` and `ExecutionProof` roots given Grandine's
// `NewPayloadRequest` root, agree with an out-of-band script written
// from the same reading of the spec. That is a consistency check, not
// a cross-check, and the `NewPayloadRequest` root itself is not checked
// at all. Design 0005 requires independent verification of these roots.
//
// No root here is pyspec-checked, and no `ssz_static` vectors exist
// for EIP-8025.

// `PublicInput` is a progressive container, so its root is not simply
// its first field: the four field roots are progressively merkleized,
// then the active-field layout is mixed in.
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

#[test_case(0, hex!("89ddf251d976f07051e8d65fe74702364572e62b3c26bb444c4c05c57e3a7237"))]
#[test_case(1, hex!("78a346a47750f72a11e14ab732d1225dd049b3fa6ec2665073a1c04e90f1b533"))]
#[test_case(32, hex!("fd7d76bee16bc69544957c2876bc3d12652720cb4ad5c20a0b3000e877c6fd37"))]
#[test_case(100, hex!("1c192027599a7d602197f45903b79f10b8186c80cf9958b69c05f62b7b7031d1"))]
#[test_case(673, hex!("1ce0b0a209078e0f99f3fe5c84451bd476e370b9a85f4f5801e9ff2e5e705d82"))]
fn execution_proof_root_matches_reference(proof_data_length: usize, expected: [u8; 32]) {
    let proof = test_execution_proof(proof_data_length);

    assert_eq!(proof.hash_tree_root(), H256(expected));
}

#[test_case(
    0,
    hex!("9829ae426496aabfbe177565cd91a45d0e0a55915b32a9059f0b3405355bcef4"),
    hex!("17c56e4a39229bd4ebe5577f39cc5408a8276d3c4eab0056327dae35c2da39f9")
)]
#[test_case(
    1,
    hex!("e2b81df2aff9f6732e49ec72206c51025ffe6cd0ef29033ecedb17ee7c00e06c"),
    hex!("49aae3efe9857ff48776929edb3f62d4ffe9dbf73851a8b4bab6b5d0d0cb6586")
)]
#[test_case(
    32,
    hex!("fcb706d569d7e8958fbc7ac0e57429f64c96167c0e493e68d47d522f8bf53868"),
    hex!("4850ba1a36c2a6cb568465aba711ec1714b8f050bd50434a6e57a0ae5a72ef08")
)]
#[test_case(
    100,
    hex!("89051e2b8d74d9aae15a4946d7500d7dfaee3da70b1de00c21a426898a8bbf62"),
    hex!("cf272039feaed56a491453a3c7d7961eead36458aeb1886c0c760e941ef6c533")
)]
#[test_case(
    673,
    hex!("a5fad18aadd311ecf0074ea58dbf2e7fdcc467466a862d07e1a2896a281e5ab2"),
    hex!("a957ea69d228afe767d0b3a60f16393d04be9fe1d6646661819450c1f949fb6b")
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

// `ExecutionProofEnvelope` commits to the beacon block root instead
// of `PublicInput`, so its root should differ from the corresponding
// `ExecutionProof` root.
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

// `Hc` must not change the object root. That root is reused as both
// the gossip de-duplication key and the `object_root` for signing.
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

// `MAX_SIGNED_EXECUTION_PROOF_ENVELOPE_SIZE` is the pre-decode gossip
// bound, so it must equal the encoded size of a maximum-sized
// envelope.
#[test]
fn max_sized_envelope_encodes_to_max_signed_execution_proof_envelope_size() {
    let bytes = max_sized_signed_envelope()
        .to_ssz()
        .expect("envelope should be serializable");

    assert_eq!(bytes.len(), MAX_SIGNED_EXECUTION_PROOF_ENVELOPE_SIZE);
}

// Mirrors consensus-specs#5593
// `test_signed_execution_proof_envelope_rejects_oversize_proof_data`.
// `proof_data` is the last variable-size field, so one more byte
// lands in it, and decoding fails at the `ProofData` limit.
#[test]
fn signed_execution_proof_envelope_rejects_oversize_proof_data() {
    let mut bytes = max_sized_signed_envelope()
        .to_ssz()
        .expect("envelope should be serializable");

    bytes.push(0);

    assert_eq!(bytes.len(), MAX_SIGNED_EXECUTION_PROOF_ENVELOPE_SIZE + 1);

    assert_eq!(
        SignedExecutionProofEnvelope::from_ssz_default(&bytes)
            .expect_err("envelope should be rejected"),
        ReadError::ListTooLong {
            maximum: MAX_PROOF_SIZE,
            actual: MAX_PROOF_SIZE + 1,
        },
    );
}

fn max_sized_signed_envelope() -> SignedExecutionProofEnvelope {
    let proof_data =
        ProofData::try_from(vec![0; MAX_PROOF_SIZE]).expect("proof data should be within bounds");

    SignedExecutionProofEnvelope {
        message: Hc::from(ExecutionProofEnvelope {
            proof_data,
            proof_type: PROOF_TYPE,
            beacon_block_root: BEACON_BLOCK_ROOT,
        }),
        validator_index: VALIDATOR_INDEX,
        signature: test_signature(),
    }
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

// `ProofData` is a `ByteList` limited to `MAX_PROOF_SIZE`, so decoding
// rejects anything larger.
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

// Serde enforces the same bound as SSZ decoding and rejects oversize
// `proof_data`.
#[test]
fn proof_data_deserialization_rejects_oversize() {
    let json = format!("\"0x{}\"", "00".repeat(MAX_PROOF_SIZE.saturating_add(1)));

    let error =
        serde_json::from_str::<ProofData>(&json).expect_err("proof data should be rejected");

    assert!(error.to_string().contains("no more than"), "{error}");
}

// Built manually because the public API rejects oversize `ProofData`.
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

// Matches the reference implementation's `test_bytes`.
fn test_bytes(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index % 256).expect("value modulo 256 should fit in u8"))
        .collect()
}

// `NewPayloadRequest` is a progressive container, so its root is
// the progressive merkleization of the four field roots with the
// active-field layout mixed in, rather than the fixed-depth
// merkleization used by a plain container. The field roots themselves
// come from types already covered by `ssz_static` spec tests,
// including the Gloas `ExecutionPayload` and `ExecutionRequests`.
#[test]
fn new_payload_request_root_is_progressive_merkleization_of_field_roots() {
    let request = test_request::<Mainnet>();

    let field_roots = [
        request.execution_payload.hash_tree_root(),
        request.versioned_hashes.hash_tree_root(),
        request.parent_beacon_block_root.hash_tree_root(),
        request.execution_requests.hash_tree_root(),
    ];

    // Active-field layout: the low four bits of a 256-bit word, with
    // field 0 in the least significant bit.
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

// Binding is preset-independent under Gloas. The preset-derived bounds
// that affect the root are equal across Mainnet and Minimal, so the
// same logical request must hash identically under both presets.
#[test]
fn root_does_not_depend_on_preset() {
    assert_eq!(
        test_request::<Mainnet>().hash_tree_root(),
        test_request::<Minimal>().hash_tree_root(),
    );
}

// A progressive-container root is not simply the root of its first
// field.
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
    let decoded = NewPayloadRequest::<Mainnet>::from_ssz_default(&bytes)
        .expect("request should be decodable");

    assert_eq!(decoded, request);
    assert_eq!(decoded.hash_tree_root(), request.hash_tree_root());
}

#[test]
fn new_carries_the_fields_it_is_given() {
    let payload = test_combined_payload::<Mainnet>();
    let params = test_params::<Mainnet>();

    let request =
        NewPayloadRequest::<Mainnet>::new(&payload, &params).expect("request should be buildable");

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

// EIP-8025 binds the Gloas `ExecutionPayload` and `ExecutionRequests`.
// Electra params contain the Electra `ExecutionRequests`, a different
// container with a different root, so those params cannot be bound.
#[test]
fn new_rejects_pre_gloas_params() {
    let payload = test_combined_payload::<Mainnet>();

    let params = ExecutionPayloadParams::Deneb {
        versioned_hashes: vec![H256::repeat_byte(1)],
        parent_beacon_block_root: H256::repeat_byte(2),
    };

    let error = NewPayloadRequest::<Mainnet>::new(&payload, &params)
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

    let error = NewPayloadRequest::<Mainnet>::new(&payload, &params)
        .expect_err("Bellatrix payload should be rejected");

    assert!(
        matches!(error, PayloadBindingError::PayloadPhaseNotSupported { .. }),
        "{error}",
    );
}

// consensus-specs bounds `versioned_hashes` by
// `MAX_BLOB_COMMITMENTS_PER_BLOCK`, but derives them from the Gloas
// `blob_kzg_commitments`, an unbounded progressive list. Binding must
// reject a source list that exceeds the target bound.
#[test]
fn new_rejects_too_many_versioned_hashes() {
    let payload = test_combined_payload::<Mainnet>();
    let params = test_params_with_versioned_hashes::<Mainnet>(MAX_VERSIONED_HASHES + 1);

    let error = NewPayloadRequest::<Mainnet>::new(&payload, &params)
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

    let request = NewPayloadRequest::<Mainnet>::new(&payload, &params)
        .expect("the maximum number of versioned hashes should be accepted");

    assert_eq!(
        request.versioned_hashes.as_ref().len(),
        MAX_VERSIONED_HASHES
    );
}

fn test_params_with_versioned_hashes<P: Preset>(count: usize) -> ExecutionPayloadParams<P> {
    ExecutionPayloadParams::Gloas {
        versioned_hashes: vec![H256::repeat_byte(1); count],
        parent_beacon_block_root: H256::repeat_byte(3),
        execution_requests: ExecutionRequests::default(),
    }
}

fn test_request<P: Preset>() -> NewPayloadRequest<P> {
    NewPayloadRequest::new(&test_combined_payload::<P>(), &test_params::<P>())
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

#[test]
fn proof_attributes_json_round_trip() {
    let attributes = ProofAttributes {
        proof_types: vec![1, 2, 3],
    };

    let json = serde_json::to_string(&attributes).expect("attributes should be serializable");

    assert_eq!(json, r#"{"proof_types":["1","2","3"]}"#);

    let decoded: ProofAttributes =
        serde_json::from_str(&json).expect("attributes should be deserializable");

    assert_eq!(decoded, attributes);
}

#[test]
fn proof_attributes_accepts_native_integers() {
    let decoded: ProofAttributes = serde_json::from_str(r#"{"proof_types":[1,2]}"#)
        .expect("native integers should be accepted");

    assert_eq!(decoded.proof_types, vec![1, 2]);
}

// `ProofData` is a `ByteList`, so its serde form is unchanged: a
// transparent `0x`-prefixed hex string in human-readable formats.
#[test]
fn proof_data_json_is_a_hex_string() {
    let proof_data = test_proof_data(3);

    let json = serde_json::to_string(&proof_data).expect("proof data should be serializable");

    assert_eq!(json, r#""0x000102""#);

    let decoded =
        serde_json::from_str::<ProofData>(&json).expect("proof data should be deserializable");

    assert_eq!(decoded, proof_data);
}

// Before design 0005, `ProofData` serialized transparently as a
// `ProgressiveByteList<MaxProofSize>`. Serialization and the
// over-limit error must be the same as that form.
#[test_case(0)]
#[test_case(1)]
#[test_case(673)]
fn proof_data_serde_matches_progressive_byte_list(length: usize) {
    let progressive = ProgressiveByteList::<MaxProofSize>::try_from(test_bytes(length))
        .expect("bytes should be within bounds");

    assert_eq!(
        serde_json::to_string(&test_proof_data(length)).expect("proof data should be serializable"),
        serde_json::to_string(&progressive).expect("bytes should be serializable"),
    );
}

#[test]
fn proof_data_oversize_error_matches_progressive_byte_list() {
    let json = format!("\"0x{}\"", "00".repeat(MAX_PROOF_SIZE + 1));

    let error = serde_json::from_str::<ProofData>(&json)
        .expect_err("proof data should be rejected")
        .to_string();

    let progressive_error = serde_json::from_str::<ProgressiveByteList<MaxProofSize>>(&json)
        .expect_err("bytes should be rejected")
        .to_string();

    assert_eq!(error, progressive_error);
}

// `versioned_hashes` follows consensus-specs#5643: a progressive list,
// whose root differs from the bounded `List` root on `master`.
#[test]
fn versioned_hashes_root_is_progressive() {
    let request = test_request::<Mainnet>();

    let progressive =
        ProgressiveList::<H256>::try_from_iter(request.versioned_hashes.iter().copied())
            .expect("versioned hashes should fit");
    let bounded =
        ContiguousList::<H256, <Mainnet as Preset>::MaxBlobCommitmentsPerBlock>::try_from_iter(
            request.versioned_hashes.iter().copied(),
        )
        .expect("versioned hashes should fit");

    assert_eq!(
        request.versioned_hashes.hash_tree_root(),
        progressive.hash_tree_root()
    );
    assert_ne!(
        request.versioned_hashes.hash_tree_root(),
        bounded.hash_tree_root()
    );
}

#[test]
fn new_payload_request_decoding_accepts_max_versioned_hashes() {
    let bytes = encoded_request_with_versioned_hashes(MAX_VERSIONED_HASHES);

    let request = NewPayloadRequest::<Mainnet>::from_ssz_default(bytes)
        .expect("the maximum number of versioned hashes should be accepted");

    assert_eq!(request.versioned_hashes.len(), MAX_VERSIONED_HASHES);
}

#[test]
fn new_payload_request_decoding_rejects_too_many_versioned_hashes() {
    let bytes = encoded_request_with_versioned_hashes(MAX_VERSIONED_HASHES + 1);

    let result = NewPayloadRequest::<Mainnet>::from_ssz_default(bytes);

    assert_eq!(
        result.expect_err("too many versioned hashes should be rejected"),
        ReadError::ListTooLong {
            maximum: MAX_VERSIONED_HASHES,
            actual: MAX_VERSIONED_HASHES + 1,
        },
    );
}

// Built by splicing because the public API rejects too many versioned
// hashes. The progressive-container encoding of `NewPayloadRequest`
// starts with the `execution_payload` and `versioned_hashes` offsets,
// then `parent_beacon_block_root`, then the `execution_requests`
// offset, which is where `versioned_hashes` ends.
fn encoded_request_with_versioned_hashes(count: usize) -> Vec<u8> {
    let mut bytes = NewPayloadRequest::new(
        &test_combined_payload::<Mainnet>(),
        &test_params_with_versioned_hashes::<Mainnet>(0),
    )
    .expect("request should be buildable")
    .to_ssz()
    .expect("request should be serializable");

    let requests_offset_position = 4 + 4 + 32;
    let requests_offset_bytes = requests_offset_position..requests_offset_position + 4;

    let requests_offset = u32::from_le_bytes(
        bytes[requests_offset_bytes.clone()]
            .try_into()
            .expect("slice should have 4 bytes"),
    );
    let hashes_length = u32::try_from(count.saturating_mul(32)).expect("length should fit in u32");
    let hashes_start = usize::try_from(requests_offset).expect("offset should fit in usize");

    bytes[requests_offset_bytes]
        .copy_from_slice(&requests_offset.saturating_add(hashes_length).to_le_bytes());
    bytes.splice(
        hashes_start..hashes_start,
        H256::repeat_byte(1).as_bytes().repeat(count),
    );

    bytes
}

// UNVERIFIED (see the note at the top of this file): a payload-derived
// `NewPayloadRequest`, the `PublicInput` built from its root, and an
// `ExecutionProof` over that `PublicInput`.
#[test]
fn payload_derived_roots_match_reference() {
    let request = test_request::<Mainnet>();

    let public_input = PublicInput {
        new_payload_request_root: request.hash_tree_root(),
        ..test_public_input()
    };

    let proof = ExecutionProof {
        public_input,
        ..test_execution_proof(100)
    };

    assert_eq!(
        request.hash_tree_root(),
        H256(hex!(
            "89bee8914d2b8c53efc999586aa3d36adbd9493b0fdc747002702fe0469167af"
        )),
    );
    assert_eq!(
        public_input.hash_tree_root(),
        H256(hex!(
            "b384087a207dcc690196552d9a5e2982083f5fec8443a3e306ad22a6d4cd37d6"
        )),
    );
    assert_eq!(
        proof.hash_tree_root(),
        H256(hex!(
            "1499f0cbe5f366f41fbf7c6e0ab5f73db677bd113294ce1f803af3fd8a5744ca"
        )),
    );
}
