use bls::SignatureBytes;
use hex_literal::hex;
use ssz::{H256, Hc, ReadError, SszHash as _, SszReadDefault as _, SszWrite as _};
use test_case::test_case;

use crate::{
    eip8025::{
        consts::{MAX_PROOF_SIZE, MAX_SIGNED_EXECUTION_PROOF_SIZE},
        containers::{ExecutionProof, ProofData, PublicInput, SignedExecutionProof},
        primitives::ProofType,
    },
    phase0::primitives::ValidatorIndex,
};

// Sample values mirrored exactly in the reference implementation.
const NEW_PAYLOAD_REQUEST_ROOT: H256 = H256(hex!(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
));
const PROOF_TYPE: ProofType = 7;
const VALIDATOR_INDEX: ValidatorIndex = 12345;

// The fixed part of `ExecutionProof`: an offset, a `ProofType` and a `PublicInput`.
const EXECUTION_PROOF_FIXED_PART: usize = 37;

// A one field container merkleizes to the root of that field, so `PublicInput` is transparent.
// This is worth pinning because `public_input.new_payload_request_root` is the only link between
// a proof and the payload it certifies.
#[test]
fn public_input_root_is_new_payload_request_root() {
    let public_input = PublicInput {
        new_payload_request_root: NEW_PAYLOAD_REQUEST_ROOT,
    };

    assert_eq!(public_input.hash_tree_root(), NEW_PAYLOAD_REQUEST_ROOT);
}

// The expected roots below were produced by an independent implementation of the container
// merkleization rules transcribed from `ssz/simple-serialize.md` and the EIP-8025 container
// definitions at the pinned `consensus-specs` revision.
//
// They are NOT cross-checked against the pyspec, which design 0001 requires and which cannot be
// run here. No `ssz_static` vectors exist for EIP-8025 either. That verification gap is open.
#[test_case(
    0,
    hex!("18876761dbeab44840a04ba1a2ba142ea6525392719c01194b805f489e884f11"),
    hex!("32f6f3b37358978f25b0b0d4133516fb72a4d9d0b86c688d07aa206d3bda4a3e")
)]
#[test_case(
    1,
    hex!("7f8e92f93732abac6c7ba2691c57c7cf906b4e8e0e2c66ece974b7815c3d14ba"),
    hex!("10c518f8141fabfa4498b2bbdf798ad50010c2e8e415aeb644ac07ea6802f2e9")
)]
#[test_case(
    32,
    hex!("625bd44b3aff595da380261fb7ee6613fab2478426d5d05641f295f23aeab34a"),
    hex!("84e5a8513bd287707c9a3f70a34fb7b1d0654e97d02707e9c5d893f1553c955e")
)]
#[test_case(
    100,
    hex!("9727e301e9d88ac931277369c166b74568fd7b5172417944a7245a43a08cfbf5"),
    hex!("e958b5861e3e0500ead3be47c9aadcffb7cec9332a7f14dd1ddcf2035f033c2d")
)]
#[test_case(
    673,
    hex!("4c3cd776036346e9ebbc79a8c3c96900ed9e9b6639054fdd3b58df16040b7f1e"),
    hex!("1c1c4c2bf75b21cf8eee91a8f9e8fcbd98e2bb2e4a13406b7c511d094d8d76ad")
)]
fn container_roots_match_reference(
    proof_data_length: usize,
    expected_proof_root: [u8; 32],
    expected_signed_root: [u8; 32],
) {
    let signed = test_signed_proof(proof_data_length);

    assert_eq!(signed.message.hash_tree_root(), H256(expected_proof_root));
    assert_eq!(signed.hash_tree_root(), H256(expected_signed_root));
}

// The `Hc` wrapper must not change the object root. That root is both the gossip de-duplication
// key and the `object_root` the signing root is built from, so the two must agree.
#[test]
fn hc_wrapper_preserves_object_root() {
    let signed = test_signed_proof(100);
    let bare = ExecutionProof::clone(&signed.message);

    assert_eq!(signed.message.hash_tree_root(), bare.hash_tree_root());
}

#[test_case(0)]
#[test_case(1)]
#[test_case(673)]
fn signed_execution_proof_ssz_round_trip(proof_data_length: usize) {
    let signed = test_signed_proof(proof_data_length);

    let bytes = signed.to_ssz().expect("proof should be serializable");
    let decoded =
        SignedExecutionProof::from_ssz_default(&bytes).expect("proof should be decodable");

    assert_eq!(decoded, signed);
    assert_eq!(decoded.hash_tree_root(), signed.hash_tree_root());
}

// `MAX_SIGNED_EXECUTION_PROOF_SIZE` is the bound gossip must apply before decoding, so it has to
// match what a maximum-sized proof actually encodes to.
#[test]
fn max_sized_proof_encodes_to_max_signed_execution_proof_size() {
    let proof_data =
        ProofData::try_from(vec![0; MAX_PROOF_SIZE]).expect("proof data should be within bounds");

    let signed = SignedExecutionProof {
        message: Hc::from(ExecutionProof {
            proof_data,
            proof_type: PROOF_TYPE,
            public_input: PublicInput {
                new_payload_request_root: NEW_PAYLOAD_REQUEST_ROOT,
            },
        }),
        validator_index: VALIDATOR_INDEX,
        signature: test_signature(),
    };

    let bytes = signed.to_ssz().expect("proof should be serializable");

    assert_eq!(bytes.len(), MAX_SIGNED_EXECUTION_PROOF_SIZE);
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

// `ProofData` is a progressive list and so unbounded at the type level. The design requires
// `ExecutionProof` decoding to reject oversize `proof_data` explicitly.
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
fn execution_proof_decoding_accepts_max_size_proof_data() {
    let bytes = encoded_execution_proof(MAX_PROOF_SIZE);

    let proof = ExecutionProof::from_ssz_default(&bytes).expect("proof should be decodable");

    assert_eq!(proof.proof_data.as_bytes().len(), MAX_PROOF_SIZE);
}

#[test]
fn execution_proof_json_round_trip() {
    let proof = ExecutionProof::clone(&test_signed_proof(100).message);

    let json = serde_json::to_string(&proof).expect("proof should be serializable");
    let decoded =
        serde_json::from_str::<ExecutionProof>(&json).expect("proof should be deserializable");

    assert_eq!(decoded, proof);
    assert_eq!(decoded.hash_tree_root(), proof.hash_tree_root());
}

// The serde path shares the bound with SSZ decoding, so it rejects oversize `proof_data` too.
#[test]
fn proof_data_deserialization_rejects_oversize() {
    let json = format!("\"0x{}\"", "00".repeat(MAX_PROOF_SIZE.saturating_add(1)));

    let error =
        serde_json::from_str::<ProofData>(&json).expect_err("proof data should be rejected");

    assert!(error.to_string().contains("no more than"), "{error}");
}

// Hand-built because `ProofData` cannot be constructed oversize through the public API.
fn encoded_execution_proof(proof_data_length: usize) -> Vec<u8> {
    let length = EXECUTION_PROOF_FIXED_PART.saturating_add(proof_data_length);

    let mut bytes = Vec::with_capacity(length);

    let offset = u32::try_from(EXECUTION_PROOF_FIXED_PART).expect("offset should fit in u32");

    bytes.extend_from_slice(&offset.to_le_bytes());
    bytes.push(PROOF_TYPE);
    bytes.extend_from_slice(NEW_PAYLOAD_REQUEST_ROOT.as_bytes());
    bytes.resize(length, 0);

    bytes
}

fn test_signed_proof(proof_data_length: usize) -> SignedExecutionProof {
    let proof_data = ProofData::try_from(test_bytes(proof_data_length))
        .expect("proof data should be within bounds");

    SignedExecutionProof {
        message: Hc::from(ExecutionProof {
            proof_data,
            proof_type: PROOF_TYPE,
            public_input: PublicInput {
                new_payload_request_root: NEW_PAYLOAD_REQUEST_ROOT,
            },
        }),
        validator_index: VALIDATOR_INDEX,
        signature: test_signature(),
    }
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
