use std::sync::Arc;

use types::{
    eip8025::containers::{ExecutionProof, ProofData, PublicInput},
    phase0::primitives::H256,
};

use crate::{MockProofEngine, NullProofEngine, ProofEngine};

pub fn test_proof() -> ExecutionProof {
    ExecutionProof {
        proof_data: ProofData::try_from(vec![1, 2, 3])
            .expect("small proof data should be within bounds"),
        proof_type: 1,
        public_input: PublicInput {
            new_payload_request_root: H256::default(),
            successful_validation: true,
            chain_id: 5,
            schema_id: 0x1501,
        },
    }
}

// Callers hold the engine as `Arc<dyn ProofEngine>`, so `ProofEngine` must
// stay object-safe. This fails to compile if it stops being so.
#[test]
fn engines_work_behind_a_trait_object() {
    let null: Arc<dyn ProofEngine> = Arc::new(NullProofEngine);
    let valid: Arc<dyn ProofEngine> = Arc::new(MockProofEngine::new(true));
    let invalid: Arc<dyn ProofEngine> = Arc::new(MockProofEngine::new(false));

    assert!(null.is_null());
    assert!(!null.verify_execution_proof(test_proof()));

    assert!(!valid.is_null());
    assert!(valid.verify_execution_proof(test_proof()));

    assert!(!invalid.is_null());
    assert!(!invalid.verify_execution_proof(test_proof()));
}
