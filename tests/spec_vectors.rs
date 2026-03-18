use bls12_381::G1Projective as BLS12381_Group;
use group::prime::PrimeGroup;
use p256::ProjectivePoint as P256_Group;
use rand::SeedableRng;
use spongefish::{Codec, Encoding, NargDeserialize, NargSerialize};

use sigma_proofs::linear_relation::CanonicalLinearRelation;

mod spec;
use spec::{rng::TestDRNG, vectors::TestVector};

#[test]
fn test_spec_testvectors_bls12381() {
    let vectors_json = include_str!("./spec/vectors/sigma-proofs_Shake128_BLS12381.json");
    testvectors::<BLS12381_Group>(vectors_json);
}

#[test]
fn test_spec_testvectors_p256() {
    let vectors_json = include_str!("./spec/vectors/sigma-proofs_Shake128_P256.json");
    testvectors::<P256_Group>(vectors_json);
}

fn testvectors<G>(vectors_json: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Codec,
{
    const PROOF_RNG_SEED: [u8; 32] = *b"proof_generation_seed\0\0\0\0\0\0\0\0\0\0\0";

    let test_vectors: Vec<TestVector> = serde_json::from_str(vectors_json)
        .map_err(|e| format!("JSON parsing error: {e}"))
        .unwrap();

    for vector in test_vectors {
        let mut proof_rng = TestDRNG::from_seed(PROOF_RNG_SEED);
        let test_name = vector.Relation;
        // Parse the statement from the test vector
        let mut parsed_instance = CanonicalLinearRelation::<G>::from_label(&vector.Statement.0)
            .expect("Failed to parse statement");

        // Assign protocol identifier
        parsed_instance.protocol_id = vector.Ciphersuite.as_bytes().to_vec();

        // Decode the witness from the test vector
        let mut cursor = vector.Witness.0.as_slice();
        let witness: Vec<_> = (0..parsed_instance.num_scalars)
            .map(|_| {
                G::Scalar::deserialize_from_narg(&mut cursor)
                    .expect("Failed to deserialize witness")
            })
            .collect();
        assert_eq!(
            witness.len(),
            parsed_instance.num_scalars,
            "witness length doesn't match instance scalars"
        );

        // Verify the parsed instance can be re-serialized to the same label
        assert_eq!(
            parsed_instance.label(),
            vector.Statement.0,
            "parsed statement doesn't match original for {test_name}"
        );

        // Create NIZK with the session_id from the test vector
        let nizk = parsed_instance
            .into_nizk(&vector.SessionId.0)
            .expect("nizk failed");

        // Commitment_response format
        {
            // Verify that the computed IV matches the test vector IV
            // Ensure the provided test vector proof verifies.
            let verification_result = nizk.verify_batchable(&vector.BatchableProof.0);
            assert!(
                verification_result.is_ok(),
                "Fiat-Shamir Schnorr proof from vectors did not verify for {test_name}: {verification_result:?}"
            );

            // Generate proof with the proof generation RNG
            let proof_batchable = nizk.prove_batchable(&witness, &mut proof_rng).unwrap();

            // Verify the proof matches
            assert_eq!(
                proof_batchable, vector.BatchableProof.0,
                "proof bytes for test vector {test_name} do not match"
            );

            // Verify the proof is valid
            let verified = nizk.verify_batchable(&proof_batchable).is_ok();
            assert!(
                verified,
                "Fiat-Shamir Schnorr proof verification failed for {test_name}"
            );
        }

        // Challenge_response format
        {
            // Ensure the provided test vector proof verifies.
            let verification_result = nizk.verify_compact(&vector.Proof.0);
            assert!(
            verification_result.is_ok(),
                "Fiat-Shamir Schnorr proof from vectors did not verify for {test_name}: {verification_result:?}"
            );

            // Generate proof with the proof generation RNG
            let proof_compact = nizk.prove_compact(&witness, &mut proof_rng).unwrap();

            // Verify the proof matches
            assert_eq!(
                proof_compact, vector.Proof.0,
                "proof bytes for test vector {test_name} do not match"
            );

            // Verify the proof is valid
            let verified = nizk.verify_compact(&proof_compact).is_ok();
            assert!(
                verified,
                "Fiat-Shamir Schnorr proof verification failed for {test_name}"
            );
        }
    }
}
