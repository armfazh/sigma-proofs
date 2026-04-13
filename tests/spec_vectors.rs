use bls12_381::G1Projective as Bls12381G1;
use group::prime::PrimeGroup;
use p256::ProjectivePoint as P256ProjectivePoint;
use rand_core::CryptoRngCore;
use spongefish::{Codec, Encoding, NargDeserialize, NargSerialize};

use sigma_proofs::{
    errors::Result,
    linear_relation::CanonicalLinearRelation,
    rng::ScalarCompatible,
    traits::{SigmaProtocol, SigmaProtocolSimulator, Transcript},
    MultiScalarMul, Nizk,
};

mod spec;
use spec::{rng::TestDrng, vectors::TestVector};

#[test]
fn test_spec_vectors_p256() {
    testvectors::<P256ProjectivePoint>(include_str!(
        "./spec/testdata/sigma-proofs_Shake128_P256.json"
    ));
}

#[test]
fn test_spec_vectors_bls12381() {
    testvectors::<Bls12381G1>(include_str!(
        "./spec/testdata/sigma-proofs_Shake128_BLS12381.json"
    ));
}

fn testvectors<G>(vectors_json: &str)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Codec,
{
    let test_vectors: Vec<TestVector> = serde_json::from_str(vectors_json)
        .map_err(|e| format!("JSON parsing error: {e}"))
        .unwrap();

    for vector in test_vectors {
        let test_name = vector.relation;
        let parsed_instance = CanonicalLinearRelation::<G>::from_label(&vector.statement.0)
            .expect("failed to parse statement");

        let witness = decode_scalars::<G>(&vector.witness.0);
        assert_eq!(
            witness.len(),
            parsed_instance.num_scalars,
            "witness length doesn't match instance scalars",
        );

        assert_eq!(
            parsed_instance.label(),
            vector.statement.0,
            "parsed statement doesn't match original for {test_name}"
        );

        let nizk = Nizk::new(&vector.session_id.0, Compatible(parsed_instance));

        assert!(
            nizk.verify_batchable(&vector.batchable_proof.0).is_ok(),
            "batchable proof from vectors did not verify for {test_name}"
        );
        assert!(
            nizk.verify_compact(&vector.proof.0).is_ok(),
            "compact proof from vectors did not verify for {test_name}"
        );

        let mut proof_rng = TestDrng::from_seed(b"proof_generation_seed");
        let batchable_proof = nizk.prove_batchable(&witness, &mut proof_rng).unwrap();
        assert_eq!(
            batchable_proof, vector.batchable_proof.0,
            "batchable proof bytes do not match for {test_name}"
        );

        let compact_proof = nizk.prove_compact(&witness, &mut proof_rng).unwrap();
        assert_eq!(
            compact_proof, vector.proof.0,
            "compact proof bytes do not match for {test_name}"
        );
    }
}

fn decode_scalars<G>(bytes: &[u8]) -> Vec<G::Scalar>
where
    G: PrimeGroup,
    G::Scalar: NargDeserialize,
{
    let mut cursor = bytes;
    let mut scalars = Vec::new();
    while !cursor.is_empty() {
        scalars.push(
            G::Scalar::deserialize_from_narg(&mut cursor).expect("failed to deserialize scalar"),
        );
    }
    scalars
}

struct Compatible<G>(CanonicalLinearRelation<G>)
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Codec;

impl<G> SigmaProtocol for Compatible<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Codec,
{
    type Commitment = G;
    type ProverState = (Vec<G::Scalar>, Vec<G::Scalar>);
    type Response = G::Scalar;
    type Witness = Vec<G::Scalar>;
    type Challenge = ScalarCompatible<G>;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<Self::Commitment>, Self::ProverState)> {
        self.0.prover_commit(witness, rng)
    }

    fn prover_response(
        &self,
        state: Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Vec<Self::Response>> {
        self.0.prover_response(state, &challenge.0)
    }

    fn verifier(
        &self,
        commitment: &[Self::Commitment],
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<()> {
        self.0.verifier(commitment, &challenge.0, response)
    }

    fn commitment_len(&self) -> usize {
        self.0.commitment_len()
    }

    fn response_len(&self) -> usize {
        self.0.response_len()
    }

    fn protocol_identifier(&self) -> [u8; 64] {
        self.0.protocol_identifier()
    }

    fn instance_label(&self) -> impl AsRef<[u8]> {
        self.0.instance_label()
    }
}

impl<G> SigmaProtocolSimulator for Compatible<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargSerialize + NargDeserialize + MultiScalarMul,
    G::Scalar: Codec,
{
    fn simulate_response(&self, rng: &mut impl CryptoRngCore) -> Vec<Self::Response> {
        self.0.simulate_response(rng)
    }

    fn simulate_commitment(
        &self,
        challenge: &Self::Challenge,
        response: &[Self::Response],
    ) -> Result<Vec<Self::Commitment>> {
        self.0.simulate_commitment(&challenge.0, response)
    }

    fn simulate_transcript(&self, rng: &mut impl CryptoRngCore) -> Result<Transcript<Self>> {
        let (a, b, c) = self.0.simulate_transcript(rng)?;
        Ok((a, ScalarCompatible(b), c))
    }
}
