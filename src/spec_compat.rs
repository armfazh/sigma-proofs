//! Changes needed to be specification-compatible with sigma/f-s drafts.
//!
//! Compaatibility
//!
//! The sigma proofs draft [] and Fiat-Shamir draft [] have reference
//! implementations. This module is used to keep this crate aligned
//! to the specification documents. Ideally, this module should not exists.

use alloc::vec::Vec;
use core::marker::PhantomData;

use group::{ff::PrimeField, prime::PrimeGroup, Group};
use rand_core::CryptoRngCore;
use spongefish::{Codec, Decoding, Encoding, NargDeserialize};

use crate::{
    errors::Result,
    linear_relation::{CanonicalLinearRelation, ScalarTerm},
    traits::{SigmaProtocol, SigmaProtocolSimulator, Transcript},
    LinearRelation, MultiScalarMul, Nizk,
};

pub struct ScalarCompatibleRepr<G: Group>(Vec<u8>, PhantomData<G>);

impl<G: Group> Default for ScalarCompatibleRepr<G> {
    fn default() -> Self {
        const EXTRA_BYTES: usize = 16;
        let Ns = (<G::Scalar as PrimeField>::NUM_BITS as usize + 7) >> 3;
        Self(alloc::vec![0u8; Ns + EXTRA_BYTES], PhantomData)
    }
}

impl<G: Group> AsMut<[u8]> for ScalarCompatibleRepr<G> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

// Spec requires to sample Ns+16 bytes and reduce modulo the order.
#[derive(PartialEq, NargDeserialize)]
pub struct ScalarCompatible<G>(pub G::Scalar)
where
    G: Group,
    G::Scalar: Decoding<[u8]>;

impl<G> Decoding<[u8]> for ScalarCompatible<G>
where
    G: Group,
    G::Scalar: Decoding<[u8]>,
{
    type Repr = ScalarCompatibleRepr<G>;

    fn decode(buf: Self::Repr) -> Self {
        let mut repr = <G::Scalar as Decoding>::Repr::default();
        if let Some(start) = repr.as_mut().len().checked_sub(buf.0.len()) {
            repr.as_mut()[start..].copy_from_slice(&buf.0);
            Self(G::Scalar::decode(repr))
        } else {
            unreachable!("scalar representation is shorter than the sampled bytes")
        }
    }
}

impl<G> Encoding<[u8]> for ScalarCompatible<G>
where
    G: Group,
    G::Scalar: Encoding<[u8]> + Decoding<[u8]>,
{
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0.encode()
    }
}

pub struct CanonicalLinearRelationCompatible<G: PrimeGroup>(pub CanonicalLinearRelation<G>);

impl<G> CanonicalLinearRelationCompatible<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargDeserialize + MultiScalarMul,
    G::Scalar: Codec,
{
    /// Create a new canonical linear relation from an arbitrary linear relation.
    ///
    /// It is used to build a canonical linear relation directly from a linear relation.
    /// No optimizations and checks are performed so to be compliant with sigma proofs spec.
    /// See Issue: https://github.com/mmaker/draft-irtf-cfrg-sigma-protocols/issues/143
    pub fn new_from_lr(statement: LinearRelation<G>) -> Self {
        let linear_combinations = statement
            .linear_map
            .linear_combinations
            .iter()
            .map(|lc| {
                lc.0.iter()
                    .filter_map(|w| {
                        if let ScalarTerm::Var(scalar_var) = w.term.scalar {
                            Some((scalar_var, w.term.elem))
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .collect();

        Self(CanonicalLinearRelation {
            image: statement.image,
            linear_combinations,
            group_elements: statement.linear_map.group_elements,
            num_scalars: statement.linear_map.num_scalars,
        })
    }

    pub fn into_nizk(self, session_identifier: &[u8]) -> Result<Nizk<Self>> {
        Ok(Nizk::new(session_identifier, self))
    }
}

impl<G> SigmaProtocol for CanonicalLinearRelationCompatible<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargDeserialize + MultiScalarMul,
    G::Scalar: Codec,
{
    type Commitment = G;
    type ProverState = (Vec<G::Scalar>, Vec<G::Scalar>);
    type Response = G::Scalar;
    type Witness = Vec<G::Scalar>;
    // Challenge is sampled from a sponge
    // Spec requires to sample Ns+16 bytes and reduce modulo the order.
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

impl<G> SigmaProtocolSimulator for CanonicalLinearRelationCompatible<G>
where
    G: PrimeGroup + Encoding<[u8]> + NargDeserialize + MultiScalarMul,
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
