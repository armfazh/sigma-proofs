//! Fiat-Shamir transformation for [`SigmaProtocol`]s.
//!
//! This module defines [`Nizk`], a generic non-interactive Sigma protocol wrapper,
//! based on applying the Fiat-Shamir heuristic using a codec.
//!
//! It transforms an interactive [`SigmaProtocol`] into a non-interactive one,
//! by deriving challenges deterministically from previous protocol messages
//! via a cryptographic sponge function (Codec).
//!
//! # Usage
//! This struct is generic over:
//! - `P`: the underlying Sigma protocol ([`SigmaProtocol`] trait).

use std::marker::PhantomData;

use crate::codec::Codec;
use crate::errors::Error;
use crate::group::serialization::{deserialize_messages, serialize_messages};
use crate::traits::{SigmaProtocol, SigmaProtocolSimulator};
use alloc::vec::Vec;
use ff::PrimeField;
use rand_core::CryptoRngCore;
use spongefish::{Encoding, NargDeserialize, NargSerialize};

/// A Fiat-Shamir transformation of a [`SigmaProtocol`] into a non-interactive proof.
///
/// [`Nizk`] wraps an interactive Sigma protocol `P`
/// and a codec `C`, to produce non-interactive proofs.
///
/// It manages the domain separation, codec reset,
/// proof generation, and proof verification.
///
/// # Type Parameters
/// - `P`: the Sigma protocol implementation.
/// - `C`: the codec used for Fiat-Shamir.
#[derive(Debug)]
pub struct Nizk<P, C>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq,
    C: Codec,
{
    pub session_id: Vec<u8>,
    /// Underlying interactive proof.
    pub interactive_proof: P,
    _phantom: PhantomData<C>,
}

impl<P, C> Nizk<P, C>
where
    P: SigmaProtocol,
    P::Challenge: PartialEq + PrimeField,
    P::Commitment: NargSerialize + NargDeserialize + Encoding,
    P::Response: NargSerialize + NargDeserialize + Encoding,
    C: Codec<Challenge = P::Challenge>,
{
    /// Constructs a new [`Nizk`] instance.
    ///
    /// # Parameters
    /// - `iv`: Domain separation tag for the hash function (e.g., protocol name or context).
    /// - `instance`: An instance of the interactive Sigma protocol.
    ///
    /// # Returns
    /// A new [`Nizk`] that can generate and verify non-interactive proofs.
    pub fn new(session_identifier: &[u8], interactive_proof: P) -> Self {
        Self {
            session_id: session_identifier.to_vec(),
            interactive_proof,
            _phantom: PhantomData,
        }
    }

    /// Generates a batchable, serialized non-interactive proof.
    ///
    /// # Parameters
    /// - `witness`: The secret witness.
    /// - `rng`: A cryptographically secure random number generator.
    ///
    /// # Returns
    /// A serialized proof suitable for batch verification.
    ///
    /// # Panics
    /// Panics if serialization fails (should not happen under correct implementation).
    pub fn prove_batchable(
        &self,
        witness: &P::Witness,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let protocol_id = self.interactive_proof.protocol_identifier();
        let instance_label = self.interactive_proof.instance_label();
        let (commitment, ip_state) = self.interactive_proof.prover_commit(witness, rng)?;
        let commitment_bytes = serialize_messages(&commitment);
        let mut codec = C::new(&protocol_id, &self.session_id, instance_label.as_ref());
        codec.prover_message(&commitment_bytes);
        let challenge = codec.verifier_challenge();
        let response = self
            .interactive_proof
            .prover_response(ip_state, &challenge)?;
        let mut proof = commitment_bytes;
        response.serialize_into_narg(&mut proof);
        Ok(proof)
    }

    /// Verifies a batchable non-interactive proof.
    ///
    /// # Parameters
    /// - `proof`: A serialized batchable proof.
    ///
    /// # Returns
    /// - `Ok(())` if the proof is valid.
    /// - `Err(Error)` if deserialization or verification fails.
    ///
    /// # Errors
    /// - Returns [`Error::VerificationFailure`] if:
    ///   - The challenge doesn't match the recomputed one from the commitment.
    ///   - The response fails verification under the Sigma protocol.
    pub fn verify_batchable(&self, narg_string: &[u8]) -> Result<(), Error> {
        let protocol_id = self.interactive_proof.protocol_identifier();
        let instance_label = self.interactive_proof.instance_label();
        let commitment_len = self.interactive_proof.commitment_len();
        let response_len = self.interactive_proof.response_len();
        let mut cursor = narg_string;
        let commitment = deserialize_messages(commitment_len, &mut cursor)?;
        let commitment_bytes = serialize_messages(&commitment);
        let mut codec = C::new(&protocol_id, &self.session_id, instance_label.as_ref());
        codec.prover_message(&commitment_bytes);
        let challenge = codec.verifier_challenge();
        let response = deserialize_messages(response_len, &mut cursor)?;
        if !cursor.is_empty() {
            return Err(Error::VerificationFailure);
        }
        self.interactive_proof
            .verifier(&commitment, &challenge, &response)
    }
}

impl<P, C> Nizk<P, C>
where
    P: SigmaProtocol + SigmaProtocolSimulator,
    P::Challenge: PartialEq + NargDeserialize + NargSerialize + PrimeField,
    C: Codec<Challenge = P::Challenge>,
{
    /// Generates a compact serialized proof.
    ///
    /// Uses a more space-efficient representation compared to batchable proofs.
    ///
    /// # Parameters
    /// - `witness`: The secret witness.
    /// - `rng`: A cryptographically secure random number generator.
    ///
    /// # Returns
    /// A compact, serialized proof.
    ///
    /// # Panics
    /// Panics if serialization fails.
    pub fn prove_compact(
        &self,
        witness: &P::Witness,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let protocol_id = self.interactive_proof.protocol_identifier();
        let instance_label = self.interactive_proof.instance_label();
        let (commitment, ip_state) = self.interactive_proof.prover_commit(witness, rng)?;
        let commitment_bytes = serialize_messages(&commitment);
        let mut codec = C::new(&protocol_id, &self.session_id, instance_label.as_ref());
        codec.prover_message(&commitment_bytes);
        let challenge = codec.verifier_challenge();
        let response = self
            .interactive_proof
            .prover_response(ip_state, &challenge)?;

        // Serialize the compact proof string.
        let mut proof = Vec::new();
        challenge.serialize_into_narg(&mut proof);
        response.serialize_into_narg(&mut proof);
        Ok(proof)
    }

    /// Verifies a compact proof.
    ///
    /// Recomputes the commitment from the challenge and response, then verifies it.
    ///
    /// # Parameters
    /// - `proof`: A compact serialized proof.
    ///
    /// # Returns
    /// - `Ok(())` if the proof is valid.
    /// - `Err(Error)` if deserialization or verification fails.
    ///
    /// # Errors
    /// - Returns [`Error::VerificationFailure`] if:
    ///   - Deserialization fails.
    ///   - The recomputed commitment or response is invalid under the Sigma protocol.
    pub fn verify_compact(&self, proof: &[u8]) -> Result<(), Error> {
        // Deserialize challenge and response from compact proof
        let mut cursor = proof;
        let protocol_id = self.interactive_proof.protocol_identifier();
        let instance_label = self.interactive_proof.instance_label();
        let challenge = P::Challenge::deserialize_from_narg(&mut cursor)?;
        let response_len = self.interactive_proof.response_len();
        let response = deserialize_messages(response_len, &mut cursor)?;

        // Proof size check
        if !cursor.is_empty() {
            return Err(Error::VerificationFailure);
        }

        // Compute the commitments
        let commitment = self
            .interactive_proof
            .simulate_commitment(&challenge, &response)?;

        // Re-compute the challenge and ensure it's the same as the one
        // we received
        let commitment_bytes = serialize_messages(&commitment);
        let mut codec = C::new(&protocol_id, &self.session_id, instance_label.as_ref());
        codec.prover_message(&commitment_bytes);
        let recomputed_challenge = codec.verifier_challenge();
        if challenge != recomputed_challenge {
            return Err(Error::VerificationFailure);
        }

        // At this point, checking
        // self.interactive_proof.verifier(&commitment, &challenge,
        // &response) is redundant, because we know that commitment =
        // simulate_commitment(challenge, response), and that challenge
        // is the output of the appropriate hash, so the signature is
        // valid.
        Ok(())
    }
}
