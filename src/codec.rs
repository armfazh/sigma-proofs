//! Encoding and decoding utilities for Fiat-Shamir and group operations.

use core::marker::PhantomData;

use group::Group;
use spongefish::NargDeserialize;

use crate::{
    duplex_sponge::{keccak::KeccakDuplexSponge, shake::ShakeDuplexSponge, DuplexSpongeInterface},
    rng::scalar_from_uniform_bytes,
};

/// A trait defining the behavior of a domain-separated codec hashing, which is typically used for [`crate::traits::SigmaProtocol`]s.
///
/// A domain-separated hashing codec is a codec, identified by a domain, which is incremented with successive messages ("absorb"). The codec can then output a bit stream of any length, which is typically used to generate a challenge unique to the given codec ("squeeze"). (See Sponge Construction).
///
/// The output is deterministic for a given set of input. Thus, both Prover and Verifier can generate the codec on their sides and ensure the same inputs have been used in both side of the protocol.
///
/// ## Minimal Implementation
/// Types implementing [`Codec`] must define:
/// - `new`
/// - `prover_message`
/// - `verifier_challenge`
pub trait Codec {
    type Challenge;

    /// Generates an empty codec that can be identified by a domain separator.
    fn new(
        protocol_identifier: &[u8; 64],
        session_identifier: &[u8],
        instance_label: &[u8],
    ) -> Self;

    /// Absorbs data into the codec.
    fn prover_message(&mut self, data: &[u8]);

    /// Produces a scalar that can be used as a challenge from the codec.
    fn verifier_challenge(&mut self) -> Self::Challenge;
}

/// A byte-level Schnorr codec that works with any duplex sponge.
///
/// This codec is generic over both the group `G` and the hash function `H`.
/// It can be used with different duplex sponge implementations.
#[derive(Clone)]
pub struct ByteSchnorrCodec<G, H>
where
    G: Group,
    H: DuplexSpongeInterface,
{
    sponge: H,
    _marker: PhantomData<G>,
}

impl<G, H> Codec for ByteSchnorrCodec<G, H>
where
    G: Group,
    G::Scalar: NargDeserialize,
    H: DuplexSpongeInterface,
{
    type Challenge = G::Scalar;

    fn new(protocol_id: &[u8; 64], session: &[u8], instance_label: &[u8]) -> Self {
        const PREFIX: &[u8] = b"fiat-shamir/session-id";
        let mut iv = [0u8; 64];
        iv[..PREFIX.len()].copy_from_slice(PREFIX);

        let mut session_hash_state = H::new(iv);
        session_hash_state.absorb(session);

        let mut sponge = H::new(*protocol_id);
        sponge.absorb(&[0; 32]);
        sponge.absorb(&session_hash_state.squeeze(32));
        sponge.absorb(instance_label);
        Self {
            sponge,
            _marker: PhantomData,
        }
    }

    fn prover_message(&mut self, data: &[u8]) {
        self.sponge.absorb(data);
    }

    fn verifier_challenge(&mut self) -> Self::Challenge {
        scalar_from_uniform_bytes::<G>(|u| {
            u.copy_from_slice(&self.sponge.squeeze(u.len()));
        })
    }
}

/// Type alias for a Keccak-based ByteSchnorrCodec.
/// This is the codec used for matching test vectors from Sage.
pub type KeccakByteSchnorrCodec<G> = ByteSchnorrCodec<G, KeccakDuplexSponge>;

/// Type alias for a SHAKE-based ByteSchnorrCodec.
pub type Shake128ByteSchnorrCodec<G> = ByteSchnorrCodec<G, ShakeDuplexSponge>;
