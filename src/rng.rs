//! The pseudo-random generator used for sampling scalars.

use alloc::vec::Vec;
use core::{array::from_fn, iter::repeat_with, marker::PhantomData};

use group::{ff::PrimeField, Group};
use rand_core::CryptoRngCore;
use spongefish::{Decoding, Encoding, NargDeserialize};

use crate::traits::ScalarRng;

/// Blanket implementation for all types that implement [`group::Group`] and
/// its Scalar field implements [`spongefish::Decoding<u8>`].
impl<G> ScalarRng for G
where
    G: Group,
    G::Scalar: Decoding<[u8]>,
{
    fn random_scalars<const N: usize>(rng: &mut impl CryptoRngCore) -> [G::Scalar; N] {
        from_fn(|_| sample_by_decoding::<G>(rng))
    }

    fn random_scalars_vec(rng: &mut impl CryptoRngCore, n: usize) -> Vec<G::Scalar> {
        let mut v = Vec::with_capacity(n);
        v.extend(repeat_with(|| sample_by_decoding::<G>(rng)).take(n));
        v
    }
}

/// Returns a type by decoding a byte string sampled from a
/// cryptographically-secure random source of bytes.
fn sample_by_decoding<G>(rng: &mut impl CryptoRngCore) -> G::Scalar
where
    G: Group,
    G::Scalar: Decoding<[u8]>,
{
    let mut rep = <ScalarCompatible<G> as Decoding>::Repr::default();
    rng.fill_bytes(rep.as_mut());
    ScalarCompatible::decode(rep).0
}

pub struct ScalarCompatibleRepr<G: Group>(Vec<u8>, PhantomData<G>);

impl<G: Group> Default for ScalarCompatibleRepr<G> {
    fn default() -> Self {
        const EXTRA_BYTES: usize = 16;
        let Ns = (<G::Scalar as PrimeField>::NUM_BITS as usize + 7) >> 3;
        Self(vec![0u8; Ns + EXTRA_BYTES], PhantomData)
    }
}

impl<G: Group> AsMut<[u8]> for ScalarCompatibleRepr<G> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

#[derive(PartialEq, Clone, Encoding, NargDeserialize)]
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
            unreachable!("scalar representation is shorter than sampled bytes")
        }
    }
}
