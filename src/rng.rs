//! The pseudo-random generator used for sampling scalars.

use alloc::vec::Vec;
use core::{array::from_fn, iter::repeat_with};

use group::{ff::PrimeField, Group};
use rand_core::CryptoRngCore;
use spongefish::Decoding;

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
    const EXTRA_BYTES: usize = 16;
    let Ns = (<G::Scalar as PrimeField>::NUM_BITS as usize + 7) >> 3;
    let mut buf = vec![0; Ns + EXTRA_BYTES];
    rng.fill_bytes(&mut buf);

    let mut repr = <G::Scalar as Decoding>::Repr::default();
    if let Some(start) = repr.as_mut().len().checked_sub(buf.len()) {
        repr.as_mut()[start..].copy_from_slice(&buf);
        G::Scalar::decode(repr)
    } else {
        unreachable!("scalar representation is shorter than sampled bytes")
    }
}
