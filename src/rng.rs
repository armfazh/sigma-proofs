//! The pseudo-random generator used for sampling scalars.

use alloc::vec::Vec;
use core::{array::from_fn, iter::repeat_with};

use group::Group;
use rand_core::CryptoRngCore;
use spongefish::Decoding;

use crate::{spec_compat::ScalarCompatible, traits::ScalarRng};

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
