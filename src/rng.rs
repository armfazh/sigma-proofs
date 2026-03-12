//  SPDX-License-Identifier: BSD-2-Clause

//! The pseudo-random generator used for sampling scalars.

use core::array::from_fn;

use alloc::vec::Vec;
use ff::PrimeField;
use group::Group;
use num_bigint::BigUint;
use num_traits::Num;
use rand_core::CryptoRngCore;
use spongefish::NargDeserialize;

pub fn random_scalars<G, const N: usize>(rng: &mut impl CryptoRngCore) -> [G::Scalar; N]
where
    G: Group,
    G::Scalar: NargDeserialize,
{
    from_fn(|_| scalar_from_uniform_bytes::<G>(|u| rng.fill_bytes(u)))
}

pub fn random_scalars_vec<G>(rng: &mut impl CryptoRngCore, len: usize) -> Vec<G::Scalar>
where
    G: Group,
    G::Scalar: NargDeserialize,
{
    (0..len)
        .map(|_| scalar_from_uniform_bytes::<G>(|u| rng.fill_bytes(u)))
        .collect()
}

pub(crate) fn scalar_from_uniform_bytes<G>(fill: impl FnOnce(&mut [u8])) -> G::Scalar
where
    G: Group,
    G::Scalar: NargDeserialize,
{
    const EXTRA_BYTES: usize = 16;
    let scalar_length = (G::Scalar::NUM_BITS as usize + 7) >> 3;
    let mut uniform_bytes = alloc::vec![0u8; scalar_length + EXTRA_BYTES];

    fill(&mut uniform_bytes);

    // OS2IP -- big-endian conversion
    let scalar = BigUint::from_bytes_be(&uniform_bytes);
    let reduced = scalar % order::<G::Scalar>();
    let reduced_bytes = reduced.to_bytes_be();
    let padded = &mut uniform_bytes[..scalar_length];
    padded.fill(0);
    padded[scalar_length - reduced_bytes.len()..].copy_from_slice(&reduced_bytes);
    G::Scalar::deserialize_from_narg(&mut &*padded).expect("invalid sampled scalar")
}

fn order<F: PrimeField>() -> BigUint {
    let mut p = F::MODULUS;
    if p.starts_with("0x") {
        p = &p[2..]
    }
    BigUint::from_str_radix(p, 16).expect("invalid modulus")
}
