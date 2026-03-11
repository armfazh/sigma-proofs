//  SPDX-License-Identifier: BSD-2-Clause

//! The pseudo-random generator used for sampling scalars.

use core::array::from_fn;

use ff::PrimeField;
use group::Group;
use num_bigint::BigUint;
use num_traits::Num;
use rand_core::RngCore;
use spongefish::NargDeserialize;

pub fn random_scalars<G, const N: usize>(rng: &mut impl RngCore) -> [G::Scalar; N]
where
    G: Group,
    G::Scalar: NargDeserialize,
{
    from_fn(|_| scalar_from_uniform_bytes::<G>(|u| rng.fill_bytes(u)))
}

pub fn random_scalars_vec<G>(rng: &mut impl RngCore, len: usize) -> Vec<G::Scalar>
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
    let scalar_length = (<G::Scalar as PrimeField>::NUM_BITS as usize + 7) >> 3;
    let mut uniform_bytes = vec![0u8; scalar_length + EXTRA_BYTES];

    fill(&mut uniform_bytes);

    // OS2IP -- big-endian conversion
    let scalar = BigUint::from_bytes_be(&uniform_bytes);
    let reduced = scalar % order::<G::Scalar>();
    let reduced_bytes = reduced.to_bytes_be();
    G::Scalar::deserialize_from_narg(&mut reduced_bytes.as_slice()).expect("invalid sampled scalar")
}

fn order<F: PrimeField>() -> BigUint {
    let mut p = F::MODULUS;
    if p.starts_with("0x") {
        p = &p[2..]
    }
    BigUint::from_str_radix(p, 16).expect("invalid modulus")
}
