//  SPDX-License-Identifier: BSD-2-Clause

//! The pseudo-random generator used for sampling scalars.

use core::array::from_fn;

use ff::{Field, PrimeField};
use group::Group;
use num_bigint::BigUint;
use num_traits::Num;
use rand_core::RngCore;

pub fn random_scalars<G: Group, const N: usize>(rng: &mut impl RngCore) -> [G::Scalar; N] {
    from_fn(|_| scalar_from_uniform_bytes::<G>(|u| rng.fill_bytes(u)))
}

pub fn random_scalars_vec<G: Group>(rng: &mut impl RngCore, len: usize) -> Vec<G::Scalar> {
    (0..len)
        .map(|_| scalar_from_uniform_bytes::<G>(|u| rng.fill_bytes(u)))
        .collect()
}

pub(crate) fn scalar_from_uniform_bytes<G: Group>(mut fill: impl FnMut(&mut [u8])) -> G::Scalar {
    const EXTRA_BYTES: usize = 16;
    let scalar_length = (<G::Scalar as PrimeField>::NUM_BITS as usize + 7) >> 3;
    let mut uniform_bytes = vec![0u8; scalar_length + EXTRA_BYTES];

    fill(&mut uniform_bytes);

    // OS2IP -- big-endian conversion
    let scalar = BigUint::from_bytes_be(&uniform_bytes);
    let reduced = scalar % order::<G::Scalar>();
    let reduced_bytes = reduced.to_bytes_be();

    let mut repr = <G::Scalar as Field>::ZERO.to_repr();
    let start = repr.as_ref().len() - reduced_bytes.len();
    repr.as_mut()[start..].copy_from_slice(&reduced_bytes);

    if isLittleEndian::<G>() {
        repr.as_mut().reverse();
    }

    G::Scalar::from_repr(repr).expect("invalid scalar representation")
}

fn order<F: PrimeField>() -> BigUint {
    let mut p = F::MODULUS;
    if p.starts_with("0x") {
        p = &p[2..]
    }
    BigUint::from_str_radix(p, 16).expect("invalid modulus")
}

// Check endianess of G::Scalar::Repr
fn isLittleEndian<G: Group>() -> bool {
    <G::Scalar as Field>::ONE.to_repr().as_ref()[0] == 0x01
}
