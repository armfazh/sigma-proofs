use rand_core::{Error, RngCore, SeedableRng};

use sigma_proofs::{DuplexSpongeInterface, ShakeDuplexSponge};

pub struct TestDRNG {
    sponge: ShakeDuplexSponge,
    offset: usize,
}

impl SeedableRng for TestDRNG {
    type Seed = [u8; 32];

    fn from_seed(seed: Self::Seed) -> Self {
        let iv_prefix = b"sigma-proofs/TestDRNG/SHAKE128";
        let mut iv = [0u8; 64];
        iv[..iv_prefix.len()].copy_from_slice(iv_prefix);
        let mut sponge = ShakeDuplexSponge::new(iv);
        sponge.absorb(&seed);
        Self { sponge, offset: 0 }
    }
}

impl RngCore for TestDRNG {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        let end = self.offset + dst.len();
        dst.copy_from_slice(&self.sponge.squeeze(end)[self.offset..]);
        self.offset = end;
    }

    fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), Error> {
        unimplemented!()
    }
}
