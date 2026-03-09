use rand_core::{Error, RngCore, SeedableRng};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

pub struct Shake128PRNG(<Shake128 as ExtendableOutput>::Reader);

impl SeedableRng for Shake128PRNG {
    type Seed = [u8; 32];

    fn from_seed(seed: Self::Seed) -> Self {
        let mut shake = Shake128::default();
        shake.update(&seed);
        Self(shake.finalize_xof())
    }
}

impl RngCore for Shake128PRNG {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.read(dst)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}
