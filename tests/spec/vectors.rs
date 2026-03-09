use serde::{Deserialize, Serialize};
use serde_with::{hex, serde_as};

#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hex(#[serde_as(as = "hex::Hex")] pub Vec<u8>);

#[allow(non_snake_case)]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TestVector {
    pub Protocol: String,
    pub Ciphersuite: String,
    pub SessionId: Hex,
    pub Statement: Hex,
    pub Witness: Hex,
    pub Proof: Hex,
    #[serde(rename = "Batchable Proof")]
    pub BatchableProof: Hex,
}
