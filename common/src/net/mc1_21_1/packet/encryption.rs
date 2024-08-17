use arrayvec::ArrayVec;
use packetize::{Decode, Encode};

use crate::array_capacitor::VarStringCap;

#[derive(Debug, Encode, Decode)]
pub struct EncryptionRequestS2c {
    pub server_id: VarStringCap<20>,
    pub public_key: ArrayVec<u8, 162>,
    pub verify_token: ArrayVec<u8, 4>,
    pub should_authenticate: bool,
}

#[derive(Debug, Encode, Decode)]
pub struct EncryptionResponseC2s {
    pub shared_secret: ArrayVec<u8, 128>,
    pub verify_token: ArrayVec<u8, 128>,
}
