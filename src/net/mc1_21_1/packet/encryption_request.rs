use arrayvec::ArrayVec;
use packetize::{Decode, Encode};

use crate::var_string::VarString;

#[derive(Debug, Encode, Decode)]
pub struct EncryptionRequestS2c {
    pub server_id: VarString<20>,
    pub public_key: ArrayVec<u8, 161>,
    pub verify_token: ArrayVec<u8, 4>,
    pub should_authenticate: bool,
}
