use arrayvec::ArrayVec;
use packetize::{Decode, Encode};

use crate::{var_int::VarInt, var_string::VarString};

#[derive(Debug, Encode, Decode)]
pub struct EncryptionRequestS2c {
    pub server_id: VarString<20>,
    pub public_key_len: VarInt,
    pub public_key: ArrayVec<u8, 327>,
    pub verity_token_len: VarInt,
    pub verify_token: ArrayVec<u8, 4>,
}
