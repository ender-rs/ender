use packetize::{Decode, Encode};

use crate::{var_int::VarInt, var_string::VarString, varint_sized_array::VarIntSizedArray};

#[derive(Encode, Decode)]
pub struct EncryptionRequestS2c {
    pub server_id: VarString<20>,
    pub public_key_len: VarInt,
    pub public_key: VarIntSizedArray<u8, 293>,
    pub verity_token_len: VarInt,
    pub verify_token: VarIntSizedArray<u8, 4>,
    pub should_authenticate: bool,
}
