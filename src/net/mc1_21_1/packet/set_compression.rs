use packetize::{Decode, Encode};

use crate::var_int::VarInt;

#[derive(Debug, Encode, Decode)]
pub struct SetCompressionS2c {
    pub threshold: VarInt,
}
