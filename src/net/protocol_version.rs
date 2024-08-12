use std::mem::{transmute, transmute_copy};

use fastbuf::{ReadBuf, WriteBuf};
use packetize::{Decode, Encode};

use crate::var_int::VarInt;

#[derive(Debug, Clone, Copy)]
pub enum ProtocolVersion {
    Mc1_21_1,
}

impl Encode for ProtocolVersion {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        VarInt::from(*self as i32).encode(buf)?;
        Ok(())
    }
}

impl Decode for ProtocolVersion {
    fn decode(buf: &mut impl ReadBuf) -> Result<Self, ()> {
        Ok(unsafe { transmute_copy(&VarInt::decode(buf)?) })
    }
}
