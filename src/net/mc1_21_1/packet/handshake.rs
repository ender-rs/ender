use std::mem::transmute_copy;

use arrayvec::ArrayString;
use fastbuf::{ReadBuf, WriteBuf};
use packetize::{Decode, Encode};

use crate::{net::protocol_version::ProtocolVersion, var_int::VarInt};

#[derive(Encode, Decode)]
pub struct HandShakeC2s {
    pub protocol_version: ProtocolVersion,
    pub server_address: ArrayString<1000>,
    pub server_port: u16,
    pub next_state: NextState,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum NextState {
    Status = 1,
    Login = 2,
    Transfer = 3,
}

impl Encode for NextState {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        VarInt::from(*self as i32).encode(buf)?;
        Ok(())
    }
}

impl Decode for NextState {
    fn decode(buf: &mut impl ReadBuf) -> Result<Self, ()> {
        Ok(unsafe { transmute_copy(&VarInt::decode(buf)?) })
    }
}
