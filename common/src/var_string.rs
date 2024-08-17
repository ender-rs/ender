use std::str::FromStr;

use arrayvec::{ArrayString, CapacityError};
use fastbuf::{ReadBuf, WriteBuf};
use packetize::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::var_int::VarInt;

pub type VarString32767 = VarString<32767>;

#[derive(Debug, derive_more::DerefMut, derive_more::Deref, Serialize, Deserialize, Clone)]
pub struct VarString<const N: usize>(pub ArrayString<N>);

impl<const N: usize> VarString<N> {
    pub fn new() -> Self {
        Self(ArrayString::new())
    }

    pub fn from_str(s: &'static str) -> Result<Self, CapacityError> {
        Ok(Self(ArrayString::from_str(s)?))
    }
}

impl<const N: usize> Encode for VarString<N> {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        VarInt::from(self.len() as i32).encode(buf)?;
        buf.try_write(self.as_bytes())?;
        Ok(())
    }
}

impl<const N: usize> Decode for VarString<N> {
    fn decode(buf: &mut impl ReadBuf) -> Result<Self, ()> {
        let mut string = VarString(ArrayString::new());
        let len = *VarInt::decode(buf)? as usize;
        unsafe { string.set_len(len) };
        let src_slice = buf.read(len);
        if src_slice.len() != len {
            return Err(());
        }
        unsafe { string.as_bytes_mut().copy_from_slice(src_slice) };
        Ok(string)
    }
}
