use fastbuf::{ReadBuf, WriteBuf};
use nonmax::NonMaxI32;
use packetize::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(
    Default,
    Debug,
    derive_more::Display,
    derive_more::From,
    derive_more::Into,
    derive_more::Deref,
    derive_more::DerefMut,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
pub struct VarInt(i32);

#[derive(
    Default,
    Debug,
    derive_more::Display,
    derive_more::From,
    derive_more::Into,
    derive_more::Deref,
    derive_more::DerefMut,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
pub struct NonMaxVarInt(NonMaxI32);

impl NonMaxVarInt {
    pub fn new(value: i32) -> Self {
        Self(unsafe { NonMaxI32::new_unchecked(value) })
    }
}

impl Into<i32> for NonMaxVarInt {
    fn into(self) -> i32 {
        self.0.get()
    }
}

impl Encode for VarInt {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        <i32 as fastvarint::VarInt>::encode_var(&self, buf)
    }
}

impl Decode for VarInt {
    fn decode(buf: &mut impl ReadBuf) -> Result<Self, ()> {
        let (len, read_len) = <i32 as fastvarint::VarInt>::decode_var(buf)?;
        buf.advance(read_len);
        Ok(VarInt(len))
    }
}

impl Encode for NonMaxVarInt {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        VarInt(self.0.get()).encode(buf)
    }
}

impl Decode for NonMaxVarInt {
    fn decode(buf: &mut impl ReadBuf) -> Result<Self, ()> {
        VarInt::decode(buf).map(|v| NonMaxVarInt(unsafe { NonMaxI32::new_unchecked(v.0) }))
    }
}
