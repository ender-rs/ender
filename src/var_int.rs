use fastbuf::{ReadBuf, WriteBuf};
use nonmax::NonMaxI32;
use packetize::{Decode, Encode};

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
        let x = self.0 as u64;
        let stage1 = (x & 0x000000000000007f)
            | ((x & 0x0000000000003f80) << 1)
            | ((x & 0x00000000001fc000) << 2)
            | ((x & 0x000000000fe00000) << 3)
            | ((x & 0x00000000f0000000) << 4);

        let leading = stage1.leading_zeros();

        let unused_bytes = (leading - 1) >> 3;
        let bytes_needed = 8 - unused_bytes;

        // set all but the last MSBs
        let msbs = 0x8080808080808080;
        let msbmask = 0xffffffffffffffff >> (((8 - bytes_needed + 1) << 3) - 1);

        let merged = stage1 | (msbs & msbmask);
        let bytes = merged.to_le_bytes();

        buf.try_write(unsafe { bytes.get_unchecked(..bytes_needed as usize) })?;
        Ok(())
    }
}

impl Decode for VarInt {
    fn decode(buf: &mut impl ReadBuf) -> Result<Self, ()> {
        let bytes = buf.get_continuous(u32::BITS as usize / 8 + 1);
        let remaining = buf.remaining();
        let mut val = 0;
        for i in 0..5 {
            if remaining < i + 1 {
                Err(())?
            }
            let byte = *unsafe { bytes.get_unchecked(i) };
            val |= (byte as i32 & 0b01111111) << (i * 7);
            if byte & 0b10000000 == 0 {
                buf.advance(i + 1);
                return Ok(val.into());
            }
        }
        Err(())
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
