use arrayvec::ArrayVec;
use fastbuf::WriteBuf;
use packetize::{Decode, Encode};

use crate::var_int::VarInt;

#[derive(derive_more::Deref, derive_more::DerefMut)]
pub struct VarIntSizedArray<T, const N: usize>(ArrayVec<T, N>);

impl<T, const N: usize> VarIntSizedArray<T, N> {
    pub fn new() -> Self {
        Self(ArrayVec::new())
    }
}

impl<T: Encode, const N: usize> Encode for VarIntSizedArray<T, N> {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        VarInt::from(self.len() as i32).encode(buf)?;
        for ele in self.iter() {
            ele.encode(buf)?;
        }
        Ok(())
    }
}

impl<T: Decode, const N: usize> Decode for VarIntSizedArray<T, N> {
    fn decode(buf: &mut impl fastbuf::ReadBuf) -> Result<Self, ()> {
        let mut arrayvec = VarIntSizedArray::new();
        unsafe { arrayvec.set_len(*VarInt::decode(buf)? as usize) };
        for _i in 0..arrayvec.len() {
            arrayvec.push(T::decode(buf)?);
        }
        Ok(arrayvec)
    }
}

