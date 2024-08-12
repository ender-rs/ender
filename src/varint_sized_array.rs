use arrayvec::ArrayVec;
use fastbuf::WriteBuf;
use packetize::{Decode, Encode};

use crate::var_int::VarInt;

#[derive(Debug, derive_more::Deref, derive_more::DerefMut)]
pub struct VarIntSizedArray<T, const N: usize>(ArrayVec<T, N>);

impl<T, const N: usize> VarIntSizedArray<T, N> {
    pub fn new() -> Self {
        Self(ArrayVec::new())
    }
}

impl<T: Encode, const CAP: usize> Encode for VarIntSizedArray<T, CAP> {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        VarInt::from(self.len() as i32).encode(buf)?;
        for ele in self.iter() {
            ele.encode(buf)?;
        }
        Ok(())
    }
}

impl<T: Decode, const CAP: usize> Decode for VarIntSizedArray<T, CAP> {
    fn decode(buf: &mut impl fastbuf::ReadBuf) -> Result<Self, ()> {
        let mut arrayvec = VarIntSizedArray::new();
        let len = *VarInt::decode(buf)? as usize;
        if CAP < len {
            #[cfg(debug_assertions)]
            dbg!(CAP < len, CAP, len);
            Err(())?
        }
        unsafe { arrayvec.set_len(len) };
        for i in 0..arrayvec.len() {
            *unsafe { arrayvec.get_unchecked_mut(i) } = T::decode(buf)?;
        }
        Ok(arrayvec)
    }
}
