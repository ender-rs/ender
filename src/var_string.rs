use arrayvec::ArrayString;
use fastbuf::WriteBuf;
use packetize::Encode;

use crate::var_int::VarInt;

#[derive(derive_more::DerefMut, derive_more::Deref)]
pub struct VarString<const N: usize>(ArrayString<N>);

impl<const N: usize> Encode for VarString<N> {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        VarInt::from(self.len() as i32).encode(buf)?;
        Ok(())
    }
}
