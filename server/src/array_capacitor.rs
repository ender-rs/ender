use derive_more::derive::{Deref, DerefMut, From, Into};
use fastbuf::{ReadBuf, WriteBuf};
use fastvarint::VarInt;
use packetize::{Decode, Encode};

#[derive(Deref, DerefMut, Debug, Into, From)]
pub struct VarStringCap<const CAP: usize>(String);

#[derive(Deref, DerefMut, Debug, Into, From)]
pub struct VecCap<T, const CAP: usize>(Vec<T>);

default impl<T: Encode, const CAP: usize> Encode for VecCap<T, CAP> {
    default fn encode(&self, buf: &mut impl fastbuf::WriteBuf) -> Result<(), ()> {
        let len = self.len() as u32;
        let len = len;
        len.encode_var(buf)?;
        for ele in self.iter() {
            ele.encode(buf)?;
        }
        Ok(())
    }
}

impl<const CAP: usize> Decode for VecCap<u8, CAP> {
    default fn decode(buf: &mut impl ReadBuf) -> Result<Self, ()> {
        let mut vec = Vec::new();
        let (vec_len, read_len) = u32::decode_var_from_buf(buf)?;
        buf.advance(read_len);
        let vec_len = vec_len as usize;
        if buf.remaining() < vec_len {
            Err(())?
        }
        if CAP < vec_len {
            #[cfg(debug_assertions)]
            dbg!(CAP < vec_len, CAP, vec_len);
            Err(())?
        }
        unsafe { vec.set_len(vec_len) };
        vec.as_mut_slice().copy_from_slice(buf.read(vec_len));
        Ok(VecCap(vec))
    }
}

default impl<T: Encode, const CAP: usize> Encode for VecCap<T, CAP> {
    default fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        let vec_len = self.len();
        (vec_len as u32).encode_var(buf)?;
        if CAP < vec_len {
            #[cfg(debug_assertions)]
            dbg!(CAP < vec_len, CAP, vec_len);
            Err(())?
        }
        for ele in self.iter() {
            ele.encode(buf)?;
        }
        Ok(())
    }
}

impl<T: Decode, const CAP: usize> Decode for VecCap<T, CAP> {
    default fn decode(buf: &mut impl ReadBuf) -> Result<Self, ()> {
        let mut vec = Vec::new();
        let (vec_len, read_len) = u32::decode_var_from_buf(buf)?;
        buf.advance(read_len);
        let vec_len = vec_len as usize;
        if CAP < vec_len {
            #[cfg(debug_assertions)]
            dbg!(CAP < vec_len, CAP, vec_len);
            Err(())?
        }
        unsafe { vec.set_len(vec_len) };
        for i in 0..vec_len {
            *unsafe { vec.get_unchecked_mut(i) } = T::decode(buf)?;
        }
        Ok(VecCap(vec))
    }
}

impl<const CAP: usize> Decode for VarStringCap<CAP> {
    fn decode(buf: &mut impl ReadBuf) -> Result<Self, ()> {
        let mut vec = Vec::new();
        let (string_len, read_len) = u32::decode_var_from_buf(buf)?;
        buf.advance(read_len);
        let string_len = string_len as usize;
        if buf.remaining() < string_len {
            Err(())?
        }
        if CAP < string_len {
            #[cfg(debug_assertions)]
            dbg!(CAP < string_len, CAP, string_len);
            Err(())?
        }
        unsafe { vec.set_len(string_len) };
        vec.as_mut_slice().copy_from_slice(buf.read(string_len));
        Ok(unsafe { VarStringCap(String::from_utf8_unchecked(vec)) })
    }
}

impl<const CAP: usize> Encode for VarStringCap<CAP> {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        (self.len() as u32).encode_var(buf)?;
        buf.write(self.as_bytes());
        Ok(())
    }
}

impl<const CAP: usize> From<&[u8]> for VecCap<u8, CAP> {
    fn from(value: &[u8]) -> Self {
        VecCap(Vec::from(value))
    }
}
