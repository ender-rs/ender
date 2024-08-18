use std::io::Cursor;

use derive_more::derive::{Deref, DerefMut};
use fastbuf::{Buffer, ReadBuf, WriteBuf};
use packetize::{Decode, Encode};

use crate::identifier::Identifier;

#[derive(Debug, Encode, Decode)]
pub struct RegistryDataS2c {
    id: Identifier,
    entries: Vec<(Identifier, Option<Nbt>)>,
}

#[derive(Debug, Deref, DerefMut)]
pub struct Nbt(simdnbt::owned::NbtCompound);

impl Encode for Nbt {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        let mut vec = Vec::new();
        self.write(&mut vec);
        buf.try_write(&[0x0a])?;
        buf.try_write(vec.as_slice())?;
        Ok(())
    }
}

impl Decode for Nbt {
    fn decode(buf: &mut impl ReadBuf) -> Result<Self, ()> {
        let type_id = buf.read(1);
        if type_id.is_empty() {
            Err(())?
        }
        let type_id = type_id[0];
        if type_id != 0x0a {
            Err(())?
        }
        let mut cur = Cursor::new(buf.get_continuous(buf.remaining()));
        let nbt = simdnbt::owned::read_compound(&mut cur).map_err(|_| ())?;
        buf.advance(cur.position() as usize);
        Ok(Nbt(nbt))
    }
}
