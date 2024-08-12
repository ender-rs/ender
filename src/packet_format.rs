use std::mem::transmute_copy;

use fastbuf::ReadBuf;
use packetize::{Decode, Encode, PacketStreamFormat};

use crate::var_int::VarInt;

pub struct MinecraftPacketFormat;

impl PacketStreamFormat for MinecraftPacketFormat {
    fn read_packet_id<ID>(buf: &mut impl ReadBuf) -> Result<ID, ()>
    where
        ID: Default,
    {
        let varint = VarInt::decode(buf)?;
        Ok(unsafe { transmute_copy(&varint) })
    }

    fn write_packet_with_id<T, P>(
        state: &mut T,
        packet: &P,
        buf: &mut impl fastbuf::WriteBuf,
    ) -> Result<(), ()>
    where
        P: packetize::Packet<T> + Encode,
    {
        let id = P::id(state).ok_or(())?;
        VarInt::from(id as i32).encode(buf)?;
        packet.encode(buf)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use fastbuf::{Buffer, WriteBuf};
    use packetize::Decode;

    use crate::var_int::VarInt;

    // [16, 0, 255, 5, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116, 99, 181, 1]
    #[test]
    fn test() {
        let mut buf = Buffer::<1000>::new();
        buf.write(&[16, 0, 255, 5, 9, 108]);
        let varint = VarInt::decode(&mut buf);
        println!("{:?}", varint.unwrap());
    }
}
