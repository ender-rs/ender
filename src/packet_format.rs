use std::{mem::transmute_copy, ops::Deref};

use fastbuf::ReadBuf;
use packetize::{Decode, Encode, PacketStreamFormat};

use crate::var_int::VarInt;

pub struct MinecraftPacketFormat;

impl PacketStreamFormat for MinecraftPacketFormat {
    fn read_packet_id<ID>(buf: &mut impl ReadBuf) -> Result<ID, ()>
    where
        ID: Default,
    {
        let packet_len = *VarInt::decode(buf)?;
        dbg!(packet_len);
        dbg!(buf.remaining());
        if buf.remaining() < packet_len as usize {
            Err(())?
        }
        let id = *VarInt::decode(buf)?;
        let backup_filled_len = buf.filled_len();
        unsafe { buf.set_filled_len(buf.pos() as usize + packet_len as usize) };
        let result = Ok(unsafe { transmute_copy(&id) });
        if result.is_err() {
            println!("packet id {id:#03x} not found");
        }
        unsafe { buf.set_filled_len(backup_filled_len) };
        result
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
