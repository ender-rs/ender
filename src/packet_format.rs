use std::mem::transmute_copy;

use fastbuf::{Buf, Buffer, ReadBuf};
use packetize::{Decode, Encode, PacketStreamFormat};

use crate::{net::login_server::PACKET_BYTE_BUFFER_LENGTH, var_int::VarInt};

pub struct MinecraftPacketFormat;

impl PacketStreamFormat for MinecraftPacketFormat {
    fn read_packet_id<ID>(buf: &mut impl ReadBuf) -> Result<ID, ()>
    where
        ID: Default,
    {
        let packet_len = *VarInt::decode(buf)?;
        if buf.remaining() < packet_len as usize {
            Err(())?
        }
        let id = *VarInt::decode(buf)?;
        let backup_filled_len = buf.filled_pos();
        unsafe { buf.set_filled_pos(buf.pos() as usize + packet_len as usize) };
        let result = Ok(unsafe { transmute_copy(&id) });
        if result.is_err() {
            println!("packet id {id:#03x} not found");
        }
        unsafe { buf.set_filled_pos(backup_filled_len) };
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
        let mut buffer = Buffer::<PACKET_BYTE_BUFFER_LENGTH>::new();
        let id = P::id(state).ok_or(())?;
        VarInt::from(id as i32).encode(&mut buffer)?;
        packet.encode(&mut buffer)?;
        VarInt::from((buffer.filled_pos() - buffer.pos()) as i32).encode(buf)?;
        buf.try_write(buffer.read(buffer.remaining()))?;
        Ok(())
    }
}
