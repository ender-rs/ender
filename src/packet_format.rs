use std::mem::transmute_copy;

use fastbuf::{Buf, Buffer, ReadBuf, WriteBuf};
use nonmax::NonMaxI32;
use packetize::{Decode, Encode, PacketStreamFormat};

use crate::{net::login_server::PACKET_BYTE_BUFFER_LENGTH, var_int::VarInt};

pub struct MinecraftPacketFormat {
    pub compression_threshold: Option<NonMaxI32>,
    last_filled_pos_of_buffer_backup: Option<NonMaxI32>,
}

impl MinecraftPacketFormat {
    pub fn new() -> Self {
        Self {
            compression_threshold: None,
            last_filled_pos_of_buffer_backup: None,
        }
    }
}

impl PacketStreamFormat for MinecraftPacketFormat {
    fn read_packet_id<ID>(&mut self, buf: &mut impl ReadBuf) -> Result<ID, ()>
    where
        ID: Default,
    {
        if let Some(compression_threshold) = self.compression_threshold {
            let packet_len = *VarInt::decode(buf)?;
            let pos_backup = buf.pos();
            let uncompressed_len = *VarInt::decode(buf)?;
            if uncompressed_len == 0 {
                let payload_len = packet_len as usize - 1;
                if buf.remaining() < payload_len {
                    return Err(());
                }
                self.last_filled_pos_of_buffer_backup =
                    Some(unsafe { NonMaxI32::new_unchecked(buf.filled_pos() as i32) });
                unsafe { buf.set_filled_pos(buf.pos() + payload_len) };
                assert_eq!(buf.remaining(), payload_len);
            } else {
                println!("actual compressoin over the threshold is not implemented yet");
                return Err(());
            }
        } else {
            let packet_len = *VarInt::decode(buf)?;
            if buf.remaining() < packet_len as usize {
                Err(())?
            }
        }
        let id = *VarInt::decode(buf)?;
        let result: ID = unsafe { transmute_copy(&id) };
        Ok(result)
    }

    fn write_packet_with_id<T, P>(
        &mut self,
        state: &mut T,
        packet: &P,
        buf: &mut impl fastbuf::WriteBuf,
    ) -> Result<(), ()>
    where
        P: packetize::Packet<T> + Encode,
    {
        let ref mut buffer = Buffer::<PACKET_BYTE_BUFFER_LENGTH>::new();
        buffer.write(&[0]);
        let id = P::id(state).ok_or(())?;
        VarInt::from(id as i32).encode(buffer)?;
        packet.encode(buffer)?;
        if let Some(compression_threshold) = self.compression_threshold {
            if (buffer.remaining() as i32) < compression_threshold.get() {
                VarInt::from(buffer.remaining() as i32).encode(buf)?;
                buf.try_write(buffer.read(buffer.remaining()))?;
            } else {
                println!("actual decompression over the threshold is not implemented yet");
                return Err(());
            }
        } else {
            unsafe { buffer.set_pos(1) };
            VarInt::from(buffer.remaining() as i32).encode(buf)?;
            buf.try_write(buffer.read(buffer.remaining()))?;
        }
        Ok(())
    }

    fn read_packet<T, P>(&mut self, state: &mut T, buf: &mut impl ReadBuf) -> Result<P, ()>
    where
        P: Decode + packetize::Packet<T>,
    {
        if let Some(s) = P::is_changing_state() {
            *state = s;
        }
        let result = P::decode(buf);
        if let Some(last_filled_pos_of_buffer_backup) = self.last_filled_pos_of_buffer_backup {
            unsafe { buf.set_filled_pos(last_filled_pos_of_buffer_backup.get() as usize) };
            self.last_filled_pos_of_buffer_backup = None;
        };
        result
    }
}
