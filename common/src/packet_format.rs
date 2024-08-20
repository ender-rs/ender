use std::mem::{transmute_copy, MaybeUninit};

use fastbuf::{Buf, Buffer, ReadBuf, WriteBuf};
use nonmax::{NonMaxI32, NonMaxU32};
use packetize::{Decode, Encode, Packet, PacketStreamFormat};

use crate::var_int::VarInt;

pub const PACKET_BYTE_BUFFER_LENGTH: usize = 500_000; //2097152;

pub struct MinecraftPacketFormat {
    pub compression_threshold: Option<NonMaxI32>,
    pub last_filled_pos_of_buffer_backup: Option<NonMaxU32>,
    pub pos_of_buffer_backup_for_error: Option<NonMaxU32>,
    pub temp_buf: Box<Buffer<PACKET_BYTE_BUFFER_LENGTH>>,
}

impl MinecraftPacketFormat {
    pub fn new() -> Self {
        Self {
            compression_threshold: None,
            last_filled_pos_of_buffer_backup: None,
            pos_of_buffer_backup_for_error: None,
            #[allow(invalid_value)]
            temp_buf: Box::new(unsafe { MaybeUninit::uninit().assume_init() }),
        }
    }
}

impl PacketStreamFormat for MinecraftPacketFormat {
    fn read_packet_id<ID>(&mut self, buf: &mut impl Buf) -> Result<ID, ()>
    where
        ID: Default,
    {
        self.pos_of_buffer_backup_for_error =
            Some(unsafe { NonMaxU32::new_unchecked(buf.pos() as u32) });
        let mut f = || -> Result<(), ()> {
            if let Some(compression_threshold) = self.compression_threshold {
                let packet_len = *VarInt::decode(buf)?;
                let backup_pos = buf.pos();
                let uncompressed_len = *VarInt::decode(buf)?;
                let uncompressed_len_read_len = buf.pos() - backup_pos;
                if uncompressed_len == 0 || uncompressed_len < compression_threshold.get() {
                    if packet_len == 0 {
                        Err(())?
                    }
                    let payload_len = packet_len as usize - 1;
                    if buf.remaining() < payload_len {
                        return Err(());
                    }
                    self.last_filled_pos_of_buffer_backup =
                        Some(unsafe { NonMaxU32::new_unchecked(buf.filled_pos() as u32) });
                    unsafe { buf.set_filled_pos(buf.pos() + payload_len) };
                } else {
                    let compresed_len = packet_len as usize - uncompressed_len_read_len;
                    if buf.remaining() < compresed_len {
                        #[cfg(debug_assertions)]
                        println!(
                            "len of bytes({}) is bigger than remaining({}) of buffer",
                            compresed_len,
                            buf.remaining()
                        );
                        Err(())?
                    }
                    let compressed_payload = buf.read(compresed_len);
                    let temp_buf = &mut *self.temp_buf;
                    temp_buf.clear();
                    let mut decoder = flate2::write::ZlibDecoder::new(temp_buf);
                    std::io::Write::write_all(&mut decoder, compressed_payload).map_err(|_| ())?;
                    let temp_buf = decoder.finish().map_err(|_| ())?;
                    temp_buf.try_write(buf.read(buf.remaining()))?;
                    buf.clear();
                    buf.try_write(temp_buf.read(temp_buf.remaining()))?;
                }
            } else {
                let packet_len = *VarInt::decode(buf)?;
                if buf.remaining() < packet_len as usize {
                    Err(())?
                }
            }
            Ok(())
        };
        match f() {
            Ok(()) => {}
            Err(()) => {
                unsafe {
                    buf.set_pos(
                        self.pos_of_buffer_backup_for_error.unwrap_unchecked().get() as usize
                    )
                };
                Err(())?
            }
        };
        let id = *VarInt::decode(buf).inspect_err(|()| {
            #[cfg(debug_assertions)]
            println!("There is no packet id for current state");
        })?;
        let result: ID = unsafe { transmute_copy(&id) };
        Ok(result)
    }

    fn write_packet_with_id<T, P>(
        &mut self,
        state: &mut T,
        packet: &P,
        buf: &mut impl Buf,
    ) -> Result<(), ()>
    where
        P: Packet<T> + Encode,
    {
        let ref mut buffer = Box::new(Buffer::<PACKET_BYTE_BUFFER_LENGTH>::new());
        buffer.write(&[0]);
        let id = P::id(state).ok_or(())?;
        if let Some(s) = P::is_changing_state() {
            *state = s;
        }
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

    fn read_packet<T, P>(&mut self, state: &mut T, buf: &mut impl Buf) -> Result<P, ()>
    where
        P: Decode + Packet<T>,
    {
        if let Some(s) = P::is_changing_state() {
            *state = s;
        }
        let result = match P::decode(buf) {
            Ok(result) => Ok(result),
            Err(()) => {
                unsafe {
                    buf.set_pos(
                        self.pos_of_buffer_backup_for_error.unwrap_unchecked().get() as usize
                    )
                };
                Err(())?
            }
        };
        if let Some(last_filled_pos_of_buffer_backup) = self.last_filled_pos_of_buffer_backup {
            unsafe { buf.set_filled_pos(last_filled_pos_of_buffer_backup.get() as usize) };
            self.last_filled_pos_of_buffer_backup = None;
        };
        result
    }
}
