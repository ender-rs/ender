use std::{io::Read, mem::MaybeUninit};

use cfb8::{Decryptor, Encryptor};
use common::{
    net::mc1_21_1::packets::{ClientBoundPacket, Mc1_21_1ConnectionState},
    packet_format::MinecraftPacketFormat,
};
use fastbuf::{Buf, Buffer, ReadBuf, ReadToBuf, WriteBuf};
use mio::Registry;
use packetize::ClientBoundPacketStream;

use super::{cryptic, login_server::PACKET_BYTE_BUFFER_LENGTH};

pub type ConnectionId = usize;

pub struct Connection {
    pub read_buf: Box<Buffer<PACKET_BYTE_BUFFER_LENGTH>>,
    pub write_buf: Box<Buffer<PACKET_BYTE_BUFFER_LENGTH>>,
    pub state: Mc1_21_1ConnectionState,
    pub stream_state: MinecraftPacketFormat,
    pub stream: mio::net::TcpStream,
    pub encrypt_key: Option<Vec<u8>>,
    pub e_cipher: Option<Encryptor<aes::Aes128>>,
    pub d_cipher: Option<Decryptor<aes::Aes128>>,
}

impl Connection {
    pub fn new(stream: mio::net::TcpStream) -> Self {
        Self {
            read_buf: Box::new(Buffer::new()),
            stream,
            state: Mc1_21_1ConnectionState::default(),
            write_buf: Box::new(Buffer::new()),
            e_cipher: None,
            d_cipher: None,
            encrypt_key: None,
            stream_state: MinecraftPacketFormat::new(),
        }
    }

    pub fn read_to_buf_from_stream(&mut self) -> Result<(), ()> {
        if let Some(ref mut cipher) = &mut self.d_cipher {
            #[allow(invalid_value)]
            let mut buf =
                unsafe { MaybeUninit::<[u8; PACKET_BYTE_BUFFER_LENGTH]>::uninit().assume_init() };
            let read_length = self.stream.read(&mut buf).map_err(|_| ())?;
            if read_length == 0 {
                return Err(());
            }

            let buf = &mut buf[..read_length];
            cryptic::decrypt(cipher, buf);
            self.read_buf.try_write(buf)?;
        } else {
            self.stream.read_to_buf(&mut self.read_buf)?;
        }
        Ok(())
    }

    pub fn send_packet(&mut self, packet: &ClientBoundPacket) -> Result<(), ()> {
        self.state.encode_client_bound_packet(
            packet,
            &mut *self.write_buf,
            &mut self.stream_state,
        )?;
        Ok(())
    }

    pub fn flush_write_buffer(&mut self) -> Result<(), ()> {
        let buf = &mut *self.write_buf;
        if let Some(ref mut cipher) = &mut self.e_cipher {
            let pos = buf.pos();
            let filled_pos = buf.filled_pos();
            let encrypted_buf = unsafe { buf.to_slice_mut().get_unchecked_mut(pos..filled_pos) };
            cryptic::encrypt(encrypted_buf, cipher);
        }

        std::io::Write::write_all(&mut self.stream, buf.read(buf.remaining())).map_err(|_| ())?;
        buf.clear();
        Ok(())
    }

    pub fn close(&mut self, registry: &Registry) {
        mio::Registry::deregister(&registry, &mut self.stream).unwrap();
    }
}
