use std::io::Read;

use crate::{
    net::mc1_21_1::packets::{ClientBoundPacket, Mc1_21_1ConnectionState},
    packet_format::{MinecraftPacketFormat, PACKET_BYTE_BUFFER_LENGTH},
};
use aes::cipher::KeyIvInit;
use cfb8::{Decryptor, Encryptor};
use fastbuf::{Buf, Buffer, ReadBuf, ReadToBuf, WriteBuf};
use nonmax::NonMaxI32;
use packetize::{ClientBoundPacketStream, ServerBoundPacketStream};

use super::{
    cryptic,
    mc1_21_1::{packet::login::SetCompressionS2c, packets::ServerBoundPacket},
};

pub type ConnectionId = usize;

pub struct Connection {
    pub read_buf: Box<Buffer<PACKET_BYTE_BUFFER_LENGTH>>,
    pub write_buf: Box<Buffer<PACKET_BYTE_BUFFER_LENGTH>>,
    pub state: Mc1_21_1ConnectionState,
    pub stream_state: MinecraftPacketFormat,
    pub stream: mio::net::TcpStream,
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
            stream_state: MinecraftPacketFormat::new(),
        }
    }

    pub fn read_to_buf_from_stream(
        &mut self,
        temp_buf: &mut [u8; PACKET_BYTE_BUFFER_LENGTH],
    ) -> Result<(), ()> {
        if let Some(ref mut cipher) = &mut self.d_cipher {
            #[allow(invalid_value)]
            let read_length = self.stream.read(temp_buf).map_err(|_| ())?;
            if read_length == 0 {
                return Err(());
            }

            let buf = &mut temp_buf[..read_length];
            cryptic::decrypt(cipher, buf);
            self.read_buf.try_write(buf)?;
        } else {
            self.stream.read_to_buf(&mut self.read_buf)?;
        }
        Ok(())
    }

    pub fn send_packet_to_client(&mut self, packet: &ClientBoundPacket) -> Result<(), ()> {
        self.state.encode_client_bound_packet(
            packet,
            &mut *self.write_buf,
            &mut self.stream_state,
        )?;
        Ok(())
    }

    pub fn send_packet_to_server(&mut self, packet: &ServerBoundPacket) -> Result<(), ()> {
        self.state.encode_server_bound_packet(
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

    pub fn send_set_compression_packet(&mut self) -> Result<(), ()> {
        const DEFAULT_COMPRESSION_THRESHOLD: i32 = 25600;
        self.send_packet_to_client(
            &SetCompressionS2c {
                threshold: DEFAULT_COMPRESSION_THRESHOLD.into(),
            }
            .into(),
        )?;
        self.flush_write_buffer()?;
        self.enable_compression(DEFAULT_COMPRESSION_THRESHOLD)?;
        Ok(())
    }

    pub fn enable_compression(&mut self, threshold: i32) -> Result<(), ()> {
        if threshold == -1 {
            self.stream_state.compression_threshold = None;
        } else {
            self.stream_state.compression_threshold =
                Some(unsafe { NonMaxI32::new_unchecked(threshold) });
        }
        Ok(())
    }

    pub fn enable_encryption(&mut self, shared_secret: &[u8]) -> Result<(), ()> {
        let crypt_key: [u8; 16] = shared_secret.try_into().unwrap();
        self.e_cipher =
            Some(Encryptor::<aes::Aes128>::new_from_slices(&crypt_key, &crypt_key).unwrap());
        self.d_cipher =
            Some(Decryptor::<aes::Aes128>::new_from_slices(&crypt_key, &crypt_key).unwrap());
        Ok(())
    }
}
