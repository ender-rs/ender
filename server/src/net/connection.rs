use cfb8::{Decryptor, Encryptor};
use fastbuf::Buffer;

use crate::packet_format::MinecraftPacketFormat;

use super::{login_server::PACKET_BYTE_BUFFER_LENGTH, mc1_21_1::packets::Mc1_21_1ConnectionState};

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
}
