use std::mem::MaybeUninit;

use cfb8::{Decryptor, Encryptor};
use derive_more::derive::{Deref, DerefMut};
use fastbuf::Buffer;
use nonmax::NonMaxUsize;

use crate::packet_format::MinecraftPacketFormat;

use super::{login_server::PACKET_BYTE_BUFFER_LENGTH, mc1_21_1::packets::Mc1_21_1ConnectionState};

#[derive(Deref, DerefMut)]
pub struct Connection<T> {
    #[deref]
    #[deref_mut]
    pub data: T,
    pub read_buf: Box<Buffer<PACKET_BYTE_BUFFER_LENGTH>>,
    pub write_buf: Box<Buffer<PACKET_BYTE_BUFFER_LENGTH>>,
    pub state: Mc1_21_1ConnectionState,
    pub stream_state: MinecraftPacketFormat,
    pub stream: mio::net::TcpStream,
    pub encrypt_key: Option<Vec<u8>>,
    pub e_cipher: Option<Encryptor<aes::Aes128>>,
    pub d_cipher: Option<Decryptor<aes::Aes128>>,
    pub verify_token: MaybeUninit<[u8; 4]>,
    pub related_http_client_id: Option<NonMaxUsize>,
}

impl<T: Default> Connection<T> {
    pub fn new(stream: mio::net::TcpStream) -> Self {
        Self {
            data: Default::default(),
            read_buf: Box::new(Buffer::new()),
            stream,
            state: Mc1_21_1ConnectionState::default(),
            write_buf: Box::new(Buffer::new()),
            e_cipher: None,
            d_cipher: None,
            encrypt_key: None,
            verify_token: MaybeUninit::uninit(),
            related_http_client_id: None,
            stream_state: MinecraftPacketFormat::new(),
        }
    }
}
