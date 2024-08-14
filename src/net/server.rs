use std::{
    io::{Read, Write},
    mem::MaybeUninit,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use aes::cipher::{generic_array, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit};
use bytes::BytesMut;
use cfb8::{Decryptor, Encryptor};
use fastbuf::{Buf, Buffer, ReadBuf, ReadToBuf, WriteBuf};
use flate2::{bufread::ZlibEncoder, write::ZlibDecoder, Compression};
use mio::{event::Event, net::TcpStream, Interest};
use nonmax::NonMaxUsize;
use packetize::{ClientBoundPacketStream, ServerBoundPacketStream};
use rand::thread_rng;
use rsa::{
    signature::digest::generic_array::GenericArray, traits::PublicKeyParts, RsaPrivateKey,
    RsaPublicKey,
};
use slab::Slab;
use tick_machine::{Tick, TickState};
use uuid::Uuid;

use crate::{
    http_request::{make_tls_config, HttpRequestEvent},
    net::mc1_21_1::packet::{
        handshake::handle_handshake, login_start::handle_login_start, status::handle_status_request,
    },
    player_name::PlayerName,
    var_string::VarString,
};

use super::mc1_21_1::{
    packet::{
        encryption_response::handle_encryption_response, login_ack::handle_login_ack,
        ping::handle_ping_request,
    },
    packets::{ClientBoundPacket, Mc1_21_1ConnectionState, ServerBoundPacket},
};

//TODO rename to LoginServer
pub struct Server {
    pub poll: mio::Poll,
    listener: mio::net::TcpListener,
    tick_state: TickState,
    pub connections: Slab<Connection>,
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
    pub public_key_der: Box<[u8]>,
    pub http_clients: Slab<HttpClient>,
    pub tls_config: Arc<rustls::ClientConfig>,
}

pub struct HttpClient {
    pub event: HttpRequestEvent,
    pub stream: TcpStream,
    pub connection_id: ConnectionId,
    pub tls: rustls::ClientConnection,
}

pub const PACKET_BYTE_BUFFER_LENGTH: usize = 4096;
pub const MAX_PACKET_SIZE: i32 = 2097152;

pub struct Connection {
    pub uuid: Uuid,
    pub player_name: PlayerName,
    pub read_buf: Box<Buffer<PACKET_BYTE_BUFFER_LENGTH>>,
    pub write_buf: Box<Buffer<PACKET_BYTE_BUFFER_LENGTH>>,
    pub state: Mc1_21_1ConnectionState,
    pub stream: mio::net::TcpStream,
    pub encrypt_key: Option<Vec<u8>>,
    pub e_cipher: Option<Encryptor<aes::Aes128>>,
    pub d_cipher: Option<Decryptor<aes::Aes128>>,
    pub compression_threshold: Option<i32>,
    pub compression_level: Option<u32>,
    pub verify_token: MaybeUninit<[u8; 4]>,
    pub related_http_client_id: Option<NonMaxUsize>,
}

impl Connection {
    pub fn new(stream: mio::net::TcpStream) -> Self {
        Self {
            read_buf: Box::new(Buffer::new()),
            stream,
            state: Mc1_21_1ConnectionState::default(),
            write_buf: Box::new(Buffer::new()),
            uuid: Uuid::nil(),
            player_name: VarString::from_str("Unknown Player").unwrap().into(),
            e_cipher: None,
            d_cipher: None,
            encrypt_key: None,
            compression_threshold: None,
            compression_level: None,
            verify_token: MaybeUninit::uninit(),
            related_http_client_id: None,
        }
    }
}

pub type ConnectionId = usize;

impl Server {
    const LISTENER_KEY: usize = usize::MAX;
    const CONNECTIONS_CAPACITY: usize = 1000;
    const HTTP_REQUESTS_CAPACITY: usize = 30;
    pub const HTTP_CLIENT_ID_OFFSET: usize = Self::CONNECTIONS_CAPACITY;
    const TICK: Duration = Duration::from_millis(50);

    pub fn new() -> Self {
        let tls_config = make_tls_config();
        let (public_key, private_key) = Self::generate_key_fair();

        dbg!("keys generated");

        let public_key_der = rsa_der::public_key_to_der(
            &private_key.n().to_bytes_be(),
            &private_key.e().to_bytes_be(),
        )
        .into_boxed_slice();

        let poll = mio::Poll::new().unwrap();
        const PORT: u16 = 25525;
        let addr = format!("[::]:{PORT}").parse().unwrap();
        let mut listener = mio::net::TcpListener::bind(addr).unwrap();
        let registry = poll.registry();
        mio::event::Source::register(
            &mut listener,
            registry,
            mio::Token(Self::LISTENER_KEY),
            Interest::READABLE,
        )
        .unwrap();

        let addr = SocketAddr::new(
            get_if_addrs::get_if_addrs().unwrap().first().unwrap().ip(),
            PORT,
        );
        Self {
            poll,
            tick_state: TickState::new(Self::TICK),
            listener,
            connections: Slab::with_capacity(Self::CONNECTIONS_CAPACITY),
            public_key,
            private_key,
            public_key_der,
            http_clients: Slab::with_capacity(Self::HTTP_REQUESTS_CAPACITY),
            tls_config,
        }
    }

    pub fn enable_encryption(
        &mut self,
        shared_secret: &[u8],
        connection_id: ConnectionId,
    ) -> Result<(), ()> {
        let crypt_key: [u8; 16] = shared_secret.try_into().unwrap();
        let connection = self.get_connection_mut(connection_id);

        connection.e_cipher =
            Some(Encryptor::<aes::Aes128>::new_from_slices(&crypt_key, &crypt_key).unwrap());
        connection.d_cipher =
            Some(Decryptor::<aes::Aes128>::new_from_slices(&crypt_key, &crypt_key).unwrap());

        connection.encrypt_key = Some(crypt_key.to_vec());

        Ok(())
    }

    pub fn enable_compression(
        &mut self,
        connection_id: ConnectionId,
        threshold: i32,
        level: u32,
    ) -> Result<(), ()> {
        let connection = self.get_connection_mut(connection_id);

        connection.compression_level = Some(level);
        connection.compression_threshold = Some(threshold);

        Ok(())
    }

    pub fn get_connection_mut(&mut self, connection_id: ConnectionId) -> &mut Connection {
        // SAFETY: connection id must valid
        unsafe { self.connections.get_unchecked_mut(connection_id as usize) }
    }

    pub unsafe fn try_get_connection(
        &mut self,
        connection_id: ConnectionId,
    ) -> Option<&mut Connection> {
        self.connections.get_mut(connection_id as usize)
    }

    pub fn start_loop(&mut self) -> ! {
        let mut events = mio::Events::with_capacity(Self::CONNECTIONS_CAPACITY);
        loop {
            self.try_tick();
            self.poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
            for event in events.iter() {
                self.on_event(event);
            }
        }
    }

    fn on_event(&mut self, selection_event: &Event) {
        let selection_key = selection_event.token().0;
        if selection_key == Self::LISTENER_KEY {
            let (stream, _addr) = self.listener.accept().unwrap();
            if self.connections.len() >= Self::CONNECTIONS_CAPACITY {
                #[cfg(debug_assertions)]
                println!("cannot accept TCP stream due to max connection capacity reached");
                return;
            }
            let key = self.connections.insert(Connection::new(stream));
            let connection = unsafe { self.connections.get_unchecked_mut(key) };
            mio::Registry::register(
                &self.poll.registry(),
                &mut connection.stream,
                mio::Token(key),
                Interest::READABLE,
            )
            .unwrap();
        } else if selection_key < Self::CONNECTIONS_CAPACITY {
            if !self.connections.contains(selection_key) {
                return;
            }
            match self.on_connection_read(selection_key) {
                Ok(()) => {}
                Err(()) => self.close_connection(selection_key as ConnectionId),
            }
        } else {
            let client_id = selection_key - Self::HTTP_CLIENT_ID_OFFSET;
            if !self.http_clients.contains(client_id) {
                return;
            }
            match self.on_http_client_event(client_id, &selection_event) {
                Ok(_) => {}
                Err(_) => {
                    let client = self.close_http_client(client_id);
                    self.close_connection(client.connection_id);
                }
            }
        }
    }

    fn on_connection_read(&mut self, connection_id: ConnectionId) -> Result<(), ()> {
        let connection = unsafe { self.connections.get_unchecked_mut(connection_id) };
        connection.stream.read_to_buf(&mut connection.read_buf)?;
        self.on_read_packet(connection_id as ConnectionId)?;
        Ok(())
    }

    fn on_read_packet(&mut self, connection_id: ConnectionId) -> Result<(), ()> {
        while self.get_connection_mut(connection_id).read_buf.remaining() != 0 {
            let connection = unsafe { self.connections.get_unchecked_mut(connection_id as usize) };
            let buf = &mut *connection.read_buf;

            if let Some(cipher) = &mut connection.d_cipher {
                let mut decrypted_buf = bytes::BytesMut::from(buf.read(buf.remaining()));
                Server::decrypt_bytes(cipher, &mut decrypted_buf);
                buf.try_write(&decrypted_buf)?;
            }

            if let (Some(threshold), Some(_)) = (
                connection.compression_threshold,
                connection.compression_level,
            ) {
                let mut decompressed_buf = Vec::new();
                let data_length = buf.remaining();
                if data_length > 0 {
                    let compressed_data = buf.read(data_length as usize);
                    let mut decoder = flate2::read::ZlibDecoder::new(&compressed_data[..]);
                    decoder.read_to_end(&mut decompressed_buf);
                    buf.clear();
                    buf.write(&decompressed_buf);
                }
            }

            match connection.state.decode_server_bound_packet(buf)? {
                ServerBoundPacket::HandShakeC2s(handshake) => {
                    handle_handshake(self, connection_id, &handshake)
                }
                ServerBoundPacket::LoginStartC2s(login_start) => {
                    handle_login_start(self, connection_id, &login_start)
                }
                ServerBoundPacket::StatusRequestC2s(status_request) => {
                    handle_status_request(self, connection_id, &status_request)
                }
                ServerBoundPacket::PingRequestC2s(ping_request) => {
                    handle_ping_request(self, connection_id, &ping_request)
                }
                ServerBoundPacket::EncryptionResponseC2s(encryption_response) => {
                    handle_encryption_response(self, connection_id, &encryption_response)
                }
                ServerBoundPacket::LoginAckC2s(login_ack) => {
                    handle_login_ack(self, connection_id, &login_ack)
                }
            }?;
        }
        Ok(())
    }

    pub fn send_packet(
        &mut self,
        connection_id: ConnectionId,
        packet: &ClientBoundPacket,
    ) -> Result<(), ()> {
        let connection = self.get_connection_mut(connection_id);
        let buf = &mut *connection.write_buf;
        let start_len = buf.remaining();
        connection.state.encode_client_bound_packet(packet, buf)?;

        let data_len = buf.remaining() - start_len;

        if let (Some(threshold), Some(compression_level)) = (
            connection.compression_threshold,
            connection.compression_level,
        ) {
            if data_len > threshold as usize {
                let mut compress_buf = Vec::new();
                let mut z = ZlibEncoder::new(
                    &buf.get_continuous(data_len)[start_len..],
                    Compression::new(compression_level),
                );

                let packet_len = data_len + z.read_to_end(&mut compress_buf).unwrap();

                if packet_len >= MAX_PACKET_SIZE as usize {
                    return Err(());
                }

                drop(z);

                buf.advance(start_len);

                buf.write(&compress_buf);
            } else {
                let data_len_size = 1;
                let packet_len = data_len_size + data_len;

                if packet_len >= MAX_PACKET_SIZE as usize {
                    return Err(());
                }

                let data_prefix_len = packet_len + data_len_size;

                for _ in 0..data_prefix_len {
                    buf.write(&[0]);
                }

                let mut temp = vec![0; data_len];
                let mut bytes_read = 0;
                while bytes_read < data_len {
                    let chunk = buf.read(data_len - bytes_read);
                    if chunk.is_empty() {
                        return Err(());
                    }
                    temp[bytes_read..bytes_read + chunk.len()].copy_from_slice(chunk);
                    bytes_read += chunk.len();
                }

                buf.advance(data_prefix_len);
                buf.write(&temp);
            }
        }

        if let Some(cipher) = &connection.e_cipher {
            let mut encrypted_buf = bytes::BytesMut::from(buf.read(buf.remaining()));
            Self::encryption(&mut encrypted_buf, cipher.clone());
            buf.try_write(&encrypted_buf)?;
        }

        Ok(())
    }

    pub fn flush_write_buffer(&mut self, connection_id: ConnectionId) {
        let connection = self.get_connection_mut(connection_id);
        let buf = &mut *connection.write_buf;
        match connection.stream.write_all(buf.read(buf.remaining())) {
            Ok(()) => {}
            Err(_) => self.close_connection(connection_id),
        };
    }

    pub fn close_connection(&mut self, connection_id: ConnectionId) {
        let connection = unsafe { self.connections.get_unchecked_mut(connection_id as usize) };
        if let Some(client_id) = connection.related_http_client_id {
            self.http_clients.remove(client_id.get());
        }
        mio::Registry::deregister(&self.poll.registry(), &mut connection.stream).unwrap();
        let _result = connection.stream.shutdown(std::net::Shutdown::Both);
        self.connections.remove(connection_id);
    }

    fn generate_key_fair() -> (RsaPublicKey, RsaPrivateKey) {
        dbg!("Generating RSA key pair");
        let mut rng = thread_rng();

        let priv_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);
        (pub_key, priv_key)
    }

    fn encryption(
        buf: &mut bytes::BytesMut,
        mut cipher: cfb8::Encryptor<aes::Aes128>,
    ) -> bytes::BytesMut {
        for chunk in buf.chunks_mut(Encryptor::<aes::Aes128>::block_size()) {
            let gen_arr = generic_array::GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block_mut(gen_arr);
        }

        buf.split()
    }

    fn decrypt_bytes(cipher: &mut cfb8::Decryptor<aes::Aes128>, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(Decryptor::<aes::Aes128>::block_size()) {
            let gen_arr = GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block_mut(gen_arr);
        }
    }
}

impl Tick for Server {
    fn try_tick(&mut self) {
        self.tick_state.try_tick(|| {});
    }
}
