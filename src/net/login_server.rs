use std::{
    io::{self, Read},
    mem::MaybeUninit,
    net::IpAddr,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use aes::cipher::{generic_array, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit};
use cfb8::{Decryptor, Encryptor};
use fastbuf::{Buf, Buffer, ReadBuf, ReadToBuf, WriteBuf};
use mio::{event::Event, net::TcpListener, Interest};
use nonmax::{NonMaxI32, NonMaxUsize};
use packetize::ClientBoundPacketStream;
use rand::thread_rng;
use rsa::{
    signature::digest::generic_array::GenericArray, traits::PublicKeyParts, RsaPrivateKey,
    RsaPublicKey,
};
use rustls::pki_types::ServerName;
use slab::Slab;
use tick_machine::{Tick, TickState};
use uuid::Uuid;

use crate::{
    net::http_server::make_tls_config, packet_format::MinecraftPacketFormat,
    player_name::PlayerName, var_string::VarString,
};

use super::{
    http_server::HttpClient,
    mc1_21_1::packets::{ClientBoundPacket, Mc1_21_1ConnectionState},
    server::ServerState,
};

pub const PACKET_BYTE_BUFFER_LENGTH: usize = 4096;
pub const MAX_PACKET_SIZE: i32 = 2097152;

pub struct LoginServerInfo {
    pub public_key_der: Box<[u8]>,
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
    pub session_server_ip: IpAddr,
    pub session_server_name: ServerName<'static>,
    pub tls_config: Arc<rustls::ClientConfig>,
}

pub struct LoginServer {
    pub state: ServerState,
    pub info: LoginServerInfo,
    pub connections: Slab<Connection>,
    pub http_clients: Slab<HttpClient>,
}

pub struct Connection {
    pub uuid: Uuid,
    pub player_name: PlayerName,
    pub read_buf: Box<Buffer<PACKET_BYTE_BUFFER_LENGTH>>,
    pub write_buf: Box<Buffer<PACKET_BYTE_BUFFER_LENGTH>>,
    pub state: Mc1_21_1ConnectionState,
    pub packet_stream: MinecraftPacketFormat,
    pub stream: mio::net::TcpStream,
    pub encrypt_key: Option<Vec<u8>>,
    pub e_cipher: Option<Encryptor<aes::Aes128>>,
    pub d_cipher: Option<Decryptor<aes::Aes128>>,
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
            verify_token: MaybeUninit::uninit(),
            related_http_client_id: None,
            packet_stream: MinecraftPacketFormat::new(),
        }
    }
}

pub type ConnectionId = usize;

impl LoginServer {
    const LISTENER_KEY: usize = usize::MAX;
    pub const CONNECTIONS_CAPACITY: usize = 1000;
    const HTTP_REQUESTS_CAPACITY: usize = 30;
    const TICK: Duration = Duration::from_millis(50);
    const PORT: u16 = 25565;

    pub fn new() -> Self {
        let tls_config = make_tls_config();
        let (public_key, private_key) = Self::generate_key_fair();

        println!("keys generated");

        let public_key_der = rsa_der::public_key_to_der(
            &private_key.n().to_bytes_be(),
            &private_key.e().to_bytes_be(),
        )
        .into_boxed_slice();

        let session_server_ip = dns_lookup::lookup_host("sessionserver.mojang.com")
            .map_err(|_| ())
            .unwrap()
            .first()
            .map(|v| *v)
            .ok_or(())
            .unwrap();
        let session_server_name =
            ServerName::try_from(String::from_str("sessionserver.mojang.com").unwrap()).unwrap();

        let addr = format!("[::]:{}", Self::PORT).parse().unwrap();
        let listener = TcpListener::bind(addr).unwrap();
        Self {
            state: ServerState::new(listener, Self::LISTENER_KEY, TickState::new(Self::TICK)),
            connections: Slab::with_capacity(Self::CONNECTIONS_CAPACITY),
            info: LoginServerInfo {
                public_key,
                private_key,
                public_key_der,
                tls_config,
                session_server_ip,
                session_server_name,
            },
            http_clients: Slab::with_capacity(Self::HTTP_REQUESTS_CAPACITY),
        }
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
            self.state
                .poll
                .poll(&mut events, Some(Duration::ZERO))
                .unwrap();
            for event in events.iter() {
                self.on_event(event);
            }
        }
    }

    fn on_event(&mut self, selection_event: &Event) {
        let selection_key = selection_event.token().0;
        if selection_key == Self::LISTENER_KEY {
            let (stream, _addr) = self.state.listener.accept().unwrap();
            if self.connections.len() >= Self::CONNECTIONS_CAPACITY {
                #[cfg(debug_assertions)]
                println!("cannot accept TCP stream due to max connection capacity reached");
                return;
            }
            let key = self.connections.insert(Connection::new(stream));
            let connection = unsafe { self.connections.get_unchecked_mut(key) };
            mio::Registry::register(
                &self.state.poll.registry(),
                &mut connection.stream,
                mio::Token(key),
                Interest::READABLE,
            )
            .unwrap();
        } else if selection_key < Self::HTTP_CLIENT_ID_OFFSET {
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

        if let Some(ref mut cipher) = &mut connection.d_cipher {
            #[allow(invalid_value)]
            let mut buf =
                unsafe { MaybeUninit::<[u8; PACKET_BYTE_BUFFER_LENGTH]>::uninit().assume_init() };
            let read_length = connection.stream.read(&mut buf).map_err(|_| ())?;
            if read_length == 0 {
                return Err(());
            }

            let buf = &mut buf[..read_length];
            LoginServer::decrypt_bytes(cipher, buf);
            connection.read_buf.try_write(buf)?;
        } else {
            connection.stream.read_to_buf(&mut connection.read_buf)?;
        }
        self.on_read_packet(connection_id as ConnectionId)?;
        Ok(())
    }

    fn on_read_packet(&mut self, connection_id: ConnectionId) -> Result<(), ()> {
        while self.get_connection_mut(connection_id).read_buf.remaining() != 0 {
            super::mc1_21_1::packets::handle_packet(self, connection_id)?;
        }
        let connection = unsafe { self.connections.get_unchecked_mut(connection_id) };
        let buf = &mut *connection.read_buf;
        buf.clear();
        Ok(())
    }

    pub fn send_packet(
        &mut self,
        connection_id: ConnectionId,
        packet: &ClientBoundPacket,
    ) -> Result<(), ()> {
        let connection = self.get_connection_mut(connection_id);
        let buf = &mut *connection.write_buf;
        connection
            .state
            .encode_client_bound_packet(packet, buf, &mut connection.packet_stream)?;
        Ok(())
    }

    pub fn flush_write_buffer(&mut self, connection_id: ConnectionId) {
        let connection = self.get_connection_mut(connection_id);
        let buf = &mut *connection.write_buf;
        if let Some(ref mut cipher) = &mut connection.e_cipher {
            let pos = buf.pos();
            let filled_pos = buf.filled_pos();
            let encrypted_buf = unsafe { buf.to_slice_mut().get_unchecked_mut(pos..filled_pos) };
            Self::encryption(encrypted_buf, cipher);
        }

        match io::Write::write_all(&mut connection.stream, buf.read(buf.remaining())) {
            Ok(()) => {}
            Err(_) => self.close_connection(connection_id),
        };
        let connection = self.get_connection_mut(connection_id);
        let buf = &mut *connection.write_buf;
        buf.clear();
    }

    pub fn close_connection(&mut self, connection_id: ConnectionId) {
        let connection = unsafe { self.connections.get_unchecked_mut(connection_id as usize) };
        if let Some(client_id) = connection.related_http_client_id {
            let mut client = self.http_clients.remove(client_id.get());
            mio::Registry::deregister(&self.state.poll.registry(), &mut client.stream).unwrap();
        }
        mio::Registry::deregister(&self.state.poll.registry(), &mut connection.stream).unwrap();
        self.connections.remove(connection_id);
    }

    fn generate_key_fair() -> (RsaPublicKey, RsaPrivateKey) {
        println!("Generating RSA key pair");
        let mut rng = thread_rng();

        let priv_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);
        (pub_key, priv_key)
    }

    fn encryption(buf: &mut [u8], cipher: &mut cfb8::Encryptor<aes::Aes128>) {
        for chunk in buf.chunks_mut(Encryptor::<aes::Aes128>::block_size()) {
            let start = Instant::now();
            let gen_arr = generic_array::GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block_mut(gen_arr);
            println!("aes encryption: {:?}", start.elapsed());
        }
    }

    fn decrypt_bytes(cipher: &mut cfb8::Decryptor<aes::Aes128>, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(Decryptor::<aes::Aes128>::block_size()) {
            let gen_arr = GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block_mut(gen_arr);
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
    ) -> Result<(), ()> {
        let connection = self.get_connection_mut(connection_id);
        if threshold == -1 {
            connection.packet_stream.compression_threshold = None;
        } else {
            connection.packet_stream.compression_threshold =
                Some(unsafe { NonMaxI32::new_unchecked(threshold) });
        }
        Ok(())
    }
}

impl Tick for LoginServer {
    fn try_tick(&mut self) {
        self.state.tick_state.try_tick(|| {});
    }
}
