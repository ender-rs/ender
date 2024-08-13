use std::{collections::HashMap, hash::Hash, io::Write, time::Duration};

use aes::cipher::{generic_array, BlockDecryptMut, BlockEncryptMut, BlockSizeUser, KeyIvInit};
use cfb8::{Decryptor, Encryptor};
use fastbuf::{Buf, Buffer, ReadBuf, ReadToBuf, WriteBuf};
use fxhash::{FxBuildHasher, FxHashMap, FxHashSet, FxHasher};
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

pub struct Server {
    poll: mio::Poll,
    listener: mio::net::TcpListener,
    tick_state: TickState,
    connections: Slab<Connection>,
    public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
    pub public_key_der: Box<[u8]>,
    pub verify_tokens: HashMap<ConnectionId, [u8; 4], FxBuildHasher>,
}

pub const PACKET_BYTE_BUFFER_LENGTH: usize = 4096;

pub struct Connection {
    pub uuid: Uuid,
    pub player_name: PlayerName,
    pub read_buf: Box<Buffer<PACKET_BYTE_BUFFER_LENGTH>>,
    pub write_buf: Box<Buffer<4096>>,
    pub state: Mc1_21_1ConnectionState,
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
            uuid: Uuid::nil(),
            player_name: VarString::from_str("Unknown Player").unwrap().into(),
            e_cipher: None,
            d_cipher: None,
            encrypt_key: None,
        }
    }
}

pub type ConnectionId = usize;

impl Server {
    const LISTENER_KEY: usize = usize::MAX;
    const CONNECTIONS_CAPACITY: usize = 1000;
    const TICK: Duration = Duration::from_millis(50);

    pub fn new() -> Self {
        let (public_key, private_key) = Self::generate_key_fair();

        dbg!("keys generated");

        let public_key_der = rsa_der::public_key_to_der(
            &private_key.n().to_bytes_be(),
            &private_key.e().to_bytes_be(),
        )
        .into_boxed_slice();

        let poll = mio::Poll::new().unwrap();
        let addr = "[::]:25525".parse().unwrap();
        let mut listener = mio::net::TcpListener::bind(addr).unwrap();
        let registry = poll.registry();
        mio::event::Source::register(
            &mut listener,
            registry,
            mio::Token(Self::LISTENER_KEY),
            mio::Interest::READABLE,
        )
        .unwrap();
        let verify_tokens =
            HashMap::with_capacity_and_hasher(Self::CONNECTIONS_CAPACITY, FxBuildHasher::new());

        Self {
            poll,
            tick_state: TickState::new(Self::TICK),
            listener,
            connections: Slab::with_capacity(Self::CONNECTIONS_CAPACITY),
            public_key,
            private_key,
            public_key_der,
            verify_tokens,
        }
    }

    pub fn enable_encryption(
        &mut self,
        shared_secret: &[u8],
        connection_id: ConnectionId,
    ) -> Result<(), ()> {
        let crypt_key: [u8; 16] = shared_secret.try_into().unwrap();
        let connection = self.get_connection(connection_id);

        connection.e_cipher =
            Some(Encryptor::<aes::Aes128>::new_from_slices(&crypt_key, &crypt_key).unwrap());
        connection.d_cipher =
            Some(Decryptor::<aes::Aes128>::new_from_slices(&crypt_key, &crypt_key).unwrap());

        connection.encrypt_key = Some(crypt_key.to_vec());
        Ok(())
    }

    pub fn get_connection(&mut self, connection_id: ConnectionId) -> &mut Connection {
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
            for token in events.iter() {
                self.on_event(token.token().0);
            }
        }
    }

    fn on_event(&mut self, selection_key: usize) {
        if selection_key == Self::LISTENER_KEY {
            let (stream, _addr) = self.listener.accept().unwrap();
            let key = self.connections.insert(Connection::new(stream));
            let connection = unsafe { self.connections.get_unchecked_mut(key) };
            mio::Registry::register(
                &self.poll.registry(),
                &mut connection.stream,
                mio::Token(key),
                mio::Interest::READABLE,
            )
            .unwrap();
        } else {
            match self.on_connection_read(selection_key) {
                Ok(()) => {}
                Err(()) => self.close_connection(selection_key as ConnectionId),
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
        while self.get_connection(connection_id).read_buf.remaining() != 0 {
            let connection = unsafe { self.connections.get_unchecked_mut(connection_id as usize) };
            let buf = &mut *connection.read_buf;

            if let Some(cipher) = &mut connection.d_cipher {
                let mut decrypted_buf = bytes::BytesMut::from(buf.read(buf.remaining()));
                Server::decrypt_bytes(cipher, &mut decrypted_buf);
                buf.try_write(&decrypted_buf)?;
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
        let connection = self.get_connection(connection_id);
        let buf = &mut *connection.write_buf;
        connection.state.encode_client_bound_packet(packet, buf)?;

        if let Some(cipher) = &connection.e_cipher {
            let mut encrypted_buf = bytes::BytesMut::from(buf.read(buf.remaining()));
            Self::encryption(&mut encrypted_buf, cipher.clone());
            buf.try_write(&encrypted_buf)?;
        }

        Ok(())
    }

    pub fn flush_write_buffer(&mut self, connection_id: ConnectionId) {
        let connection = self.get_connection(connection_id);
        let buf = &mut *connection.write_buf;
        match connection.stream.write_all(buf.read(buf.remaining())) {
            Ok(()) => {}
            Err(_) => self.close_connection(connection_id),
        };
    }

    fn close_connection(&mut self, connection_id: ConnectionId) {
        let connection = unsafe { self.connections.get_unchecked_mut(connection_id as usize) };
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
