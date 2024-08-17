use std::{
    future::IntoFuture,
    io::{self, Read},
    mem::MaybeUninit,
    time::Duration,
};

use aes::cipher::KeyIvInit;
use cfb8::{Decryptor, Encryptor};
use derive_more::derive::{Deref, DerefMut};
use fastbuf::{Buf, ReadBuf, ReadToBuf, WriteBuf};
use kanal::{AsyncSender, Sender};
use mio::{event::Event, net::TcpListener, Interest};
use nonmax::{NonMaxI32, NonMaxUsize};
use packetize::ClientBoundPacketStream;
use slab::Slab;

use super::{
    connection::{self, Connection, ConnectionId},
    cryptic::{self, CrypticState},
    http_client::HttpClient,
    mc1_21_1::{packet::game_profile::GameProfile, packets::ClientBoundPacket},
    server::ServerState,
};

pub const PACKET_BYTE_BUFFER_LENGTH: usize = 4096;
pub const MAX_PACKET_SIZE: i32 = 2097152;

pub struct LoginServer {
    pub info: CrypticState,
    pub state: ServerState,
    pub connections: Slab<LoginConnection>,
    listener: TcpListener,
    pub http_clients: Slab<HttpClient>,
    pub game_player_sender: Sender<(Connection, GameProfile)>,
}

#[derive(Deref, DerefMut)]
pub struct LoginConnection {
    #[deref]
    #[deref_mut]
    game_profile: GameProfile,
    pub verify_token: MaybeUninit<[u8; 4]>,
    pub related_http_client_id: Option<NonMaxUsize>,
    pub connection: Connection,
}

impl LoginServer {
    const LISTENER_KEY: usize = usize::MAX;
    pub const CONNECTIONS_CAPACITY: usize = 1000;
    const HTTP_REQUESTS_CAPACITY: usize = 30;
    const PORT: u16 = 25565;

    pub fn new(game_player_sender: Sender<(Connection, GameProfile)>) -> Self {
        let addr = format!("[::]:{}", Self::PORT).parse().unwrap();
        let mut listener = TcpListener::bind(addr).unwrap();
        let state = ServerState::new_with_listener(&mut listener, Self::LISTENER_KEY);
        Self {
            listener,
            state,
            connections: Slab::with_capacity(Self::CONNECTIONS_CAPACITY),
            info: CrypticState::new(),
            http_clients: Slab::with_capacity(Self::HTTP_REQUESTS_CAPACITY),
            game_player_sender,
        }
    }

    pub fn get_connection_mut(&mut self, connection_id: ConnectionId) -> &mut LoginConnection {
        // SAFETY: connection id must valid
        unsafe { self.connections.get_unchecked_mut(connection_id as usize) }
    }

    pub fn try_get_connection_mut(
        &mut self,
        connection_id: ConnectionId,
    ) -> Option<&mut LoginConnection> {
        self.connections.get_mut(connection_id as usize)
    }

    pub fn start_loop(&mut self) -> ! {
        let mut events = mio::Events::with_capacity(Self::CONNECTIONS_CAPACITY);
        loop {
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
            let (stream, _addr) = self.listener.accept().unwrap();
            if self.connections.len() >= Self::CONNECTIONS_CAPACITY {
                #[cfg(debug_assertions)]
                println!("cannot accept TCP stream due to max connection capacity reached");
                return;
            }
            let key = self.connections.insert(LoginConnection {
                connection: Connection::new(stream),
                game_profile: GameProfile::default(),
                verify_token: MaybeUninit::uninit(),
                related_http_client_id: None,
            });
            let connection = unsafe { self.connections.get_unchecked_mut(key) };
            mio::Registry::register(
                &self.state.poll.registry(),
                &mut connection.connection.stream,
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
                    if let Some(client) = self.close_http_client(client_id) {
                        self.close_connection(client.connection_id);
                    }
                }
            }
        }
    }

    //TODO move to connection impl block
    fn on_connection_read(&mut self, connection_id: ConnectionId) -> Result<(), ()> {
        let login_connection = unsafe { self.connections.get_unchecked_mut(connection_id) };

        if let Some(ref mut cipher) = &mut login_connection.connection.d_cipher {
            #[allow(invalid_value)]
            let mut buf =
                unsafe { MaybeUninit::<[u8; PACKET_BYTE_BUFFER_LENGTH]>::uninit().assume_init() };
            let read_length = login_connection
                .connection
                .stream
                .read(&mut buf)
                .map_err(|_| ())?;
            if read_length == 0 {
                return Err(());
            }

            let buf = &mut buf[..read_length];
            cryptic::decrypt(cipher, buf);
            login_connection.connection.read_buf.try_write(buf)?;
        } else {
            login_connection
                .connection
                .stream
                .read_to_buf(&mut login_connection.connection.read_buf)?;
        }
        self.on_read_packet(connection_id as ConnectionId)?;
        Ok(())
    }

    fn on_read_packet(&mut self, connection_id: ConnectionId) -> Result<(), ()> {
        while self
            .get_connection_mut(connection_id)
            .connection
            .read_buf
            .remaining()
            != 0
        {
            super::mc1_21_1::packets::handle_packet(self, connection_id)?;
        }
        let connection = unsafe { self.connections.get_unchecked_mut(connection_id) };
        connection.connection.read_buf.clear();
        Ok(())
    }

    pub fn send_packet(
        &mut self,
        connection_id: ConnectionId,
        packet: &ClientBoundPacket,
    ) -> Result<(), ()> {
        let connection = self.get_connection_mut(connection_id);
        connection.connection.state.encode_client_bound_packet(
            packet,
            &mut *connection.connection.write_buf,
            &mut connection.connection.stream_state,
        )?;
        Ok(())
    }

    pub fn flush_write_buffer(&mut self, connection_id: ConnectionId) {
        let connection = self.get_connection_mut(connection_id);
        let buf = &mut *connection.connection.write_buf;
        if let Some(ref mut cipher) = &mut connection.connection.e_cipher {
            let pos = buf.pos();
            let filled_pos = buf.filled_pos();
            let encrypted_buf = unsafe { buf.to_slice_mut().get_unchecked_mut(pos..filled_pos) };
            cryptic::encrypt(encrypted_buf, cipher);
        }

        match io::Write::write_all(&mut connection.connection.stream, buf.read(buf.remaining())) {
            Ok(()) => {
                let connection = self.get_connection_mut(connection_id);
                let buf = &mut *connection.connection.write_buf;
                buf.clear();
            }
            Err(_) => self.close_connection(connection_id),
        };
    }

    pub fn remove_attached_http_client(&mut self, connection_id: ConnectionId) {
        let connection = unsafe { self.connections.get_unchecked_mut(connection_id as usize) };
        if let Some(client_id) = connection.related_http_client_id {
            let mut client = self.http_clients.remove(client_id.get());
            mio::Registry::deregister(&self.state.poll.registry(), &mut client.stream).unwrap();
            connection.related_http_client_id = None;
        }
    }

    pub fn close_connection(&mut self, connection_id: ConnectionId) {
        self.remove_attached_http_client(connection_id);
        if let Some(connection) = self.connections.get_mut(connection_id) {
            mio::Registry::deregister(
                &self.state.poll.registry(),
                &mut connection.connection.stream,
            )
            .unwrap();
            self.connections.remove(connection_id);
        }
    }

    pub fn send_player_to_game_server(&mut self, connection_id: ConnectionId) {
        self.remove_attached_http_client(connection_id);
        let connection = self.connections.remove(connection_id);
        let sender = &self.game_player_sender;
        sender
            .send((connection.connection, connection.game_profile))
            .unwrap();
    }

    pub fn enable_encryption(
        &mut self,
        shared_secret: &[u8],
        connection_id: ConnectionId,
    ) -> Result<(), ()> {
        let crypt_key: [u8; 16] = shared_secret.try_into().unwrap();
        let connection = self.get_connection_mut(connection_id);
        connection.connection.e_cipher =
            Some(Encryptor::<aes::Aes128>::new_from_slices(&crypt_key, &crypt_key).unwrap());
        connection.connection.d_cipher =
            Some(Decryptor::<aes::Aes128>::new_from_slices(&crypt_key, &crypt_key).unwrap());
        connection.connection.encrypt_key = Some(crypt_key.to_vec());
        Ok(())
    }

    pub fn enable_compression(
        &mut self,
        connection_id: ConnectionId,
        threshold: i32,
    ) -> Result<(), ()> {
        let connection = self.get_connection_mut(connection_id);
        if threshold == -1 {
            connection.connection.stream_state.compression_threshold = None;
        } else {
            connection.connection.stream_state.compression_threshold =
                Some(unsafe { NonMaxI32::new_unchecked(threshold) });
        }
        Ok(())
    }
}
