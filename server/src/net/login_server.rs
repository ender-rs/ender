use std::{
    io::{self},
    mem::MaybeUninit,
    time::Duration,
};

use aes::cipher::KeyIvInit;
use cfb8::{Decryptor, Encryptor};
use derive_more::derive::{Deref, DerefMut};
use fastbuf::{Buf, ReadBuf};
use kanal::Sender;
use mio::{event::Event, net::TcpListener, Interest, Poll};
use nonmax::{NonMaxI32, NonMaxUsize};
use slab::Slab;

use super::{
    connection::{Connection, ConnectionId},
    cryptic::{self, CrypticState},
    http_client::HttpClient,
    mc1_21_1::{packet::game_profile::GameProfile, packets::ClientBoundPacket},
};

pub const PACKET_BYTE_BUFFER_LENGTH: usize = 4096;
pub const MAX_PACKET_SIZE: i32 = 2097152;

pub struct LoginServer {
    pub info: CrypticState,
    pub poll: Poll,
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
    pub attached_http_client_id: Option<NonMaxUsize>,
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
        let poll = mio::Poll::new().unwrap();
        let registry = poll.registry();
        mio::event::Source::register(
            &mut listener,
            registry,
            mio::Token(Self::LISTENER_KEY),
            Interest::READABLE,
        )
        .unwrap();

        Self {
            listener,
            poll,
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
            let key = self.connections.insert(LoginConnection {
                connection: Connection::new(stream),
                game_profile: GameProfile::default(),
                verify_token: MaybeUninit::uninit(),
                attached_http_client_id: None,
            });
            let connection = unsafe { self.connections.get_unchecked_mut(key) };
            mio::Registry::register(
                &self.poll.registry(),
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

    fn on_connection_read(&mut self, connection_id: ConnectionId) -> Result<(), ()> {
        let connection = self.get_connection_mut(connection_id);
        connection.connection.read_to_buf_from_stream()?;
        self.on_read_packet(connection_id)?;
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
            super::mc1_21_1::packets::handle_login_server_s_packet(self, connection_id)?;
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
        connection.connection.send_packet(packet)?;
        Ok(())
    }

    pub fn flush_write_buffer(&mut self, connection_id: ConnectionId) -> Result<(), ()> {
        let connection = self.get_connection_mut(connection_id);
        connection.connection.flush_write_buffer()?;
        Ok(())
    }

    pub fn remove_attached_http_client(&mut self, connection_id: ConnectionId) {
        let connection = unsafe { self.connections.get_unchecked_mut(connection_id as usize) };
        if let Some(client_id) = connection.attached_http_client_id {
            let mut client = self.http_clients.remove(client_id.get());
            mio::Registry::deregister(&self.poll.registry(), &mut client.stream).unwrap();
            connection.attached_http_client_id = None;
        }
    }

    pub fn close_connection(&mut self, connection_id: ConnectionId) {
        self.remove_attached_http_client(connection_id);
        if let Some(connection) = self.connections.get_mut(connection_id) {
            connection.connection.close(self.poll.registry());
            self.connections.remove(connection_id);
        }
    }

    pub fn transfer_player_to_game_server(&mut self, connection_id: ConnectionId) {
        self.remove_attached_http_client(connection_id);
        let mut connection = self.connections.remove(connection_id);
        self.poll
            .registry()
            .deregister(&mut connection.connection.stream)
            .unwrap();
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
