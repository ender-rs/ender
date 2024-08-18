use std::{mem::MaybeUninit, time::Duration};

use common::{
    net::mc1_21_1::packet::game_profile::GameProfile, packet_format::PACKET_BYTE_BUFFER_LENGTH,
};
use derive_more::derive::{Deref, DerefMut};
use fastbuf::{Buf, ReadBuf};
use kanal::Receiver;
use mio::{event::Event, Interest, Poll, Token};
use slab::Slab;
use tick_machine::{Tick, TickState};

use common::net::connection::{Connection, ConnectionId};

pub struct GameServer {
    poll: Poll,
    temp_buf: Box<[u8; PACKET_BYTE_BUFFER_LENGTH]>,
    tick_state: TickState,
    connections: Slab<GamePlayer>,
    receiver: Receiver<(Connection, GameProfile)>,
}

#[derive(Deref, DerefMut)]
pub struct GamePlayer {
    game_profile: GameProfile,
    #[deref]
    #[deref_mut]
    pub connection: Connection,
}

impl GameServer {
    const TICK: Duration = Duration::from_millis(50);
    const CONNECTIONS_CAPACITY: usize = 1000;

    pub fn new(receiver: Receiver<(Connection, GameProfile)>) -> Self {
        Self {
            connections: Slab::new(),
            receiver,
            tick_state: TickState::new(Self::TICK),
            poll: Poll::new().unwrap(),
            #[allow(invalid_value)]
            temp_buf: Box::new(unsafe { MaybeUninit::uninit().assume_init() }),
        }
    }

    pub fn get_connection_mut(&mut self, connection_id: ConnectionId) -> &mut GamePlayer {
        unsafe { self.connections.get_unchecked_mut(connection_id) }
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
        if !self.connections.contains(selection_key) {
            return;
        }
        match self.on_connection_read(selection_key) {
            Ok(()) => {}
            Err(()) => self.close_connection(selection_key as ConnectionId),
        }
    }

    fn on_connection_read(&mut self, connection_id: ConnectionId) -> Result<(), ()> {
        let connection = unsafe { self.connections.get_unchecked_mut(connection_id) };
        connection
            .connection
            .read_to_buf_from_stream(&mut self.temp_buf)?;
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
            super::handler::mc_1_12_1_handler::handle_game_server_s_packet(self, connection_id)?;
        }
        let connection = unsafe { self.connections.get_unchecked_mut(connection_id) };
        connection.connection.read_buf.clear();
        Ok(())
    }

    fn close_connection(&mut self, connection_id: ConnectionId) {
        if let Some(connection) = self.connections.try_remove(connection_id) {}
    }
}

impl Tick for GameServer {
    fn try_tick(&mut self) {
        self.tick_state.try_tick(|| {
            if let Ok(connection) = self.receiver.try_recv_realtime() {
                if let Some((connection, game_profile)) = connection {
                    println!("connection {:?} joined the server", game_profile.name);
                    let connection_id = self.connections.insert(GamePlayer {
                        game_profile,
                        connection,
                    });
                    let connection = unsafe { self.connections.get_unchecked_mut(connection_id) };
                    self.poll
                        .registry()
                        .register(
                            &mut connection.stream,
                            Token(connection_id),
                            Interest::READABLE,
                        )
                        .unwrap();
                }
            };
        });
    }
}
