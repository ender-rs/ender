use std::time::Duration;

use kanal::{AsyncReceiver, Receiver};
use mio::event::Event;
use slab::Slab;
use tick_machine::{Tick, TickState};

use super::{
    connection::{Connection, ConnectionId},
    mc1_21_1::packet::game_profile::GameProfile,
    server::ServerState,
};

pub struct GameServer {
    state: ServerState,
    tick_state: TickState,
    connections: Slab<GamePlayer>,
    receiver: Receiver<(Connection, GameProfile)>,
}

impl GameServer {
    const TICK: Duration = Duration::from_millis(50);
    const CONNECTIONS_CAPACITY: usize = 1000;

    pub fn new(receiver: Receiver<(Connection, GameProfile)>) -> Self {
        Self {
            state: ServerState::new(),
            connections: Slab::with_capacity(Self::CONNECTIONS_CAPACITY),
            receiver,
            tick_state: TickState::new(Self::TICK),
        }
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
        if !self.connections.contains(selection_key) {
            return;
        }
        match self.on_connection_read(selection_key) {
            Ok(()) => {}
            Err(()) => self.close_connection(selection_key as ConnectionId),
        }
    }

    fn on_connection_read(&mut self, selection_key: usize) -> Result<(), ()> {
        Ok(())
    }

    fn close_connection(&mut self, connection_id: ConnectionId) {}
}

impl Tick for GameServer {
    fn try_tick(&mut self) {
        self.tick_state.try_tick(|| {
            if let Ok(connection) = self.receiver.try_recv() {
                if let Some((connection, game_profile)) = connection {
                    println!("connection {:?} joined the server", game_profile.name);
                }
            };
        });
    }
}

pub struct GamePlayer {
    game_profile: GameProfile,
    connection: Connection,
}
