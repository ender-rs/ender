use std::time::Duration;

use kanal::AsyncReceiver;
use slab::Slab;
use tick_machine::TickState;

use super::{
    connection::Connection, mc1_21_1::packet::game_profile::GameProfile, server::ServerState,
};

pub struct GameServer {
    server_state: ServerState,
    connections: Slab<Connection<GamePlayer>>,
    receiver: AsyncReceiver<Connection<GameProfile>>,
}

impl GameServer {
    const TICK: Duration = Duration::from_millis(50);
    const CONNECTIONS_CAPACITY: usize = 1000;

    pub fn new(receiver: AsyncReceiver<Connection<GameProfile>>) -> Self {
        Self {
            server_state: ServerState::new(TickState::new(Self::TICK)),
            connections: Slab::with_capacity(Self::CONNECTIONS_CAPACITY),
            receiver,
        }
    }

    pub fn start_loop(&mut self) -> ! {
        loop {}
    }
}

pub struct GamePlayer {}
