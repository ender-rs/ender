use mio::{net::TcpListener, Interest, Poll};
use tick_machine::TickState;

pub struct ServerState {
    pub poll: mio::Poll,
    pub tick_state: TickState,
}

impl ServerState {
    pub fn new(tick_state: TickState) -> Self {
        Self {
            poll: Poll::new().unwrap(),
            tick_state,
        }
    }

    pub fn new_with_listener(
        listener: &mut TcpListener,
        listener_key: usize,
        tick_state: TickState,
    ) -> Self {
        let poll = mio::Poll::new().unwrap();
        let registry = poll.registry();
        mio::event::Source::register(
            listener,
            registry,
            mio::Token(listener_key),
            Interest::READABLE,
        )
        .unwrap();

        Self { poll, tick_state }
    }
}
