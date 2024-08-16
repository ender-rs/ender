use mio::{net::TcpListener, Interest};
use tick_machine::TickState;

pub struct ServerState {
    pub poll: mio::Poll,
    pub listener: mio::net::TcpListener,
    pub tick_state: TickState,
}

impl ServerState {
    pub fn new(mut listener: TcpListener, listener_key: usize, tick_state: TickState) -> Self {
        let poll = mio::Poll::new().unwrap();
        let registry = poll.registry();
        mio::event::Source::register(
            &mut listener,
            registry,
            mio::Token(listener_key),
            Interest::READABLE,
        )
        .unwrap();

        Self {
            poll,
            listener,
            tick_state,
        }
    }
}
