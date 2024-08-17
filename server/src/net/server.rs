use mio::{net::TcpListener, Interest, Poll};
use tick_machine::TickState;

pub struct ServerState {
    pub poll: mio::Poll,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            poll: Poll::new().unwrap(),
        }
    }

    pub fn new_with_listener(
        listener: &mut TcpListener,
        listener_key: usize,
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

        Self { poll }
    }
}
