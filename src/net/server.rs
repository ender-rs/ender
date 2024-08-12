use std::time::Duration;

use fastbuf::{Buffer, ReadBuf, ReadToBuf, WriteBuf};
use packetize::{Decode, ServerBoundPacketStream};
use slab::Slab;
use tick_machine::{Tick, TickState};

use crate::var_int::VarInt;

use super::mc1_21_1::{
    packet::handshake::HandShakeC2s,
    packets::{Mc1_21_1Packets, ServerBoundPacket},
};

pub struct Server {
    poll: mio::Poll,
    listener: mio::net::TcpListener,
    tick_state: TickState,
    connections: Slab<Connection>,
}

pub const PACKET_READ_BUFFER_LENGTH: usize = 4096;

pub struct Connection {
    read_buf: Box<Buffer<PACKET_READ_BUFFER_LENGTH>>,
    write_buf: Box<Buffer<4096>>,
    state: Mc1_21_1Packets,
    stream: mio::net::TcpStream,
}

impl Connection {
    pub fn new(stream: mio::net::TcpStream) -> Self {
        Self {
            read_buf: Box::new(Buffer::new()),
            stream,
            state: Mc1_21_1Packets::default(),
            write_buf: Box::new(Buffer::new()),
        }
    }
}

pub type ConnectionId = usize;

impl Server {
    const LISTENER_KEY: usize = usize::MAX;
    const CONNECTIONS_CAPACITY: usize = 1000;
    const TICK: Duration = Duration::from_millis(50);

    pub fn new() -> Self {
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
        Self {
            poll,
            tick_state: TickState::new(Self::TICK),
            listener,
            connections: Slab::with_capacity(Self::CONNECTIONS_CAPACITY),
        }
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
            self.poll
                .registry()
                .register(
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
        let connection = unsafe { self.connections.get_unchecked_mut(connection_id as usize) };
        let buf = &mut *connection.read_buf;
        println!("{:?}", buf.remaining());
        while buf.remaining() != 0 {
            dbg!(buf.pos());
            dbg!(buf.remaining());
            dbg!(buf.filled_len());
            let packet_len: i32 = VarInt::decode(buf)?.into();
            if packet_len as usize > buf.remaining() {
                Err(())?;
            }
            let backup_filled_len = buf.filled_len();
            unsafe { buf.set_filled_len(buf.pos() + packet_len as usize) };
            println!("HIHIHI");
            match connection.state.decode_server_bound_packet(buf)? {
                ServerBoundPacket::HandShakeC2s(HandShakeC2s {
                    protocol_version,
                    server_address,
                    server_port,
                    next_state,
                }) => {
                    dbg!(protocol_version, server_address, server_port, next_state);
                }
            };
            unsafe { buf.set_filled_len(backup_filled_len) };
        }
        Ok(())
    }

    fn close_connection(&mut self, connection_id: ConnectionId) {
        let connection = unsafe { self.connections.get_unchecked_mut(connection_id as usize) };
        mio::Registry::deregister(&self.poll.registry(), &mut connection.stream).unwrap();
        let _result = connection.stream.shutdown(std::net::Shutdown::Both);
        self.connections.remove(connection_id);
    }
}

impl Tick for Server {
    fn try_tick(&mut self) {
        self.tick_state.try_tick(|| {});
    }
}
