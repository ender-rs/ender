use std::{io::Write, time::Duration};

use fastbuf::{Buffer, ReadBuf, ReadToBuf};
use packetize::{ClientBoundPacketStream, ServerBoundPacketStream};
use slab::Slab;
use tick_machine::{Tick, TickState};

use crate::net::mc1_21_1::packet::{
    handshake::handle_handshake, login_start::handle_login_start, status::handle_status_request,
};

use super::mc1_21_1::{
    packet::ping::handle_ping_request,
    packets::{ClientBoundPacket, Mc1_21_1ConnectionState, ServerBoundPacket},
};

pub struct Server {
    poll: mio::Poll,
    listener: mio::net::TcpListener,
    tick_state: TickState,
    connections: Slab<Connection>,
}

pub const PACKET_BYTE_BUFFER_LENGTH: usize = 4096;

pub struct Connection {
    pub read_buf: Box<Buffer<PACKET_BYTE_BUFFER_LENGTH>>,
    pub write_buf: Box<Buffer<4096>>,
    pub state: Mc1_21_1ConnectionState,
    pub stream: mio::net::TcpStream,
}

impl Connection {
    pub fn new(stream: mio::net::TcpStream) -> Self {
        Self {
            read_buf: Box::new(Buffer::new()),
            stream,
            state: Mc1_21_1ConnectionState::default(),
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
}

impl Tick for Server {
    fn try_tick(&mut self) {
        self.tick_state.try_tick(|| {});
    }
}
