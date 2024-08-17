use std::{net::SocketAddr, str::FromStr};

use arrayvec::ArrayString;
use common::net::{
    connection::Connection,
    mc1_21_1::packet::handshake::{HandShakeC2s, NextState},
    protocol_version::ProtocolVersion,
};
use mio::net::TcpStream;
use packetize::{ClientBoundPacketStream, ServerBoundPacketStream};

fn main() -> Result<(), ()> {
    let args: Vec<String> = std::env::args().collect();
    let addr_string = &args[1];
    let addr: SocketAddr = addr_string.parse().unwrap();
    let stream = TcpStream::connect(addr).unwrap();
    let mut connection = Connection::new(stream);
    connection.send_packet_to_server(
        &HandShakeC2s {
            protocol_version: ProtocolVersion::Mc1_21_1,
            server_address: ArrayString::from_str(&addr_string).unwrap(),
            server_port: 25565,
            next_state: NextState::Login,
        }
        .into(),
    )?;
    Ok(())
}

fn read(connection: &mut Connection) -> Result<(), ()> {
    connection.read_to_buf_from_stream()?;
    let packet = connection
        .state
        .decode_client_bound_packet(&mut connection.read_buf, &mut connection.stream_state)?;
    Ok(())
}
