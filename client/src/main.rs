use std::{net::SocketAddr, str::FromStr};

use arrayvec::ArrayString;
use common::net::{
    connection::Connection,
    mc1_21_1::{
        packet::{
            handshake::{HandShakeC2s, NextState},
            login::LoginStartC2s,
        },
        packets::{ClientBoundPacket, Mc1_21_1ConnectionState},
    },
    protocol_version::ProtocolVersion,
};
use mio::net::TcpStream;
use packetize::ClientBoundPacketStream;
use uuid::Uuid;

#[derive(Debug)]
pub enum Error {
    TcpStreamConnectError,
    AddressParsingError,
    ReadToBufFromStreamError,
    SendPacketError,
    DecodePacketError,
    FlushWriteBufferError,
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    let addr_string = &args[1];
    let addr: SocketAddr = addr_string
        .parse()
        .map_err(|_| Error::AddressParsingError)?;
    let stream = std::net::TcpStream::connect(addr).map_err(|_| Error::TcpStreamConnectError)?;
    let stream = TcpStream::from_std(stream);
    let mut connection = Connection::new(stream);
    connection
        .send_packet_to_server(
            &HandShakeC2s {
                protocol_version: ProtocolVersion::Mc1_21_1,
                server_address: ArrayString::from_str(&addr_string).unwrap(),
                server_port: 25565,
                next_state: NextState::Login,
            }
            .into(),
        )
        .map_err(|_| Error::SendPacketError)?;
    connection.state = Mc1_21_1ConnectionState::Login;
    connection
        .send_packet_to_server(
            &LoginStartC2s {
                name: "EnderMan".into(),
                uuid: Uuid::nil(),
            }
            .into(),
        )
        .map_err(|_| Error::SendPacketError)?;
    connection
        .flush_write_buffer()
        .map_err(|_| Error::FlushWriteBufferError)?;
    read(&mut connection)?;
    Ok(())
}

fn read(connection: &mut Connection) -> Result<(), Error> {
    connection
        .read_to_buf_from_stream()
        .map_err(|_| Error::ReadToBufFromStreamError)?;
    let packet = connection
        .state
        .decode_client_bound_packet(&mut connection.read_buf, &mut connection.stream_state)
        .map_err(|_| Error::DecodePacketError)?;
    match packet {
        ClientBoundPacket::StatusResponseS2c(_) => todo!(),
        ClientBoundPacket::PingResponseS2c(_) => todo!(),
        ClientBoundPacket::LoginDisconnectS2c(login_disconnect) => {
            println!("{login_disconnect:?}");
        }
        ClientBoundPacket::EncryptionRequestS2c(_) => todo!(),
        ClientBoundPacket::LoginSuccessS2c(_) => todo!(),
        ClientBoundPacket::SetCompressionS2c(set_compression) => {}
        ClientBoundPacket::PluginMessageConfS2c(_) => todo!(),
        ClientBoundPacket::FinishConfigurationS2c(_) => todo!(),
        ClientBoundPacket::FeatureFlagsS2c(_) => todo!(),
        ClientBoundPacket::KnownPacksS2c(_) => todo!(),
        ClientBoundPacket::RegistryDataS2c(_) => todo!(),
        ClientBoundPacket::PluginMessagePlayS2c(_) => todo!(),
    }
    Ok(())
}
