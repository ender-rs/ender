use std::{fs::File, io::Write, mem::MaybeUninit, net::SocketAddr, str::FromStr};

use arrayvec::ArrayString;
use common::{
    net::{
        connection::Connection,
        mc1_21_1::{
            packet::{
                client_info::{ChatMode, ClientInformationC2s, DisplaySkinParts, MainHand},
                handshake::{HandShakeC2s, NextState},
                known_packs::{KnownPack, KnownPacks, KnownPacksC2s},
                login::{LoginAckC2s, LoginStartC2s},
            },
            packets::{ClientBoundPacket, Mc1_21_1ConnectionState},
        },
        protocol_version::ProtocolVersion,
    },
    packet_format::PACKET_BYTE_BUFFER_LENGTH,
};
use fastbuf::ReadBuf;
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
    CompressionEnablingError,
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    let addr_string = &args[1];
    let output_file = &args[2];
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
    #[allow(invalid_value)]
    let ref mut temp_buf =
        unsafe { MaybeUninit::<[u8; PACKET_BYTE_BUFFER_LENGTH]>::uninit().assume_init() };
    let mut file = File::create(output_file).unwrap();
    loop {
        match read(&mut connection, temp_buf, &mut file) {
            Ok(ReadResult::Done) => return Ok(()),
            Ok(ReadResult::NotDone) => {}
            Err(Error::DecodePacketError) => {}
            Err(err) => Err(err)?,
        };
    }
}

pub enum ReadResult {
    Done,
    NotDone,
}

fn read(
    connection: &mut Connection,
    temp_buf: &mut [u8; PACKET_BYTE_BUFFER_LENGTH],
    output_file: &mut File,
) -> Result<ReadResult, Error> {
    connection
        .read_to_buf_from_stream(temp_buf)
        .map_err(|_| Error::ReadToBufFromStreamError)?;
    while connection.read_buf.remaining() != 0 {
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
            ClientBoundPacket::LoginSuccessS2c(login_success) => {
                println!("{login_success:?}");
                connection
                    .send_packet_to_server(&LoginAckC2s.into())
                    .map_err(|_| Error::SendPacketError)?;
                connection
                    .send_packet_to_server(
                        &ClientInformationC2s {
                            locale: "ko_kr".into(),
                            view_distance: 12,
                            chat_mode: ChatMode::Enabled,
                            chat_colors: true,
                            display_skin_parts: DisplaySkinParts::all(),
                            main_hand: MainHand::Right,
                            enable_text_filtering: true,
                            allow_server_listings: true,
                        }
                        .into(),
                    )
                    .map_err(|_| Error::SendPacketError)?;

                connection
                    .send_packet_to_server(
                        &KnownPacksC2s(KnownPacks {
                            known_packs: vec![KnownPack {
                                namespace: "minecraft".into(),
                                id: "core".into(),
                                version: ProtocolVersion::Mc1_21_1.to_string().into(),
                            }],
                        })
                        .into(),
                    )
                    .map_err(|_| Error::SendPacketError)?;
                connection
                    .flush_write_buffer()
                    .map_err(|_| Error::FlushWriteBufferError)?;
            }
            ClientBoundPacket::SetCompressionS2c(set_compression) => {
                println!("{set_compression:?}");
                connection
                    .enable_compression(*set_compression.threshold)
                    .map_err(|_| Error::CompressionEnablingError)?;
            }
            ClientBoundPacket::PluginMessageConfS2c(plugin_msg) => {
                println!("{plugin_msg:?}");
            }
            ClientBoundPacket::FinishConfigurationS2c(_) => todo!(),
            ClientBoundPacket::FeatureFlagsS2c(feature_flags) => {
                println!("{feature_flags:?}");
            }
            ClientBoundPacket::KnownPacksS2c(known_packs) => {
                println!("{known_packs:?}");
            }
            ClientBoundPacket::RegistryDataS2c(registry_data) => {
                output_file
                    .write_all(
                        simd_json::to_string_pretty(&registry_data.to_json())
                            .unwrap()
                            .as_bytes(),
                    )
                    .unwrap();
            }
            ClientBoundPacket::PluginMessagePlayS2c(_) => todo!(),
            ClientBoundPacket::UpdateTagsS2c(update_tags) => {
                return Ok(ReadResult::Done);
                // println!("{update_tags:?}");
            }
        }
    }
    Ok(ReadResult::NotDone)
}
