use common::net::mc1_21_1::packets::ServerBoundPacket;
use packetize::ServerBoundPacketStream;

use crate::net::{connection::ConnectionId, game_server::GameServer, login_server::LoginServer};

use super::handlers::{handle_client_information, handle_encryption_response, handle_finish_configuration_ack, handle_handshake, handle_known_packs, handle_login_ack, handle_login_start, handle_ping_request, handle_plugin_message, handle_status_request};

pub fn handle_login_server_s_packet(
    server: &mut LoginServer,
    connection_id: ConnectionId,
) -> Result<(), ()> {
    let connection = &mut server.get_connection_mut(connection_id).connection;
    match connection
        .state
        .decode_server_bound_packet(&mut connection.read_buf, &mut connection.stream_state)?
    {
        ServerBoundPacket::HandShakeC2s(handshake) => {
            handle_handshake(server, connection_id, &handshake)
        }
        ServerBoundPacket::LoginStartC2s(login_start) => {
            handle_login_start(server, connection_id, &login_start)
        }
        ServerBoundPacket::StatusRequestC2s(status_request) => {
            handle_status_request(server, connection_id, &status_request)
        }
        ServerBoundPacket::PingRequestC2s(ping_request) => {
            handle_ping_request(server, connection_id, &ping_request)
        }
        ServerBoundPacket::EncryptionResponseC2s(encryption_response) => {
            handle_encryption_response(server, connection_id, &encryption_response)
        }
        _ => Err(()),
    }
}

pub fn handle_game_server_s_packet(
    server: &mut GameServer,
    connection_id: ConnectionId,
) -> Result<(), ()> {
    let connection = &mut server.get_connection_mut(connection_id).connection;
    match connection
        .state
        .decode_server_bound_packet(&mut connection.read_buf, &mut connection.stream_state)?
    {
        ServerBoundPacket::LoginAckC2s(login_ack) => {
            handle_login_ack(server, connection_id, &login_ack)
        }
        ServerBoundPacket::PluginMessageConfC2s(plugin_message) => {
            handle_plugin_message(server, connection_id, &plugin_message)
        }
        ServerBoundPacket::FinishConfigurationAckC2s(finish_conf_ack) => {
            handle_finish_configuration_ack(server, connection_id, &finish_conf_ack)
        }
        ServerBoundPacket::PluginMessagePlayC2s(plugin_message) => {
            handle_plugin_message(server, connection_id, &plugin_message)
        }
        ServerBoundPacket::ClientInformationC2s(client_info) => {
            handle_client_information(server, connection_id, &client_info)
        }
        ServerBoundPacket::KnownPacksC2s(known_packs) => {
            handle_known_packs(server, connection_id, &known_packs)
        }
        _ => Err(()),
    }
}
