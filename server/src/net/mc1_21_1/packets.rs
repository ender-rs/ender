use packetize::{streaming_packets, ServerBoundPacketStream};

use crate::net::login_server::{ConnectionId, LoginServer};

use super::packet::{
    client_information::{handle_client_information, ClientInformationC2s},
    disconnect::LoginDisconnectS2c,
    encryption::{handle_encryption_response, EncryptionRequestS2c, EncryptionResponseC2s},
    feature_flags::FeatureFlagsS2c,
    finish_configuration::{
        handle_finish_configuration_ack, FinishConfigurationAckC2s, FinishConfigurationS2c,
    },
    handshake::{handle_handshake, HandShakeC2s},
    known_packs::{handle_known_packs, KnownPacksC2s, KnownPacksS2c},
    login_ack::{handle_login_ack, LoginAckC2s},
    login_start::{handle_login_start, LoginStartC2s},
    login_success::LoginSuccessS2c,
    ping::{handle_ping_request, PingRequestC2s, PingResponseS2c},
    plugin_message::{
        handle_plugin_message, PluginMessageConfC2s, PluginMessageConfS2c, PluginMessagePlayC2s,
        PluginMessagePlayS2c,
    },
    set_compression::SetCompressionS2c,
    status::{handle_status_request, StatusRequestC2s, StatusResponseS2c},
};

#[streaming_packets]
#[derive(Debug, Default)]
pub enum Mc1_21_1ConnectionState {
    #[default]
    HandShake(HandShakeC2s),
    Status(
        StatusRequestC2s,
        StatusResponseS2c,
        PingRequestC2s,
        PingResponseS2c,
    ),
    Login(
        LoginStartC2s,
        #[id(0)] LoginDisconnectS2c,
        #[id(1)] EncryptionRequestS2c,
        #[id(0x01)] EncryptionResponseC2s,
        #[id(0x02)] LoginSuccessS2c,
        #[id(0x03)] SetCompressionS2c,
        #[change_state_to(Conf)]
        #[id(0x03)]
        LoginAckC2s,
    ),
    Conf(
        #[id(0x00)] ClientInformationC2s,
        #[id(0x02)] PluginMessageConfC2s,
        #[id(0x01)] PluginMessageConfS2c,
        #[id(0x03)] FinishConfigurationS2c,
        #[change_state_to(Play)]
        #[id(0x03)]
        FinishConfigurationAckC2s,
        #[id(0x0C)] FeatureFlagsS2c,
        #[id(0x0E)] KnownPacksS2c,
        #[id(0x07)] KnownPacksC2s,
    ),
    Play(
        #[id(0x19)] PluginMessagePlayS2c,
        #[id(0x12)] PluginMessagePlayC2s,
    ),
}

pub fn handle_packet(server: &mut LoginServer, connection_id: ConnectionId) -> Result<(), ()> {
    let connection = server.get_connection_mut(connection_id);
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
    }
}
