use packetize::streaming_packets;

use crate::packet_format::MinecraftPacketFormat;

use super::packet::{
    disconnect::LoginDisconnectS2c,
    encryption_request::EncryptionRequestS2c,
    encryption_response::EncryptionResponseC2s,
    finish_configuration::{FinishConfigurationAckC2s, FinishConfigurationS2c},
    handshake::HandShakeC2s,
    login_ack::LoginAckC2s,
    login_start::LoginStartC2s,
    login_success::LoginSuccessS2c,
    ping::{PingRequestC2s, PingResponseS2c},
    plugin_message::{
        PluginMessageConfC2s, PluginMessageConfS2c, PluginMessagePlayC2s, PluginMessagePlayS2c,
    },
    set_compression::SetCompressionS2c,
    status::{StatusRequestC2s, StatusResponseS2c},
};

#[streaming_packets(MinecraftPacketFormat)]
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
        #[id(0x02)] PluginMessageConfC2s,
        #[id(0x01)] PluginMessageConfS2c,
        #[id(0x03)] FinishConfigurationS2c,
        #[change_state_to(Play)]
        #[id(0x03)]
        FinishConfigurationAckC2s,
    ),
    Play(
        #[id(0x19)] PluginMessagePlayS2c,
        #[id(0x12)] PluginMessagePlayC2s,
    ),
}
