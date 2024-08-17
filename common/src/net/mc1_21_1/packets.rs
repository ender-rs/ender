use packetize::{streaming_packets, ServerBoundPacketStream};

use super::packet::{
    client_information::ClientInformationC2s,
    disconnect::LoginDisconnectS2c,
    encryption::{EncryptionRequestS2c, EncryptionResponseC2s},
    feature_flags::FeatureFlagsS2c,
    finish_configuration::{FinishConfigurationAckC2s, FinishConfigurationS2c},
    handshake::HandShakeC2s,
    known_packs::{KnownPacksC2s, KnownPacksS2c},
    login_ack::LoginAckC2s,
    login_start::LoginStartC2s,
    login_success::LoginSuccessS2c,
    ping::{PingRequestC2s, PingResponseS2c},
    plugin_message::{
        PluginMessageConfC2s, PluginMessageConfS2c, PluginMessagePlayC2s, PluginMessagePlayS2c,
    },
    registry_data::RegistryDataS2c,
    set_compression::SetCompressionS2c,
    status::{StatusRequestC2s, StatusResponseS2c},
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
        #[id(0x07)] RegistryDataS2c,
    ),
    Play(
        #[id(0x19)] PluginMessagePlayS2c,
        #[id(0x12)] PluginMessagePlayC2s,
    ),
}

