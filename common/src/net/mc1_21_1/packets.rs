use packetize::streaming_packets;

use super::packet::{
    client_info::ClientInformationC2s,
    disconnect::LoginDisconnectS2c,
    encryption::{EncryptionRequestS2c, EncryptionResponseC2s},
    feature_flags::FeatureFlagsS2c,
    finish_configuration::{FinishConfigurationAckC2s, FinishConfigurationS2c},
    handshake::HandShakeC2s,
    known_packs::{KnownPacksC2s, KnownPacksS2c},
    login::{LoginAckC2s, LoginStartC2s, LoginSuccessS2c},
    plugin_message::{
        PluginMessageConfC2s, PluginMessageConfS2c, PluginMessagePlayC2s, PluginMessagePlayS2c,
    },
    registry_data::RegistryDataS2c,
    set_compression::SetCompressionS2c,
    status::{PingRequestC2s, PingResponseS2c, StatusRequestC2s, StatusResponseS2c},
    update_tags::UpdateTagsS2c,
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
        #[id(0x00)] LoginStartC2s,
        #[id(0x00)] LoginDisconnectS2c,
        #[id(0x01)] EncryptionRequestS2c,
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
        #[id(0x0D)] UpdateTagsS2c,
    ),
    Play(
        #[id(0x19)] PluginMessagePlayS2c,
        #[id(0x12)] PluginMessagePlayC2s,
    ),
}
