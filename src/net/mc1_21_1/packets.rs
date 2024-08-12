use packetize::streaming_packets;

use crate::packet_format::MinecraftPacketFormat;

use super::packet::{
    disconnect::LoginDisconnectS2c,
    encryption_request::EncryptionRequestS2c,
    encryption_response::EncryptionResponseC2s,
    handshake::HandShakeC2s,
    login_start::LoginStartC2s,
    ping::{PingRequestC2s, PingResponseS2c},
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
        LoginDisconnectS2c,
        EncryptionRequestS2c,
        EncryptionResponseC2s,
    ),
}
