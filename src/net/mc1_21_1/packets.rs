use packetize::streaming_packets;

use crate::packet_format::MinecraftPacketFormat;

use super::packet::{
    handshake::HandShakeC2s,
    login_start::LoginStartC2s,
    ping::PingRequestC2s,
    status::{StatusRequestC2s, StatusResponseS2c},
};

#[streaming_packets(MinecraftPacketFormat)]
#[derive(Debug, Default)]
pub enum Mc1_21_1ConnectionState {
    #[default]
    HandShake(HandShakeC2s),
    Status(StatusRequestC2s, StatusResponseS2c, PingRequestC2s),
    Login(LoginStartC2s),
}
