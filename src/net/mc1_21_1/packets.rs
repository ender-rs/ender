use packetize::streaming_packets;

use crate::packet_format::MinecraftPacketFormat;

use super::packet::handshake::HandShakeC2s;

#[streaming_packets(MinecraftPacketFormat)]
#[derive(Default)]
pub enum Mc1_21_1Packets {
    #[default]
    HandShake(HandShakeC2s),
}
