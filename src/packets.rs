use packetize::{streaming_packets, Decode, Encode, PacketStreamFormat};

#[streaming_packets(MinecraftPacketFormat)]
#[derive(Default)]
pub enum ConnectionState {
    #[default]
    HandShake(HandShakeC2s),
}

#[derive(Encode, Decode)]
pub struct HandShakeC2s {}

pub struct MinecraftPacketFormat;

impl PacketStreamFormat for MinecraftPacketFormat {
    fn read_packet_id<ID>(read_cursor: &mut impl fastbuf::ReadBuf) -> Result<ID, ()>
    where
        ID: Default,
    {
        todo!()
    }

    fn write_packet_with_id<T, P>(
        state: &mut T,
        packet: &P,
        cursor: &mut impl fastbuf::WriteBuf,
    ) -> Result<(), ()>
    where
        P: packetize::Packet<T> + packetize::Encode,
    {
        todo!()
    }
}
