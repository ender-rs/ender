use std::mem::transmute_copy;

use arrayvec::ArrayString;
use fastbuf::ReadBuf;
use fastvarint::VarInt;
use packetize::{streaming_packets, Decode, Encode, PacketStreamFormat};

#[streaming_packets(MinecraftPacketFormat)]
#[derive(Default)]
pub enum Mc1_21_1Packets {
    #[default]
    HandShake(HandShakeC2s),
}

#[derive(Encode, Decode)]
pub struct HandShakeC2s {
    protocol_version: ProtocolVersion,
    server_address: ArrayString<255>,
    server_port: u16,
    next_state: NextState,
}

#[derive(Encode, Decode)]
pub enum NextState {
    Status = 1,
    Login = 2,
    Transfer = 3,
}

#[derive(Encode, Decode)]
pub enum ProtocolVersion {
    Mc1_21_1,
}

pub struct MinecraftPacketFormat;

impl PacketStreamFormat for MinecraftPacketFormat {
    fn read_packet_id<ID>(buf: &mut impl ReadBuf) -> Result<ID, ()>
    where
        ID: Default,
    {
        const MAX_VAR_INT_SPACE: usize = <u32 as VarInt>::MAX_VAR_INT_SPACE;
        let buffer = buf.get_continuous(MAX_VAR_INT_SPACE);
        let (data, read_length) = u32::decode_var(|i| Ok(unsafe { *buffer.get_unchecked(i) }))?;
        buf.advance(read_length);
        Ok(unsafe { transmute_copy(&data) })
    }

    fn write_packet_with_id<T, P>(
        state: &mut T,
        packet: &P,
        buf: &mut impl fastbuf::WriteBuf,
    ) -> Result<(), ()>
    where
        P: packetize::Packet<T> + Encode,
    {
        let id = P::id(state).ok_or(())?;
        id.encode_var(|b| {
            buf.write(&[b]);
            Ok(())
        })?;
        packet.encode(buf)?;
        Ok(())
    }
}
