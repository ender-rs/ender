use std::hint::black_box;

use arrayvec::ArrayString;
use ender::packets::{HandShakeC2s, Mc1_21_1Packets, NextState, ProtocolVersion::Mc1_21_1};
use fastbuf::Buffer;
use packetize::ServerBoundPacketStream;

#[divan::bench]
fn sandbox() {
    let mut state = Mc1_21_1Packets::HandShake;
    let mut buf = Buffer::<4096>::new();
    black_box(
        state.encode_server_bound_packet(
            &HandShakeC2s {
                protocol_version: Mc1_21_1,
                server_address: ArrayString::new(),
                server_port: 123,
                next_state: NextState::Login,
            }
            .into(),
            &mut buf,
        ),
    );
}

fn main() {
    divan::main()
}
