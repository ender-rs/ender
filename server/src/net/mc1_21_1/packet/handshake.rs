use std::mem::transmute_copy;

use arrayvec::ArrayString;
use fastbuf::{ReadBuf, WriteBuf};
use packetize::{Decode, Encode};

use crate::{
    net::{
        connection::ConnectionId, login_server::LoginServer,
        mc1_21_1::packets::Mc1_21_1ConnectionState, protocol_version::ProtocolVersion,
    },
    var_int::VarInt,
};

#[derive(Debug, Encode, Decode)]
pub struct HandShakeC2s {
    pub protocol_version: ProtocolVersion,
    pub server_address: ArrayString<1000>,
    pub server_port: u16,
    pub next_state: NextState,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum NextState {
    Status = 1,
    Login = 2,
    Transfer = 3,
}

impl Encode for NextState {
    fn encode(&self, buf: &mut impl WriteBuf) -> Result<(), ()> {
        VarInt::from(*self as i32).encode(buf)?;
        Ok(())
    }
}

impl Decode for NextState {
    fn decode(buf: &mut impl ReadBuf) -> Result<Self, ()> {
        Ok(unsafe { transmute_copy(&VarInt::decode(buf)?) })
    }
}

pub fn handle_handshake(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    handshake: &HandShakeC2s,
) -> Result<(), ()> {
    let connection = server.get_connection_mut(connection_id);
    connection.connection.state = match handshake.next_state {
        NextState::Status => Mc1_21_1ConnectionState::Status,
        NextState::Login => Mc1_21_1ConnectionState::Login,
        NextState::Transfer => todo!(),
    };
    Ok(())
}
