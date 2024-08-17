use packetize::{Decode, Encode};

use crate::{net::{connection::ConnectionId, login_server::LoginServer}, var_string::VarString};

#[derive(Debug, Encode, Decode)]
pub struct Disconnect(Box<VarString<32767>>);

#[derive(Debug, Encode, Decode)]
pub struct LoginDisconnectS2c(Disconnect);

pub fn handle_disconnect(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    disconnect: &Disconnect,
) {
    dbg!(disconnect);
}
