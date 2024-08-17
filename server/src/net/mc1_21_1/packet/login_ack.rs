use packetize::{Decode, Encode};

use crate::net::{connection::ConnectionId, login_server::LoginServer};

#[derive(Debug, Encode, Decode)]
pub struct LoginAckC2s;

pub fn handle_login_ack(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    login_ack: &LoginAckC2s,
) -> Result<(), ()> {
    println!("login ack received");
    Ok(())
}
