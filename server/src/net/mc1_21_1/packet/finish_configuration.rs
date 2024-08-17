use packetize::{Decode, Encode};

use crate::net::{connection::ConnectionId, login_server::LoginServer};

#[derive(Encode, Decode, Debug)]
pub struct FinishConfigurationS2c;

#[derive(Encode, Decode, Debug)]
pub struct FinishConfigurationAckC2s;

pub fn handle_finish_configuration_ack(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    finish_conf_ack: &FinishConfigurationAckC2s,
) -> Result<(), ()> {
    Ok(())
}
