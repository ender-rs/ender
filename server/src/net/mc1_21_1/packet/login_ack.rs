use packetize::{Decode, Encode};

use crate::net::{
    connection::ConnectionId,
    game_server::GameServer,
    mc1_21_1::packet::{
        feature_flags::FeatureFlagsS2c,
        plugin_message::{PluginMessage, PluginMessageConfS2c},
    },
};

#[derive(Debug, Encode, Decode)]
pub struct LoginAckC2s;

pub fn handle_login_ack(
    server: &mut GameServer,
    connection_id: ConnectionId,
    login_ack: &LoginAckC2s,
) -> Result<(), ()> {
    dbg!(login_ack);
    let connection = server.get_connection_mut(connection_id);
    connection.send_packet(
        &FeatureFlagsS2c {
            flags: vec!["minecraft:vanilla".into()],
        }
        .into(),
    )?;
    connection.flush_write_buffer()?;
    Ok(())
}
