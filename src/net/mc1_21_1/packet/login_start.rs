use packetize::{Decode, Encode};
use uuid::Uuid;

use crate::{
    net::server::{ConnectionId, Server},
    var_string::VarString,
};

#[derive(Debug, Encode, Decode)]
pub struct LoginStartC2s {
    name: VarString<16>,
    uuid: Uuid,
}

pub fn handle_login_start(
    server: &mut Server,
    connection_id: ConnectionId,
    login_start: &LoginStartC2s,
) -> Result<(), ()>{
    dbg!(login_start);
    Ok(())
}
