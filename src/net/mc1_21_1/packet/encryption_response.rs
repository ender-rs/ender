use arrayvec::ArrayVec;
use packetize::{Decode, Encode};

use crate::{
    net::server::{ConnectionId, Server},
    var_int::VarInt,
    var_string::VarString,
};

#[derive(Debug, Encode, Decode)]
pub struct EncryptionResponseC2s {
    pub shared_secret_len: VarInt,
    pub shared_secret: ArrayVec<u8, 20>,
    pub verify_token_len: VarInt,
    pub verify_token: ArrayVec<u8, 4>,
}

pub fn handle_encryption_response(
    server: &mut Server,
    connection_id: ConnectionId,
    encryption_response: &EncryptionResponseC2s,
) -> Result<(), ()> {
    dbg!(encryption_response);

    // let verify_token = server.verify_tokens.get(&connection_id).ok_or(())?;

    // if encryption_response.verify_token != *verify_token {
    //     return Err(());
    // }

    Ok(())
}
