use arrayvec::ArrayVec;
use packetize::{Decode, Encode};
use rsa::Pkcs1v15Encrypt;

use crate::{
    net::server::{ConnectionId, Server},
    var_int::VarInt,
    var_string::VarString,
};

#[derive(Debug, Encode, Decode)]
pub struct EncryptionResponseC2s {
    pub shared_secret: ArrayVec<u8, 128>,
    pub verify_token: ArrayVec<u8, 128>,
}

pub fn handle_encryption_response(
    server: &mut Server,
    connection_id: ConnectionId,
    encryption_response: &EncryptionResponseC2s,
) -> Result<(), ()> {
    #[cfg(debug_assertions)]
    println!("{encryption_response:?}");

    let verify_token = server.verify_tokens.get(&connection_id).ok_or(())?;

    let decrypted_veify_token = server
        .private_key
        .decrypt(Pkcs1v15Encrypt, &encryption_response.verify_token)
        .unwrap();

    dbg!(&decrypted_veify_token);
    dbg!(verify_token);

    if decrypted_veify_token != *verify_token {
        dbg!("Verify token mismatch!");
        return Err(());
    }

    server.verify_tokens.remove(&connection_id);

    Ok(())
}
