use arrayvec::ArrayVec;
use num_bigint::BigInt;
use packetize::{Decode, Encode};
use rsa::Pkcs1v15Encrypt;
use sha1::{Digest, Sha1};

use crate::net::{
    http_server::HttpRequestEvent,
    login_server::{ConnectionId, LoginServer},
};

#[derive(Debug, Encode, Decode)]
pub struct EncryptionResponseC2s {
    pub shared_secret: ArrayVec<u8, 128>,
    pub verify_token: ArrayVec<u8, 128>,
}

pub fn handle_encryption_response(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    encryption_response: &EncryptionResponseC2s,
) -> Result<(), ()> {
    let connection = server.get_connection_mut(connection_id);
    let verify_token = unsafe { connection.verify_token.assume_init() };

    let decrypted_veify_token = server
        .private_key
        .decrypt(Pkcs1v15Encrypt, &encryption_response.verify_token)
        .unwrap();

    if decrypted_veify_token.as_slice() != verify_token {
        dbg!("Verify token mismatch!");
        return Err(());
    }

    let decrypted_shared_secret = server
        .private_key
        .decrypt(Pkcs1v15Encrypt, &encryption_response.shared_secret)
        .unwrap();

    server.enable_encryption(&decrypted_shared_secret, connection_id)?;

    let hash = Sha1::new()
        .chain_update(&decrypted_shared_secret)
        .chain_update(&server.public_key_der)
        .finalize();
    let hash = BigInt::from_signed_bytes_be(&hash).to_str_radix(16);
    let connection = server.get_connection_mut(connection_id);
    let player_name = connection.player_name.to_string();

    // Check if player are not banned
    // Unpack textures
    // Compression

    server.connect_http_request_client(
        connection_id,
        HttpRequestEvent::Auth {
            player_name,
            server_id: hash,
        },
    )?;

    Ok(())
}
