use arrayvec::ArrayVec;
use num_bigint::BigInt;
use packetize::{Decode, Encode};
use rsa::Pkcs1v15Encrypt;
use sha1::{Digest, Sha1};

use crate::{
    net::{
        mc1_21_1::packet::login_success::LoginSuccessS2c,
        server::{ConnectionId, Server},
    },
    player_name,
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
        server.verify_tokens.remove(&connection_id);
        return Err(());
    }

    server.verify_tokens.remove(&connection_id);

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
    let connection = server.get_connection(connection_id);
    let ip = connection.stream.peer_addr().unwrap();

    // auth

    send_login_success_packet(server, connection_id)?;

    Ok(())
}

fn send_login_success_packet(server: &mut Server, connection_id: ConnectionId) -> Result<(), ()> {
    let connection = server.get_connection(connection_id);
    let uuid = connection.uuid;
    let username = connection.player_name.clone();
    server.send_packet(
        connection_id,
        &LoginSuccessS2c {
            uuid,
            username,
            properties: Vec::new(),
            strict_error_handling: false,
        }
        .into(),
    )?;
    server.flush_write_buffer(connection_id);
    Ok(())
}
