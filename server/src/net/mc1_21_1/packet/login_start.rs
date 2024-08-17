use std::mem::MaybeUninit;

use arrayvec::ArrayVec;
use packetize::{Decode, Encode};
use rand::random;
use uuid::Uuid;

use crate::{
    net::{
        connection::ConnectionId,
        login_server::LoginServer,
        mc1_21_1::packet::{encryption::EncryptionRequestS2c, set_compression::SetCompressionS2c},
    },
    player_name::PlayerName,
    var_string::VarString,
};

#[derive(Debug, Encode, Decode)]
pub struct LoginStartC2s {
    name: PlayerName,
    uuid: Uuid,
}

pub fn handle_login_start(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    login_start: &LoginStartC2s,
) -> Result<(), ()> {
    dbg!(login_start);

    let verify_token: [u8; 4] = random();
    let connection = server.get_connection_mut(connection_id);
    connection.verify_token = MaybeUninit::new(verify_token);
    let public_key_der = &server.info.public_key_der;

    dbg!(public_key_der.len());

    let mut public_key = ArrayVec::<u8, 161>::new();
    unsafe {
        std::ptr::copy_nonoverlapping(
            public_key_der.as_ptr(),
            public_key.as_mut_ptr(),
            public_key_der.len(),
        );
        public_key.set_len(public_key_der.len());
    }

    let mut verify_token_array = ArrayVec::<u8, 4>::new();
    unsafe {
        std::ptr::copy_nonoverlapping(
            verify_token.as_ptr(),
            verify_token_array.as_mut_ptr(),
            verify_token.len(),
        );
        verify_token_array.set_len(verify_token.len());
    }

    send_set_compression_packet(server, connection_id)?;
    server.send_packet(
        connection_id,
        &EncryptionRequestS2c {
            server_id: VarString::from_str("").unwrap(),
            public_key,
            verify_token: verify_token_array,
            should_authenticate: true,
        }
        .into(),
    )?;
    server.flush_write_buffer(connection_id);

    dbg!("Success send encrypt request");
    let connection = server.get_connection_mut(connection_id);
    connection.id = login_start.uuid;
    connection.name = login_start.name.clone();
    Ok(())
}

fn send_set_compression_packet(
    server: &mut LoginServer,
    connection_id: ConnectionId,
) -> Result<(), ()> {
    const DEFAULT_COMPRESSION_THRESHOLD: i32 = 256000;
    server.send_packet(
        connection_id,
        &SetCompressionS2c {
            threshold: DEFAULT_COMPRESSION_THRESHOLD.into(),
        }
        .into(),
    )?;
    server.flush_write_buffer(connection_id);
    server.enable_compression(connection_id, DEFAULT_COMPRESSION_THRESHOLD)?;
    Ok(())
}
