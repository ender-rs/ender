use packetize::{Decode, Encode};
use rand::random;
use uuid::Uuid;

use crate::{
    net::{
        mc1_21_1::packet::encryption_request::EncryptionRequestS2c,
        server::{ConnectionId, Server},
    },
    var_string::VarString,
    varint_sized_array::VarIntSizedArray,
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
) -> Result<(), ()> {
    dbg!(login_start);

    let verify_token: [u8; 4] = random();
    server.verify_tokens.insert(connection_id, verify_token);
    let public_key_der = &server.public_key_der;

    dbg!(public_key_der.len());

    let mut public_key = VarIntSizedArray::<u8, 293>::new();
    unsafe {
        std::ptr::copy_nonoverlapping(
            public_key_der.as_ptr(),
            public_key.as_mut_ptr(),
            public_key_der.len(),
        );
        public_key.set_len(public_key_der.len());
    }

    let mut verify_token_array = VarIntSizedArray::<u8, 4>::new();
    unsafe {
        std::ptr::copy_nonoverlapping(
            verify_token.as_ptr(),
            verify_token_array.as_mut_ptr(),
            verify_token.len(),
        );
        verify_token_array.set_len(verify_token.len());
    }

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
    Ok(())
}
