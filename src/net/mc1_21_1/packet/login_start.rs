use arrayvec::ArrayVec;
use packetize::{Decode, Encode};
use rand::random;
use uuid::Uuid;

use crate::{
    net::{
        mc1_21_1::packet::encryption_request::EncryptionRequestS2c,
        server::{ConnectionId, Server},
    },
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
) -> Result<(), ()> {
    dbg!(login_start);

    let verify_token: [u8; 4] = random();
    let public_key_der = &server.public_key_der;

    let mut public_key = ArrayVec::<u8, 327>::new();
    unsafe {
        std::ptr::copy_nonoverlapping(
            public_key_der.as_ptr(),
            public_key.as_mut_ptr(),
            public_key_der.len(),
        );
        public_key.set_len(public_key_der.len());
    }

    server.send_packet(
        connection_id,
        &EncryptionRequestS2c {
            server_id: VarString::from_str("").unwrap(),
            public_key_len: (public_key_der.len() as i32).into(),
            public_key,
            verity_token_len: (verify_token.len() as i32).into(),
            verify_token: verify_token.into(),
        }
        .into(),
    )?;
    dbg!("Success send encrypt request");
    Ok(())
}
