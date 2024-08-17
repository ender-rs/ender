use std::{mem::MaybeUninit, str::FromStr};

use arrayvec::ArrayVec;
use common::{
    net::{
        mc1_21_1::{
            packet::{
                client_information::ClientInformationC2s,
                disconnect::Disconnect,
                encryption::{EncryptionRequestS2c, EncryptionResponseC2s},
                feature_flags::FeatureFlagsS2c,
                finish_configuration::FinishConfigurationAckC2s,
                handshake::{HandShakeC2s, NextState},
                known_packs::KnownPacks,
                login::{LoginAckC2s, LoginStartC2s},
                plugin_message::PluginMessage,
                set_compression::SetCompressionS2c,
                status::{
                    Description, Players, Sample, Status, StatusRequestC2s, StatusResponseS2c,
                    Version,
                },
                status::{PingRequestC2s, PingResponseS2c},
            },
            packets::Mc1_21_1ConnectionState,
        },
        protocol_version::ProtocolVersion,
    },
    var_string::VarString,
};
use num_bigint::BigInt;
use rsa::Pkcs1v15Encrypt;
use sha1::{Digest, Sha1};
use uuid::Uuid;

use crate::net::{
    connection::ConnectionId, game_server::GameServer, http_client::HttpRequestEvent,
    login_server::LoginServer,
};

pub fn handle_client_information(
    server: &mut GameServer,
    connection_id: ConnectionId,
    client_information: &ClientInformationC2s,
) -> Result<(), ()> {
    dbg!(client_information);
    Ok(())
}

pub fn handle_disconnect(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    disconnect: &Disconnect,
) {
    dbg!(disconnect);
}

pub fn handle_encryption_response(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    encryption_response: &EncryptionResponseC2s,
) -> Result<(), ()> {
    let connection = server.get_connection_mut(connection_id);
    let verify_token = unsafe { connection.verify_token.assume_init() };

    let decrypted_veify_token = server
        .info
        .private_key
        .decrypt(Pkcs1v15Encrypt, &encryption_response.verify_token)
        .unwrap();

    if decrypted_veify_token.as_slice() != verify_token {
        dbg!("Verify token mismatch!");
        return Err(());
    }

    let decrypted_shared_secret = server
        .info
        .private_key
        .decrypt(Pkcs1v15Encrypt, &encryption_response.shared_secret)
        .unwrap();

    server.enable_encryption(&decrypted_shared_secret, connection_id)?;

    let hash = Sha1::new()
        .chain_update(&decrypted_shared_secret)
        .chain_update(&server.info.public_key_der)
        .finalize();
    let hash = BigInt::from_signed_bytes_be(&hash).to_str_radix(16);
    let connection = server.get_connection_mut(connection_id);
    let player_name = connection.name.to_string();

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

pub fn handle_finish_configuration_ack(
    server: &mut GameServer,
    connection_id: ConnectionId,
    finish_conf_ack: &FinishConfigurationAckC2s,
) -> Result<(), ()> {
    Ok(())
}

pub fn handle_handshake(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    handshake: &HandShakeC2s,
) -> Result<(), ()> {
    let connection = server.get_connection_mut(connection_id);
    connection.connection.state = match handshake.next_state {
        NextState::Status => Mc1_21_1ConnectionState::Status,
        NextState::Login => Mc1_21_1ConnectionState::Login,
        NextState::Transfer => todo!(),
    };
    Ok(())
}

pub fn handle_known_packs(
    server: &mut GameServer,
    connection_id: ConnectionId,
    known_packs: &KnownPacks,
) -> Result<(), ()> {
    Ok(())
}

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

pub fn handle_login_start(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    login_start: &LoginStartC2s,
) -> Result<(), ()> {
    dbg!(login_start);

    let verify_token: [u8; 4] = rand::random();
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
    server.flush_write_buffer(connection_id)?;

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
    server.flush_write_buffer(connection_id)?;
    server.enable_compression(connection_id, DEFAULT_COMPRESSION_THRESHOLD)?;
    Ok(())
}

pub fn handle_plugin_message(
    server: &mut GameServer,
    connection_id: ConnectionId,
    plugin_message: &PluginMessage,
) -> Result<(), ()> {
    println!("{plugin_message:?}");
    Ok(())
}

pub fn handle_status_request(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    status_request: &StatusRequestC2s,
) -> Result<(), ()> {
    dbg!(status_request);
    server.send_packet(
        connection_id,
        &StatusResponseS2c {
            status: Status {
                version: Version {
                    name: ProtocolVersion::Mc1_21_1.to_string(),
                    protocol: ProtocolVersion::Mc1_21_1,
                },
                players: Players {
                    max: 100,
                    online: 0,
                    sample: {
                        let mut vec = ArrayVec::new();
                        let value = Sample {
                            name: VarString::from_str("Notch").unwrap().into(),
                            id: Uuid::nil(),
                        };
                        unsafe { vec.push_unchecked(value) };
                        vec
                    },
                },
                description: Some(Description {
                    text: String::from_str("Hello ender").unwrap(),
                }),
                favicon: None,
                enforce_sercure_chat: false,
            },
        }
        .into(),
    )?;
    server.flush_write_buffer(connection_id)?;
    Ok(())
}

pub fn handle_ping_request(
    server: &mut LoginServer,
    connection_id: ConnectionId,
    ping_request: &PingRequestC2s,
) -> Result<(), ()> {
    server.send_packet(
        connection_id,
        &PingResponseS2c {
            payload: ping_request.payload,
        }
        .into(),
    )?;
    server.flush_write_buffer(connection_id)?;
    dbg!(ping_request);
    Ok(())
}
