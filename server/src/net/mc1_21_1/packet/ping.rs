use packetize::{Decode, Encode};

use crate::net::login_server::{ConnectionId, LoginServer};

#[derive(Debug, Encode, Decode)]
pub struct PingRequestC2s {
    payload: i64,
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
    server.flush_write_buffer(connection_id);
    dbg!(ping_request);
    Ok(())
}

#[derive(Debug, Encode, Decode)]
pub struct PingResponseS2c {
    payload: i64,
}
