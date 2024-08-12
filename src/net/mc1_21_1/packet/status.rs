use packetize::{Decode, Encode};

use crate::net::server::{ConnectionId, Server};

#[derive(Debug, Encode, Decode)]
pub struct StatusRequestC2s;

pub fn handle_status_request(
    server: &mut Server,
    connection_id: ConnectionId,
    status_request: &StatusRequestC2s,
) {
    dbg!(status_request);
}

#[derive(Debug, Encode, Decode)]
pub struct StatusResponseS2c;

pub fn handle_status_response(
    server: &mut Server,
    connection_id: ConnectionId,
    status_response: StatusResponseS2c,
) {
    dbg!(status_response);
}
