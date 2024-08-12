use packetize::{Decode, Encode};

use crate::net::server::{ConnectionId, Server};

#[derive(Debug, Encode, Decode)]
pub struct PingRequestC2s;

pub fn handle_ping_request(
    server: &mut Server,
    connection_id: ConnectionId,
    ping_request: &PingRequestC2s,
) {
    dbg!(ping_request);
}
