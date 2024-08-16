use packetize::{Decode, Encode};

use crate::{
    identifier::Identifier,
    net::login_server::{ConnectionId, LoginServer},
};

#[derive(Debug, Encode, Decode)]
pub struct FeatureFlagsS2c {
    flags: Vec<Identifier>,
}
