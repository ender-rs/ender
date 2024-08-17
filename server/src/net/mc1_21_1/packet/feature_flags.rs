use packetize::{Decode, Encode};

use crate::identifier::Identifier;

#[derive(Debug, Encode, Decode)]
pub struct FeatureFlagsS2c {
    pub flags: Vec<Identifier>,
}
