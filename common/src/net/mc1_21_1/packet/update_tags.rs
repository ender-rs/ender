use packetize::{Decode, Encode};

use crate::{identifier::Identifier, var_int::VarInt};

#[derive(Debug, Encode, Decode)]
pub struct UpdateTagsS2c {
    registry: Identifier,
    tags: Vec<Tags>,
}

#[derive(Debug, Encode, Decode)]
pub struct Tags {
    name: Identifier,
    entries: Vec<VarInt>,
}
