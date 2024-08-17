use packetize::{Decode, Encode};

use crate::identifier::Identifier;

#[derive(Debug, Encode, Decode)]
pub struct RegistryDataS2c {
    id: Identifier,
    entries: Vec<Entry>,
}

#[derive(Debug, Encode, Decode)]
pub struct Entry {
    id: Identifier,
    data: Option<EnrtyData>,
}

#[derive(Debug, Encode, Decode)]
pub struct EnrtyData {}
