use packetize::{Decode, Encode};
use uuid::Uuid;

use crate::{player_name::PlayerName, var_string::VarString};

#[derive(Debug, Encode, Decode)]
pub struct LoginSuccessS2c {
    pub uuid: Uuid,
    pub username: PlayerName,
    pub properties: Vec<Property>,
}

#[derive(Debug, Encode, Decode)]
pub struct Property {
    pub name: Box<VarString<32767>>,
    pub value: Box<VarString<32767>>,
    pub signature: Option<Box<VarString<32767>>>,
}
