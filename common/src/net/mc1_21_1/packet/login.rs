use packetize::{Decode, Encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{array_capacitor::VarStringCap32767, player_name::PlayerName};

#[derive(Debug, Encode, Decode)]
pub struct LoginStartC2s {
    pub name: PlayerName,
    pub uuid: Uuid,
}

#[derive(Debug, Encode, Decode)]
pub struct LoginSuccessS2c {
    pub uuid: Uuid,
    pub username: PlayerName,
    pub properties: Vec<Property>,
    pub strict_error_handling: bool,
}

#[derive(Debug, Encode, Decode)]
pub struct LoginAckC2s;

#[derive(Serialize, Deserialize, Debug, Encode, Decode, Clone)]
pub struct Property {
    pub name: VarStringCap32767,
    pub value: VarStringCap32767,
    pub signature: Option<VarStringCap32767>,
}
