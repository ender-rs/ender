use arrayvec::ArrayVec;
use packetize::{Decode, Encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    player_name::PlayerName,
    var_array::{VarStringCap, VarStringCap32767},
    var_int::VarInt,
};

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

#[derive(Debug, Encode, Decode)]
pub struct EncryptionRequestS2c {
    pub server_id: VarStringCap<20>,
    pub public_key: ArrayVec<u8, 162>,
    pub verify_token: ArrayVec<u8, 4>,
    pub should_authenticate: bool,
}

#[derive(Debug, Encode, Decode)]
pub struct EncryptionResponseC2s {
    pub shared_secret: ArrayVec<u8, 128>,
    pub verify_token: ArrayVec<u8, 128>,
}

#[derive(Debug, Encode, Decode)]
pub struct SetCompressionS2c {
    pub threshold: VarInt,
}
