use std::ops::DerefMut;

use packetize::{Decode, Encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    array_capacitor::{VarStringCap, VarStringCap32767},
    player_name::PlayerName,
};

#[derive(Serialize, Deserialize, Debug, Encode, Decode, Clone)]
pub struct Property {
    pub name: VarStringCap32767,
    pub value: VarStringCap32767,
    pub signature: Option<VarStringCap32767>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ProfileAction {
    #[serde(rename = "FORCED_NAME_CHANGE")]
    ForcedNameChange,
    #[serde(rename = "USING_BANNED_SKIN")]
    UsingBannedSkin,
}

#[derive(Deserialize, Debug, Clone)]
pub struct GameProfile {
    pub id: Uuid,
    pub name: PlayerName,
    pub properties: Vec<Property>,
    #[serde(rename = "profileActions")]
    pub profile_actions: Option<Vec<ProfileAction>>,
}

impl Default for GameProfile {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            name: VarStringCap("Unknown Player".to_string().into()).into(),
            properties: Vec::new(),
            profile_actions: None,
        }
    }
}
