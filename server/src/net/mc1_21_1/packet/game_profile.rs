use packetize::{Decode, Encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{player_name::PlayerName, var_string::VarString};

#[derive(Serialize, Deserialize, Debug, Encode, Decode, Clone)]
pub struct Property {
    pub name: Box<VarString<32767>>,
    pub value: Box<VarString<32767>>,
    pub signature: Option<Box<VarString<32767>>>,
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
            name: VarString::from_str("Unknown Player").unwrap().into(),
            properties: Vec::new(),
            profile_actions: None,
        }
    }
}
