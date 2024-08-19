use std::str::FromStr;

use arrayvec::ArrayString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::player_name::PlayerName;

use super::mc1_21_1::packet::login::Property;

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
            name: ArrayString::from_str("Unknown Player").unwrap().into(),
            properties: Vec::new(),
            profile_actions: None,
        }
    }
}
