use packetize::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::{net::server::Server, var_string::VarString};

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
    pub name: String,
    pub properties: Vec<Property>,
    #[serde(rename = "profileActions")]
    pub profile_actions: Option<Vec<ProfileAction>>,
}

pub fn authenticate(
    username: &str,
    server_hash: &str,
    ip: &SocketAddr,
    server: &mut Server,
) -> Result<GameProfile, ()> {
    let address = format!("https://sessionserver.mojang.com/session/minecraft/hasJoined?username={username}&serverId={server_hash}&ip={ip}");
    // let response = server.reqwest_client.get(address).send().unwrap();

    // match response.status() {
    //     StatusCode::OK => {}
    //     StatusCode::NO_CONTENT => Err("no content").unwrap(),
    //     _ => Err("other").unwrap(),
    // }
    // let profile: GameProfile = response.json().unwrap();
    //Ok(profile)
    todo!()
}
