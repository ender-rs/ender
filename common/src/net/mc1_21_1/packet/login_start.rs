use packetize::{Decode, Encode};
use uuid::Uuid;

use crate::player_name::PlayerName;

#[derive(Debug, Encode, Decode)]
pub struct LoginStartC2s {
    pub name: PlayerName,
    pub uuid: Uuid,
}
