use packetize::{Decode, Encode};
use uuid::Uuid;

use crate::player_name::PlayerName;

use super::authentication::Property;

#[derive(Debug, Encode, Decode)]
pub struct LoginSuccessS2c {
    pub uuid: Uuid,
    pub username: PlayerName,
    pub properties: Vec<Property>,
    pub strict_error_handling: bool,
}
