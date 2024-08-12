use packetize::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::var_string::VarString;

#[derive(Debug, Encode, Decode, Serialize, Deserialize, derive_more::Into, derive_more::From)]
pub struct PlayerName(VarString<16>);

impl PlayerName {
    pub fn new() -> Self {
        Self(VarString::new())
    }
}
