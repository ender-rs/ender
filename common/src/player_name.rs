use packetize::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::array_capacitor::VarStringCap;

#[derive(
    Debug,
    Encode,
    Decode,
    Serialize,
    Deserialize,
    derive_more::Into,
    derive_more::From,
    Clone,
    derive_more::Deref,
    derive_more::DerefMut,
)]
pub struct PlayerName(pub VarStringCap<16>);

impl PlayerName {
    pub fn new() -> Self {
        Self(VarStringCap(String::new()))
    }
}
