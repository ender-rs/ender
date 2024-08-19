use derive_more::derive::Display;
use packetize::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::array_capacitor::VarStringCap;

#[derive(
    Debug,
    derive_more::DerefMut,
    derive_more::Deref,
    Serialize,
    Deserialize,
    Clone,
    derive_more::Into,
    derive_more::From,
    Encode,
    Decode,
    Display,
)]
pub struct Identifier(VarStringCap<32767>);

impl From<&'static str> for Identifier {
    fn from(value: &'static str) -> Self {
        Identifier(VarStringCap(value.to_string()))
    }
}
