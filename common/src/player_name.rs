use arrayvec::ArrayString;
use packetize::{Decode, Encode};
use serde::{Deserialize, Serialize};

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
pub struct PlayerName(pub ArrayString<16>);

impl PlayerName {
    pub fn new() -> Self {
        Self(ArrayString::new())
    }
}
