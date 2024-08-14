use packetize::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::var_string::VarString;

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
)]
pub struct Identifier(VarString<32767>);
