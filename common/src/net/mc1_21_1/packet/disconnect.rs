use packetize::{Decode, Encode};

use crate::var_string::VarString;

#[derive(Debug, Encode, Decode)]
pub struct Disconnect(Box<VarString<32767>>);

#[derive(Debug, Encode, Decode)]
pub struct LoginDisconnectS2c(Disconnect);
