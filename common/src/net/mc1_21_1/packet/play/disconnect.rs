use packetize::{Decode, Encode};

use crate::var_array::VarStringCap32767;

#[derive(Debug, Encode, Decode)]
pub struct Disconnect(VarStringCap32767);

#[derive(Debug, Encode, Decode)]
pub struct LoginDisconnectS2c(Disconnect);
