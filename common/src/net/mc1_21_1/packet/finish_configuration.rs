use packetize::{Decode, Encode};

#[derive(Encode, Decode, Debug)]
pub struct FinishConfigurationS2c;

#[derive(Encode, Decode, Debug)]
pub struct FinishConfigurationAckC2s;
