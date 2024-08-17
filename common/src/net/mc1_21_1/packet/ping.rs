use packetize::{Decode, Encode};

#[derive(Debug, Encode, Decode)]
pub struct PingRequestC2s {
    pub payload: i64,
}


#[derive(Debug, Encode, Decode)]
pub struct PingResponseS2c {
    pub payload: i64,
}
