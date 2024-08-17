use std::net::SocketAddr;

use common::net::connection::Connection;
use mio::net::TcpStream;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let addr: SocketAddr = args[1].parse().unwrap();
    let stream = TcpStream::connect(addr).unwrap();
    let connection = Connection::new(stream);
}
