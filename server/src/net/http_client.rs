use std::{
    io::{Read, Write},
    net::SocketAddr,
};

use httparse::{Response, EMPTY_HEADER};
use mio::{event::Event, net::TcpStream, Interest, Token};
use nonmax::NonMaxUsize;

use crate::net::mc1_21_1::packet::{game_profile::GameProfile, login_success::LoginSuccessS2c};

use super::{connection::ConnectionId, login_server::LoginServer};

pub struct HttpClient {
    pub event: HttpRequestEvent,
    pub stream: TcpStream,
    pub connection_id: ConnectionId,
    pub tls: rustls::ClientConnection,
}

pub enum HttpRequestEvent {
    Auth {
        player_name: String,
        server_id: String,
    },
}

impl LoginServer {
    pub const HTTP_CLIENT_ID_OFFSET: usize = Self::CONNECTIONS_CAPACITY;
    pub fn on_http_client_event(
        &mut self,
        client_id: usize,
        selection_event: &Event,
    ) -> Result<(), ()> {
        if selection_event.is_writable() {
            let client = unsafe { self.http_clients.get_unchecked_mut(client_id) };
            client.tls.write_tls(&mut client.stream).map_err(|_| ())?;
        } else {
            self.on_http_client_read(client_id)?;
        }
        Ok(())
    }

    pub fn connect_http_request_client(
        &mut self,
        connection_id: ConnectionId,
        event: HttpRequestEvent,
    ) -> Result<(), ()> {
        let stream =
            mio::net::TcpStream::connect(SocketAddr::new(self.info.session_server_ip, 443))
                .map_err(|_| ())?;
        let tls = rustls::ClientConnection::new(
            self.info.tls_config.clone(),
            self.info.session_server_name.clone(),
        )
        .map_err(|_| ())?;
        let client = HttpClient {
            stream,
            connection_id,
            event,
            tls,
        };
        let client_id = self.http_clients.insert(client);
        let connection = self.get_connection_mut(connection_id);
        connection.related_http_client_id = Some(unsafe { NonMaxUsize::new_unchecked(client_id) });
        let client = unsafe { self.http_clients.get_unchecked_mut(client_id) };
        mio::Registry::register(
            &self.state.poll.registry(),
            &mut client.stream,
            mio::Token(client_id + Self::HTTP_CLIENT_ID_OFFSET),
            Interest::READABLE.add(Interest::WRITABLE),
        )
        .unwrap();
        self.on_http_client_connect(client_id)?;
        Ok(())
    }

    fn on_http_client_connect(&mut self, client_id: usize) -> Result<(), ()> {
        let client = unsafe { self.http_clients.get_unchecked_mut(client_id) };
        match &client.event {
            HttpRequestEvent::Auth {
                player_name,
                server_id,
            } => {
                let mut payload = String::new();
                ufmt::uwrite!(payload, "GET /session/minecraft/hasJoined?username={}&serverId={} HTTP/1.1\r\nHost: sessionserver.mojang.com\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n", player_name, server_id)
                    .unwrap();

                client
                    .tls
                    .writer()
                    .write_all(payload.as_bytes())
                    .map_err(|_| ())?;
            }
        }
        Ok(())
    }

    fn on_http_client_read(&mut self, client_id: usize) -> Result<(), ()> {
        let client = unsafe { self.http_clients.get_unchecked_mut(client_id) };
        let read_length = client.tls.read_tls(&mut client.stream).map_err(|_| ())?;
        if read_length == 0 {
            Err(())?
        }
        let io_state = client.tls.process_new_packets().map_err(|_| ())?;
        if io_state.tls_bytes_to_write() != 0 {
            client.tls.write_tls(&mut client.stream).map_err(|_| ())?;
        }
        self.state
            .poll
            .registry()
            .reregister(
                &mut client.stream,
                Token(client_id + Self::HTTP_CLIENT_ID_OFFSET),
                Interest::WRITABLE.add(Interest::READABLE),
            )
            .unwrap();
        let plaintext_read_length = io_state.plaintext_bytes_to_read();
        if plaintext_read_length != 0 {
            let mut buffer = vec![0u8; io_state.plaintext_bytes_to_read()];
            client
                .tls
                .reader()
                .read_exact(&mut buffer)
                .map_err(|_| ())?;
            let mut headers = [EMPTY_HEADER; 16];
            let response = Response::new(&mut headers).parse(&buffer).map_err(|_| ())?;
            if response.is_complete() {
                buffer.drain(0..response.unwrap());
                self.on_read_http_response(client_id, buffer)?;
                self.close_http_client(client_id);
            } else {
                Err(())?
            }
        }
        Ok(())
    }

    fn on_read_http_response(&mut self, client_id: usize, buf: Vec<u8>) -> Result<(), ()> {
        let client = unsafe { self.http_clients.get_unchecked_mut(client_id) };

        let connection_id = client.connection_id;
        match &client.event {
            HttpRequestEvent::Auth {
                player_name,
                server_id,
            } => {
                let connection =
                    unsafe { self.connections.get_unchecked_mut(client.connection_id) };
                let uuid = connection.id;
                let player_name = connection.name.clone();
                println!("LoginSuccess");

                let game_profile: GameProfile =
                    simd_json::serde::from_reader(buf.as_slice()).map_err(|_| ())?;
                self.send_packet(
                    connection_id,
                    &LoginSuccessS2c {
                        uuid,
                        username: player_name,
                        properties: Vec::new(),
                        strict_error_handling: false,
                    }
                    .into(),
                )?;
                self.flush_write_buffer(connection_id);
                self.send_player_to_game_server(connection_id);
            }
        };
        Ok(())
    }

    pub fn close_http_client(&mut self, client_id: usize) -> Option<HttpClient> {
        if let Some(mut client) = self.http_clients.try_remove(client_id) {
            mio::Registry::deregister(&self.state.poll.registry(), &mut client.stream).unwrap();
            let connection = self.connections.get_mut(client.connection_id);
            if let Some(connection) = connection {
                connection.related_http_client_id = None;
            }
            Some(client)
        } else {
            None
        }
    }
}
