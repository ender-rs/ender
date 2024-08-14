use std::{
    io::{BufReader, Read, Write},
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
};

use httparse::{Response, EMPTY_HEADER};
use mio::{event::Event, net::TcpStream, Interest};
use nonmax::NonMaxUsize;
use rustls::{
    crypto::{aws_lc_rs, CryptoProvider},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    RootCertStore,
};

use crate::net::mc1_21_1::packet::{authentication::GameProfile, login_success::LoginSuccessS2c};

use super::login_server::{ConnectionId, LoginServer};

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
        let addr = dns_lookup::lookup_host("sessionserver.mojang.com")
            .map_err(|_| ())?
            .first()
            .map(|v| *v)
            .ok_or(())?;
        let server_name =
            ServerName::try_from(String::from_str("sessionserver.mojang.com").unwrap()).unwrap();
        let stream = mio::net::TcpStream::connect(SocketAddr::new(addr, 443)).map_err(|_| ())?;
        let tls =
            rustls::ClientConnection::new(self.tls_config.clone(), server_name).map_err(|_| ())?;
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
            &self.poll.registry(),
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
                let uuid = connection.uuid;
                let player_name = connection.player_name.clone();
                println!("LoginSuccess");

                let game_profile: GameProfile =
                    simd_json::serde::from_reader(buf.as_slice()).map_err(|_| ())?;
                println!(
                    "{:?}",
                    LoginSuccessS2c {
                        uuid,
                        username: player_name.clone(),
                        properties: game_profile.properties.clone(),
                        strict_error_handling: false
                    }
                );
                self.send_packet(
                    connection_id,
                    &LoginSuccessS2c {
                        uuid,
                        username: player_name,
                        properties: game_profile.properties,
                        strict_error_handling: false,
                    }
                    .into(),
                )?;
                self.flush_write_buffer(connection_id);
            }
        };
        Ok(())
    }

    pub fn close_http_client(&mut self, client_id: usize) -> HttpClient {
        let mut client = self.http_clients.remove(client_id);
        mio::Registry::deregister(&self.poll.registry(), &mut client.stream).unwrap();
        let _result = client.stream.shutdown(std::net::Shutdown::Both);
        let connection = self.connections.get_mut(client.connection_id);
        if let Some(connection) = connection {
            connection.related_http_client_id = None;
        }
        client
    }
}

pub fn make_tls_config() -> Arc<rustls::ClientConfig> {
    let mut root_store = RootCertStore::empty();

    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder_with_provider(
        CryptoProvider {
            cipher_suites: aws_lc_rs::DEFAULT_CIPHER_SUITES.to_vec(),
            ..aws_lc_rs::default_provider()
        }
        .into(),
    )
    .with_protocol_versions(rustls::DEFAULT_VERSIONS)
    .expect("inconsistent cipher-suite/versions selected")
    .with_root_certificates(root_store);

    println!("generating certificate...");
    let (certs, key) = generate_certifacte();
    println!("certificate generated successfully");

    let config = config
        .with_client_auth_cert(certs, key)
        .expect("invalid client auth certs/key");

    Arc::new(config)
}

fn generate_certifacte() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    use rand::rngs::OsRng;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::RsaPrivateKey;

    use rcgen::{date_time_ymd, CertificateParams, DistinguishedName};

    let mut params: CertificateParams = Default::default();
    params.not_before = date_time_ymd(2021, 5, 19);
    params.not_after = date_time_ymd(4096, 1, 1);
    params.distinguished_name = DistinguishedName::new();

    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let private_key_der = private_key.to_pkcs8_der().unwrap();
    let key_pair = rcgen::KeyPair::try_from(private_key_der.as_bytes()).unwrap();

    let cert = params.self_signed(&key_pair).unwrap();
    let pem_serialized = cert.pem();
    let pem = pem::parse(&pem_serialized).unwrap();
    let der_serialized = pem.contents();

    (
        load_certs(der_serialized),
        load_private_key(key_pair.serialize_pem().as_bytes()),
    )
}

fn load_certs(der_encoded_certs: &[u8]) -> Vec<CertificateDer<'static>> {
    let mut reader = BufReader::new(der_encoded_certs);
    rustls_pemfile::certs(&mut reader)
        .map(|result| result.unwrap())
        .collect()
}

fn load_private_key(der_encoded_key: &[u8]) -> PrivateKeyDer<'static> {
    let mut reader = BufReader::new(der_encoded_key);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return key.into(),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return key.into(),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return key.into(),
            None => break,
            _ => {}
        }
    }

    panic!("no keys found in given data (encrypted keys not supported)",);
}
