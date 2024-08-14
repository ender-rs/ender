use std::io::BufReader;
use std::sync::Arc;

use rustls::crypto::{aws_lc_rs as provider, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;

pub enum HttpRequestEvent {
    Auth {
        player_name: String,
        server_id: String,
    },
}

pub fn make_tls_config() -> Arc<rustls::ClientConfig> {
    let mut root_store = RootCertStore::empty();

    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder_with_provider(
        CryptoProvider {
            cipher_suites: provider::DEFAULT_CIPHER_SUITES.to_vec(),
            ..provider::default_provider()
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

    //#[cfg(debug_assertions)]
    //{
    //    let hash = ring::digest::digest(&ring::digest::SHA512, der_serialized);
    //    let hash_hex = hash.as_ref().iter().fold(String::new(), |mut output, b| {
    //        let _ = write!(output, "{b:02x}");
    //        output
    //    });
    //    println!("sha-512 fingerprint: {hash_hex}");
    //    println!("{pem_serialized}");
    //    println!("der: {:?}", key_pair.serialize_der());
    //}

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
