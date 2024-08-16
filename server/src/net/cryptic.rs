use std::{io::BufReader, net::IpAddr, str::FromStr, sync::Arc};

use aes::cipher::{
    generic_array::{self, GenericArray},
    BlockDecryptMut, BlockEncryptMut, BlockSizeUser,
};
use cfb8::{Decryptor, Encryptor};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use rustls::{
    crypto::{aws_lc_rs, CryptoProvider},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    RootCertStore,
};

pub struct CrypticState {
    pub public_key_der: Box<[u8]>,
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
    pub session_server_ip: IpAddr,
    pub session_server_name: ServerName<'static>,
    pub tls_config: Arc<rustls::ClientConfig>,
}

impl CrypticState {
    pub fn new() -> Self {
        let tls_config = make_tls_config();
        let mut rng = rand::thread_rng();

        let private_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        println!("keys generated");

        let public_key_der = rsa_der::public_key_to_der(
            &private_key.n().to_bytes_be(),
            &private_key.e().to_bytes_be(),
        )
        .into_boxed_slice();

        let session_server_ip = dns_lookup::lookup_host("sessionserver.mojang.com")
            .map_err(|_| ())
            .unwrap()
            .first()
            .map(|v| *v)
            .ok_or(())
            .unwrap();
        let session_server_name =
            ServerName::try_from(String::from_str("sessionserver.mojang.com").unwrap()).unwrap();
        Self {
            public_key_der,
            public_key,
            private_key,
            session_server_ip,
            session_server_name,
            tls_config,
        }
    }
}

pub fn encrypt(buf: &mut [u8], cipher: &mut cfb8::Encryptor<aes::Aes128>) {
    for chunk in buf.chunks_mut(Encryptor::<aes::Aes128>::block_size()) {
        let gen_arr = generic_array::GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block_mut(gen_arr);
    }
}

pub fn decrypt(cipher: &mut cfb8::Decryptor<aes::Aes128>, buf: &mut [u8]) {
    for chunk in buf.chunks_mut(Decryptor::<aes::Aes128>::block_size()) {
        let gen_arr = GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block_mut(gen_arr);
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
