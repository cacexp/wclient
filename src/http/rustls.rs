/// Helper functions to configure [rustls](https://crates.io/crates/rustls)
use std::sync::Arc;
use rustls;
use std::path::Path;
use std::fs::File;
use crate::config::{HttpConfig, HttpsVerify, HttpsCert};
use std::io::BufReader;
use rustls::RootCertStore;
use std::fs;
use std::io;

/// Internal module to disable server certificate verification
#[cfg(feature = "dangerous_configuration")]
mod danger {

    pub struct NoCertificateVerification {}

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}

#[cfg(feature = "dangerous_configuration")]
fn apply_do_not_verify(cfg: &mut rustls::ClientConfig) {
     cfg.dangerous()
        .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
}

#[cfg(not(feature = "dangerous_configuration"))]
pub(crate) fn apply_do_not_verify(_: &mut rustls::ClientConfig) {
    panic!("This build does not support HttpsVerify::False");
}

fn load_private_key(filename: &str) -> Result<rustls::PrivateKey, io::Error> {
    let keyfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(keyfile);

    loop {
        let read = rustls_pemfile::read_one(&mut reader);
        if read.is_err() {
            break;
        };

        match read.unwrap() {
            Some(rustls_pemfile::Item::RSAKey(key)) => return Ok(rustls::PrivateKey(key)),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return Ok(rustls::PrivateKey(key)),
            None => break,
            _ => {}
        }
    }

    return Err(io::Error::new(io::ErrorKind::InvalidData, 
        format!("File {}, does not contains a valid key", filename)));
}

pub(crate) fn load_certificates(path: &Path) -> Result<Vec<Vec<u8>>, io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    return rustls_pemfile::certs(&mut reader);
}

pub(crate) fn load_ca_certificates(root_store: &mut RootCertStore, verify: &HttpsVerify) -> Result<(), io::Error> {

    match verify {
        HttpsVerify::False => {
            // Do nothing
        },
        HttpsVerify::True => {
            let platform_certs = rustls_native_certs::load_native_certs()
            .or_else(|_|  {
                Err(io::Error::new(io::ErrorKind::InvalidData, "Cannot load platform CA certs"))
            })?;

            for cert in platform_certs {
                root_store
                    .add(&rustls::Certificate(cert.0))
                    .or_else(|e| {Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))})?;
            }
        }
        HttpsVerify::Path(path) => {
            let file_path = Path::new(path);
            let metadata = fs::metadata(file_path)?;
            if metadata.is_dir() {
              for entry in fs::read_dir(file_path)? {
                  let entry_result = entry?;
                  if entry_result.metadata()?.is_file() {
                    let certificates = load_certificates(entry_result.path().as_path())?;
                    root_store.add_parsable_certificates(&certificates);
                  }
              }
            } else {
                let certificates = load_certificates(file_path)?;
                root_store.add_parsable_certificates(&certificates);
            }
        }
    }
    return Ok(())
}

fn get_client_cert(config: &HttpsCert) -> Result<Option<(Vec<rustls::Certificate>, rustls::PrivateKey)>, io::Error> {
    match config {
        HttpsCert::CertKey { ref cert, ref key } => {
            let auth_cert: Vec<rustls::Certificate> = load_certificates(Path::new(cert))?
                .iter()
                .map(|v| {rustls::Certificate(v.clone())} )
                .collect();
                        
            let auth_key = load_private_key(key.as_str())?;
            
            return Ok(Some((auth_cert, auth_key)));
        },       
        HttpsCert::None => {
            return Ok(None);
        }
    };
}

pub(crate) fn make_rustls_config(config: &HttpConfig) -> Result<Arc<rustls::ClientConfig>, io::Error> {

    // default suites
    let suites = rustls::DEFAULT_CIPHER_SUITES.to_vec();

    // Default versions

    let versions =  rustls::DEFAULT_VERSIONS.to_vec();

    // Root Cert store
    let mut root_store = RootCertStore::empty();

    
    load_ca_certificates(&mut root_store, &config.verify)?;

    let client_cert = get_client_cert(&config.cert)?;

    // Add root CA of client cert to trusted CAs

    if client_cert.is_some() {
        let cert = &(client_cert.as_ref().unwrap().0);
        if cert.len() > 1 {
            root_store.add(cert.get(cert.len() -1).as_ref().unwrap()).or_else(|e| {Err(io::Error::new(io::ErrorKind::InvalidData, format!("{}", e)))})?;
        }
    }

    // Build Config
    
    let config_builder = rustls::ClientConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .or_else(|_|  {Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid TLS version"))})?
        .with_root_certificates(root_store);


    let mut rustls_config = if client_cert.is_some() {
        let (cert, key) = client_cert.unwrap();
        config_builder.with_single_cert(cert, key)
            .or_else(|_|  {Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid client cert/key"))})?
    } else {
        config_builder.with_no_client_auth()
    };
    

    if config.verify == HttpsVerify::False {
        apply_do_not_verify(&mut rustls_config);
    }
    
    Ok(Arc::new(rustls_config))
}