/// Helper functions to configure [rustls](https://crates.io/crates/rustls)
use std::sync::Arc;
use rustls;
use std::path::Path;
use std::fs::File;
use crate::config::{HttpConfig, HttpsVerify};
use std::io::BufReader;
use rustls::RootCertStore;
use std::fs;
use std::io::Error;

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


pub(crate) fn load_certificates(path: &Path) -> Result<Vec<Vec<u8>>, Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    return rustls_pemfile::certs(&mut reader);
}

pub(crate) fn load_ca_certificates(root_store: &mut RootCertStore, verify: &HttpsVerify) -> Result<(), Error> {

    match verify {
        HttpsVerify::False => {
            // Do nothing
        },
        HttpsVerify::True => {
            for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
                root_store
                    .add(&rustls::Certificate(cert.0))
                    .unwrap();
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

pub(crate) fn make_rustls_config(config: &HttpConfig) -> Result<Arc<rustls::ClientConfig>, Error> {

    // default suites
    let suites = rustls::DEFAULT_CIPHER_SUITES.to_vec();

    // Default versions

    let versions =  rustls::DEFAULT_VERSIONS.to_vec();

    // Root Cert store
    let mut root_store = RootCertStore::empty();

    
    load_ca_certificates(&mut root_store, &config.verify)?;

    let mut rustls_config = rustls::ClientConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suite/versions selected")
        .with_root_certificates(root_store)
        .with_no_client_auth();
     
    if config.verify == HttpsVerify::False {
        apply_do_not_verify(&mut rustls_config);
    }
    
    Ok(Arc::new(rustls_config))
}