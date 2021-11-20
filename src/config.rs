// Copyright 2021 Juan A. Cáceres (cacexp@gmail.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! HTTP configuration settings
//! 
//! Current configuration settings:
//! * `timeout`: Sets the [Duration](std::time::Duration) for a connect, read or write operation at a TCP socket (**TO DO**)
//! * `verify`: The Root CA certificates to authenticate the server with HTTPS, see [HttpsVerify](crate::config::HttpsVerify)
//! * `cert`: The client certificate to be authenticated against the serve with HTTPS, see [HttpsCert](crate::config::HttpsCert)
//!  

use std::time::Duration;

/// HTTPS Configuration to verify server's certificate
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum HttpsVerify {
    /// Verify using default CA bundle (default value)
    True,
    /// Do not verify server's certificate. **WARNING**: this value is not recommended and it generate a `panic!` 
    /// if feature `dangerous_configuration` is not set
    False,    
    /// Verify server's certificate against local CA in path, this can be a single file or a directory containing CA certificates in 
    /// [PEM format](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail)
    Path(String)
}

/// HTTPS configuration to set Client certificate
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum HttpsCert {
    /// Do not use client certificate (default value)
    None,    
    /// Tuple with paths of files containing certificate and private key
    /// **Note**: If client certificate is not signed by a trusted CA (see [crate::config::HttpsVerify]), 
    /// it must include full certificate chain, including root CA
    CertKey{cert: String, key: String}
}

/// HTTP Configuration
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct HttpConfig {
    /// Connecton, write and read timeout for a TCP socket
    pub timeout: Option<Duration>,
    /// Directory or file path with trusted CA certificates
    pub verify: HttpsVerify,
    /// Client certificate
    pub cert: HttpsCert
}

/// `HttpConfig` helper builder
pub struct HttpConfigBuilder {
    timeout: Option<Duration>,
    verify: HttpsVerify,
    cert: HttpsCert
}

impl HttpConfigBuilder {
    pub fn default() -> HttpConfigBuilder {
        HttpConfigBuilder{
            timeout: None,
            verify: HttpsVerify::True,
            cert: HttpsCert::None
        }
    }

    /// Sets the connection, write and read timeout for a TCP socket
    pub fn timeout(mut self, value: Duration) -> HttpConfigBuilder {
        self.timeout = Some(value);
        self
    }

    /// Sets how to verify HTTPS server certificate
    pub fn verify(mut self, value: HttpsVerify) -> HttpConfigBuilder {
        self.verify = value;
        self
    }

     /// Sets client certificate
     pub fn cert(mut self, value: HttpsCert) -> HttpConfigBuilder {
        self.cert = value;
        self
    }

    /// Builder function ofor HttpConfig
    pub fn build(self) -> HttpConfig {
        HttpConfig{
            timeout: self.timeout,
            verify: self.verify,
            cert: self.cert
        }
    }
}