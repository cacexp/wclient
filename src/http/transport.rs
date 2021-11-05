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

use std::io::IoSlice;
use rustls::OwnedTrustAnchor;
use rustls::RootCertStore;
use webpki_roots;
use std::sync::Arc;
use crate::config::HttpConfig;
use std::io::{Write, Read, Error, ErrorKind};
use std::net::{TcpStream, Shutdown};
use log::*;


/// Base trait for [ClientConnection](crate::http::ClientConnection) , it will be implemented for HTTP and HTTPS
pub (crate) trait Transport : Write + Read {
    /// Target host
    fn host(&self) -> &str;
    /// Target port
    fn port(&self) -> u16;
    /// Checks whether the transport is open
    fn is_open(&self) -> bool;
    /// Closes the transport
    fn close(&mut self);
}

pub (crate) struct TcpTransport {
    host: String,
    port: u16,
    open: bool,
    socket: TcpStream
}

impl TcpTransport {
    pub (crate) fn open(host: &str, port: u16, _config: &HttpConfig) -> Result<Self, Error> {
        info!("Opening Connection with server {:?}", host);

        let socket = TcpStream::connect((host, port))?;

        socket.set_nodelay(true)?;

        Ok(TcpTransport {
            host: String::from(host),
            port,
            open: true,
            socket,
        })
    }

    fn stream(&mut self) -> Result<TcpStream, Error> {
        if self.open {
            if let Ok(clone) = self.socket.try_clone() {
                Ok(clone)

            } else {
                Err(Error::new(ErrorKind::NotConnected, "Cannot get stream"))
            }
        } else {
            Err(Error::new(ErrorKind::NotConnected, "Not connected"))
        }
    }
}

impl Transport for TcpTransport {

    fn host(&self) -> &str {
        self.host.as_ref()
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn is_open(&self) -> bool {
        self.open
    }
        

    fn close(&mut self) {
        if ! self.open {
            return;
        }

        let _result = self.socket.shutdown(Shutdown::Both);
        self.open = false;
    }
}

impl Read for TcpTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.socket.read(buf)
    }
}

impl Write for TcpTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.socket.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
    }
}


pub (crate) struct TlsTransport {
    open: bool,
    tcp: TcpTransport,
    tls: rustls::ClientConnection
}

impl TlsTransport {
    pub (crate) fn open(host: &str, port: u16, config: &HttpConfig) -> Result<Self, Error> {
        let transport = TcpTransport::open(host, port, config)?;
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS
                .0
                .iter()
                .map(|ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                }),
        );
        let rustls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let dns_name = rustls::ServerName::try_from(host);

        if dns_name.is_err() {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid DNS name"));
        }
        let tls_conn = rustls::ClientConnection::new(Arc::new(rustls_config), dns_name.unwrap());

        if tls_conn.is_err() {
            return Err(Error::new(ErrorKind::InvalidData, "Cannot create TLS"));
        }
        Ok(TlsTransport {
            open: true,
            tcp: transport,
            tls: tls_conn.unwrap()
        })
    }

    /// If we're handshaking, complete all the IO for that.
    /// If we have data to write, write it all.
    fn complete_prior_io(&mut self) -> std::io::Result<()> {
        // code extracted from rustls::Stream

        if self.tls.is_handshaking() {
            self.tls.complete_io(&mut self.tcp)?;
        }

        if self.tls.wants_write() {
            self.tls.complete_io(&mut self.tcp)?;
        }

        Ok(())
    }

}

impl Transport for TlsTransport {
    fn host(&self) -> &str {
        self.tcp.host()
    }

    fn port(&self) -> u16 {
        self.tcp.port()
    }

    fn is_open(&self) -> bool {
        self.open && self.tcp.is_open()
    }

    fn close(&mut self) {
        self.tcp.close()
    }
}

impl Read for TlsTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // code extracted from rustls::Stream
        self.complete_prior_io()?;
        while self.tls.wants_read() {
            let at_eof = self.tls.complete_io(&mut self.tcp)?.0 == 0;
            if at_eof {
                if let Ok(io_state) = self.tls.process_new_packets() {
                    if at_eof && io_state.plaintext_bytes_to_read() == 0 {
                        return Ok(0);
                    }
                }
                break;
            }
        }

        self.tls.reader().read(buf)
    }
}

impl Write for TlsTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Code extracted from rustls::Stream
        self.complete_prior_io()?;

        let len = self.tls.writer().write(buf)?;
        let _ = self.tls.complete_io(&mut self.tcp);

        Ok(len)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        // Code extracted from rustls::Stream
        self.complete_prior_io()?;

        let len = self.tls.writer().write_vectored(bufs)?;
        
        let _ = self.tls.complete_io(&mut self.tcp);

        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Code extracted from rustls::Stream

        self.complete_prior_io()?;

        self.tls.writer().flush()?;
        if self.tls.wants_write() {
            self.tls.complete_io(&mut self.tcp)?;
        }
        Ok(())
    }
}

