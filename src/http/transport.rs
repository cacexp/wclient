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

use crate::config::HttpConfig;
use std::io::{Write, Read, Error, ErrorKind};
use std::net::{TcpStream, Shutdown};
use log::*;

/// Base trait for [ClientConnection](crate::http::ClientConnection) , it will be implemented for HTTP and HTTPS
pub (crate) trait Transport {
    /// Target host
    fn host(&self) -> &str;
    /// Target port
    fn port(&self) -> u16;
    /// Checks whether the transport is open
    fn is_open(&self) -> bool;
    /// Gets a [Write](std::io::Write) to write a message, returns [Error](std::io::Error) on failure
    fn writer(&mut self) -> Result<Box<dyn Write>, Error>;
    /// Gets a [Read](std::io::Read) to read a message, returns [Error](std::io::Error) on failure
    fn reader(&mut self) -> Result<Box<dyn Read>, Error>;
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

    fn writer(&mut self) -> Result<Box<dyn Write>, Error> {
        Ok(Box::new(self.stream()?))
    }

    fn reader(&mut self) -> Result<Box<dyn Read>, Error> {
        Ok(Box::new(self.stream()?))
    }

    fn close(&mut self) {
        if ! self.open {
            return;
        }

        let _result = self.socket.shutdown(Shutdown::Both);
        self.open = false;
    }
}