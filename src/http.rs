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

//! HTTP Protocol Implementation
//! 
/// HTTP Transport Implementation
mod transport;

use crate::http::transport::TlsTransport;
use std::result::Result;
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use url::Url;
use crate::*;
use crate::config::HttpConfig;
use crate::http::transport::{Transport, TcpTransport};
use std::io::*;
use log::*;

const HTTP_SCHEMA: &str = "http";
const HTTPS_SCHEMA: &str = "https";
const SET_COOKIE: &str = "set-cookie";
const CONTENT_LENGTH: &str = "Content-Length";
const HTTP_1_1: &str = "HTTP/1.1";
const HTTP_2_0: &str = "HTTP/2.0";


/// HTTP version
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum HttpVersion {Version1_0, Version1_1, Version2_0, Version3_0}


/// Parse an url in as `&str` and generates an [Url](url::Url)
pub(crate) fn parse_url(url: &str) -> Result<Url, Error> {
    let url =  Url::parse(url).or_else(
        |u| Err(Error::new(ErrorKind::InvalidInput, u))
    )?;

    Ok(url)
}

/// HTTP scheme, it can be plain HTTP or secure HTTPS
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub(crate) enum HttpScheme {HTTP, HTTPS}

impl FromStr for HttpScheme {
    type Err = Error;

    fn from_str(s: &str) -> Result<HttpScheme, Error> {
        let lower_case = s.to_ascii_lowercase();
        match lower_case.as_str() {
            HTTP_SCHEMA => Ok(HttpScheme::HTTP),
            HTTPS_SCHEMA => Ok(HttpScheme::HTTPS),
            _ => Err(Error::new(ErrorKind::InvalidInput, "Schema is not HTTP"))
        }
    }
}

/// Represents a server endpoint to which a [ClientConnection] is connected.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub (crate) struct EndPoint {
    /// HTTP Scheme
    pub scheme: HttpScheme,
    /// Target host
    pub host: String,
    /// Target port
    pub port: u16
}

impl EndPoint {
    /// Constructor from [Url](url::Url)
    pub fn from_url(url: &Url) -> Result<EndPoint, Error> {
        let scheme = HttpScheme::from_str(url.scheme())?;
        let default_port: u16 = if scheme == HttpScheme::HTTP { 80 } else { 443 };
        let port = url.port().unwrap_or(default_port);
        let host = String::from(url.host_str().ok_or(
            Error::new(ErrorKind::AddrNotAvailable, "Cannot get host from url"))?);
        Ok(EndPoint { scheme, host, port })
    }
}

// HTTP client connection. It uses a [Transport] to send HTTP [Request](crate::Request) and receive [Response](crate::Response).
/// A `ClientConnection` must be allocated by [ClientConnectionFactory::client_connection]  
pub(crate) struct ClientConnection {
    /// Target endpoint
    end_point : EndPoint,
    /// Proxy endpoint if it is needed to be used
    proxy: Option<EndPoint>,
    /// Connection configuration
    config: HttpConfig,
    /// Allocated transport by [ClientConnectionFactory::make_transport]
    transport: Box<dyn Transport>
}

impl ClientConnection  {

    /// Client Connection constructor
    fn new(end_point: EndPoint,
           proxy: Option<EndPoint>,
           config: HttpConfig,
           transport: Box<dyn Transport>) -> ClientConnection {

        ClientConnection {
            end_point,
            proxy,
            config,
            transport
        }
    }

    /// Sends a [Request](crate::Request) to the target server
    pub(crate) fn send(&mut self, request: &Request) -> Result<Response, Error> {
        if ! self.transport.is_open() {
            return Err(Error::new(ErrorKind::NotConnected, "Connection is not open"));
        }

        let mut buffer = BufWriter::new(Vec::new());

         // TODO implements different HTTP version protocol

        Self::write_http11(&mut buffer, request)?;

        let bytes = buffer.into_inner().unwrap();

        self.transport.write(bytes.as_slice())?;

        self.transport.flush()?;

        if log_enabled!(Level::Debug) {
            let string = String::from_utf8(bytes).unwrap();
            debug!("{}", string);
        }

        return self.receive();
    }

    /// Close the connection
    fn close(&mut self) {
        // TODO make thread-safe 
        if!self.transport.is_open() {       
            self.transport.close();
        }
    }

    fn write_http11(writer: &mut impl Write, request: &Request) -> Result<(), Error> {
        let target_url = request.parsed_url.as_ref().ok_or_else(
            || Error::new(ErrorKind::AddrNotAvailable, "Does not have a valid Http url")
        )?;

        write!(writer, "{} {}",
               request.method,
               &target_url.path())?;

        if !request.params.is_empty() {
            write!(writer, "?")?;
            for (key, value) in &request.params {
                write!(writer, "{}={}", key, value)?;
            }
        }

        write!(writer, " HTTP/1.1\r\n")?;  // println! only writes \n

        if target_url.has_host() {
            let host = target_url.host_str().unwrap_or_else(|| "");
            match target_url.port() {
                None => write!(writer, "Host: {}\r\n", host)?,
                Some(port) => write!(writer, "Host: {:?}:{:?}\r\n", host, port)?
            }
        }

        if request.cookies.len() > 0 {
            write!(writer, "Cookie: ")?;
            let mut first = true;
            for (key, value) in &request.cookies {
                if first {
                    first = false;
                    write!(writer, "{}={}", key, value)?;
                } else {
                    write!(writer, "; {}={}", key, value)?;
                }
            }
            write!(writer, "\r\n")?;
        }


        for (key, value) in &request.headers {
            write!(writer, "{}: {}\r\n", key, value)?;
        }

        if request.has_body() {
            let body = &request.body;
            write!(writer, "Content-Length: {}\r\n\r\n", body.len())?; // Empty line: end of metadata
            writer.write(body)?;
        } else {
            write!(writer, "\r\n")?;  // Empty line: end of metadata
        }

        return Ok(())
    }

    /// Receives a [Response](crate::Response) from server
    pub fn receive(&mut self) -> Result<Response, Error> {

        debug!("Receiving Response");
        
        let mut line = String::new();

        let mut buffer = BufReader::new(self.transport.as_mut());
        buffer.read_line(&mut line)?;

        if line.len() == 0 {
            error!("HTTPConnection::receive Connection is closed");
            // Connection Closed
            return Err(Error::new(ErrorKind::BrokenPipe, "Connection closed"));
        }

        debug!("{}", line);

        let (_, status) = Self::parse_http11_response_status(&line)?;

        let mut response = Response::new(status);

        loop {
            line.clear();
            match buffer.read_line(&mut line) {
                Ok(n) => {
                    debug!("{}", line);

                    if n == 0 {
                        return Ok(response);  // end of file
                    }
                    let trimmed = line.trim();

                    if trimmed.is_empty() { // end of headers
                        break;
                    }

                    let (key, value) = Self::parse_http11_header(trimmed)?;
                    let key_lc = key.to_lowercase();
                    if key_lc == SET_COOKIE {
                        let cookie = Cookie::from_str(&value)?;
                        response.cookies.push(cookie);
                    }

                    response.headers.insert(key, value);
                }
                Err(e) => return Err(e)
            }
        }

        // Reading body
        if response.headers.contains_key(CONTENT_LENGTH) { //there is content-length header

            debug!("Reading body");

            let length = usize::from_str(response.headers.get(CONTENT_LENGTH).unwrap())
                .or_else(|_| Err(Error::new(ErrorKind::InvalidData,
                                            "Content-Length value is not a number")))?;

            debug!("Reading body of {} bytes", length);

            let mut data: Vec<u8> = vec![0;length];

            buffer.read_exact(data.as_mut_slice())?;

            response.body = data;

            debug!("Body length is {} bytes", response.body.len());

        } else { // no content-length header, read to the end of the file
            let mut data: Vec<u8> = Vec::new();

            match buffer.read_to_end(&mut data) {
                Ok(n) => {
                    if n == 0 {
                        response.body = data;
                    }
                },
                Err(e) => return Err(e)
            }
        }

        return Ok(response);
    }

    fn parse_http11_header(line: &str) -> Result<(String, String), Error> {
        if let Some(index) = line.find(':') {
            let key = line[0..index].to_string();

            let value = String::from(line[index+1..].trim());

            return Ok((key, value))

        } else {
            Err(Error::new(ErrorKind::InvalidData, format!("Malformed HTTP header: {}", line)))
        }
    }
    fn parse_http11_response_status(line: &str) -> Result<(HttpVersion, HttpStatusCode), Error> {
        let mut iter = line.split_whitespace();

        return if let Some(version_str) = iter.next() {
            let version = Self::parse_http_version(version_str)?;
            if let Some(status_str) = iter.next() {
                let status = Self::parse_http_status(status_str)?;
                Ok((version, status))
            } else {
                Err(Error::new(ErrorKind::InvalidData, "Error parsing HTTP status"))
            }
        } else {
            Err(Error::new(ErrorKind::InvalidData, "Error parsing HTTP version"))
        }
    }

    fn parse_http_version(version: &str) -> Result<HttpVersion, Error> {
        match version {
            HTTP_1_1 => Ok(HttpVersion::Version1_1),
            HTTP_2_0 => Ok(HttpVersion::Version2_0),
            _ => Err(Error::new(ErrorKind::InvalidData, format!("Not supported HTTP version {}", version)))
        }
    }

    fn parse_http_status(status: &str) -> Result<u16, Error> {
        match status.parse::<u16>() {
            Ok(value) => Ok(value),
            Err(_) => Err(Error::new(ErrorKind::InvalidData,
                                     format!("Unknown HTTP status code {}", status)))
        }
    }
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        if self.transport.is_open() { // forgot to close the connection
            self.close()
        }
    }
}


/// Factory for [ClientConnection]
/// 
/// TODO: To make connection pooling and thread-safe
pub(crate) struct ClientConnectionFactory {
}

impl ClientConnectionFactory {

    /// Allocates the [Tranport](crate::http::transport::Transport) based on the endpont [HttpScheme](crate::http::HttpScheme)
    fn make_transport(end_point: &EndPoint,
                      config: &HttpConfig) -> Result<Box<dyn Transport>, Error> {
        if end_point.scheme ==  HttpScheme::HTTP {
            Ok(Box::new(TcpTransport::open(&end_point.host, end_point.port, config)?))
        } else {
            Ok(Box::new(TlsTransport::open(&end_point.host, end_point.port, config)?))
        }
    }

    /// Creates a client connection based on Http version and schema (Http or https).
    /// 
    /// Returns a shareable refcount pointer `Arc<ClientConnection>` to be prepared to reuse
    /// connections with HTTP 1.1 and later
    pub(crate) fn client_connection(url: &Url, 
                                    config: &HttpConfig) -> Result<Box<ClientConnection>, Error>
    {
        // TODO: get proxy from config
        let end_point = EndPoint::from_url(url)?;

        let transport = Self::make_transport(&end_point, config)?;

        Ok(Box::new(ClientConnection::new(end_point, None, config.clone(),transport)))
    }

}
