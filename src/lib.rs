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

//! # Simple Web Client for Rust
//! `wclient` is a lightweigh HTTP web client inspired on [Python Requests](https://docs.python-requests.org/en/latest/).
//! 
//! It allows to send HTTP requests and receive the responses.
//! 
//! **Note**: This is a MVP implementation
//! 
//! # Features
//! * HTTP 1.1 Request and Response over plain TCP/IP
//! * HTTP 1.1 Single Body
//! * HTTPS (v1.1) with default site certificate verification (only with host CA certificates)
//! # Future Features
//! * HTTPS client certification authentication
//! * HTTPS custom site certificate validation
//! * Multipart
//! * HTTP Session with Cookie Jar
//! * HTTP Connection pooling
//!  
//! # User Guide
//! 
//! To create a `Request`, it is needed a [RequestBuilder](crate::RequestBuilder). 
//! 
//! The `RequestBuilder` has constructor functions for each HTTP method that requires the target `url` string: [connect](crate::RequestBuilder::connect),
//! [delete](crate::RequestBuilder::delete), [get](crate::RequestBuilder::get), [head](crate::RequestBuilder::head), [options](crate::RequestBuilder::options),
//! [patch](crate::RequestBuilder::patch), [post](crate::RequestBuilder::post) and [put](crate::RequestBuilder::put).
//! 
//! The 'RequestBuilder' allows to add name/value data for:
//! * Headers through the functions [header](crate::RequestBuilder::header) for a single header or [headers](crate::RequestBuilder::headers) for a set of headers.
//! Header names are case-insensitive.
//! * Parameters through the functions [param](crate::RequestBuilder::param) for a single parameter or [params](crate::RequestBuilder::params) for a set of parameters.
//! Parameter names are case-sensitive.
//! * Cookies through the functions [cookie](crate::RequestBuilder::cookie) for a single cookie or [cookies](crate::RequestBuilder::cookies) for a set of cookies.
//! Cookie names are case-sensitive.
//! 
//! Also, the `RequestBuilder` allows to set [HttpConfig](crate::HttpConfig) configurations through the [config](crate::RequestBuilder::config) function.
//! Finally, to create a [Request](crate::Request) object, it has to be used the [build](RequestBuilder::build) member function of `RequestBuilder`.
//! 
//! Next example shows how to construct a `GET` request to the URL `http://web.myservice.com/user?id=12345&name=John`
//! 
//! ```rust
//! use wclient::RequestBuilder;
//!
//! let request = RequestBuilder::get("http://web.myservice.com/user")
//!     .header("Accept", "application/json")
//!     .param("id", "12345")
//!     .param("name", "John")
//!     .build(); 
//! ```  
//! 
//! The `Request` body can be set as a `Vec<u8>` using the function [body](crate::RequestBuilder::body) or 
//! the function [json](crate::RequestBuilder::json) with a JSON Object value form the crate [json](https://docs.rs/json/0.12.4/json/).
//! 
//! 
//! ```no_run
//! use wclient::RequestBuilder;
//! use json::object;
//! let data = object! {
//!    name: "John",
//!    surname: "Smith"
//! };
//! 
//! let mut request = RequestBuilder::post("Http://web.myservice.com/user")
//!     .header("Accept", "application/json")
//!     .param("id", "12345")
//!     .json(&data)
//!     .build();

//! // The Response
//! 
//! let response = request.send().unwrap();
//! // Check status code is 200 Success
//! assert_eq!(response.status_code(), 200);
//! let result_json = response.json();
//! // Check the request had JSON content
//! assert!(result_json.is_ok());
//! let result_data = result_json.unwrap();
//! // Print JSON object
//! println!("{:?}", result_data.as_str() )
//! 
//! ``` 
//! 
//! After, created, the `send` function sends the request message to the target URL and returns a `Result<Response, Error>` value.
//! 
#![allow(dead_code)]

pub mod config;

pub mod cookie;

mod constants;

mod http;

use crate::cookie::Cookie;
use crate::config::{HttpConfig, HttpConfigBuilder};

use crate::constants::{CONTENT_TYPE, CONTENT_TYPE_JSON};
use crate::http::{parse_url, ClientConnectionFactory};

use std::str::from_utf8;
use std::io::{Error, ErrorKind};
use std::fmt;

use std::collections::HashMap;
use case_insensitive_hashmap::CaseInsensitiveHashMap;
use json::JsonValue;
use url::Url;


/// HTTP Request Method
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum HttpMethod {GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}",
                match self {
                    Self::GET => "GET",
                    Self::HEAD => "HEAD",
                    Self::POST => "POST",
                    Self::PUT=> "PUT",
                    Self::DELETE=> "DELETE",
                    Self::CONNECT => "CONNECT",
                    Self::OPTIONS => "OPTIONS",
                    Self::TRACE => "TRACE",
                    Self::PATCH=> "PATCH"
                }
        )
    }
}

/// HTTP request
/// 
/// A request is composed of:
/// * HTTP method (`GET`, `POST`, `PUT`, `DELETE`, ... )
/// * Target URL, for example, `https://myservice.com/users`
/// * (optional) Request headers.
/// * (optional) Request path parameters, for example, `id` in the  URL `https://myservice.com/users?id=1111`.
/// * (optional) Server cookies
/// * (optional) Request body of type `Vec[u8]`
/// 
/// Request headers, parameters and cookies are represented by a pair of `name` and `value` strings.
/// Additionally, a [HttpConfig](crate::config::HttpConfig) struct can be used to configure the HTTP connections stablished to
/// send a `Request` and receive a `Response`.
/// 
/// For more information see [HTTP Request](https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages#http_requests).
/// 


pub struct Request {
    /// HTTP method
    pub method: HttpMethod,
    /// Target url
    pub url: String,
    /// Parsed URL
    parsed_url: Option<Url>,
    /// HTTP version
    pub(crate) config: HttpConfig,
    /// Request headers
    pub(crate) headers: CaseInsensitiveHashMap<String>,
    // Request Cookies
    pub(crate) cookies: HashMap<String, String>,
    /// Request params
    pub(crate) params: HashMap<String, String>,
    /// Request body (not implemented multi-part yet)
    pub(crate) body: Vec<u8>
}


impl Request {
    /// Checks if this request has body
    pub fn has_body(&self) -> bool {
        self.body.len() > 0
    }

     /// Sends the request to the target URL.
    /// Returns the Response message or `std::io::Error` if any issue happened.
    pub fn send(&mut self) -> Result<Response, Error> {
        let url = parse_url(&self.url)?;

        let mut connection =
            ClientConnectionFactory::client_connection(
                &url,
                &self.config)?;

        self.parsed_url = Some(url);
        
        connection.send(self)
        
    }

}

/// Helper builder for [Request](crate::Request)
/// * The Request builder has a constructor for each HTTP method (`get`, `post`, `put`, ...) and a set of member functions
/// to set the request members. 
/// * A `build` function creates `Request`. 
/// 
/// ```no_run
/// use wclient::RequestBuilder;
/// use json::object;
/// let data = object! {
///    name: "John",
///    surname: "Smith"
/// };
/// 
/// let mut request = RequestBuilder::post("Http://web.myservice.com/user")
///     .header("Accept", "application/json")
///     .param("id", "12345")
///     .json(&data)
///     .build();
/// ``` 
pub struct RequestBuilder {
    /// HTTP method
    method: HttpMethod,
    /// Target url
    url: String,
    /// HTTP version
    config: HttpConfig,
    /// Request headers
    headers: CaseInsensitiveHashMap<String>,
    // Request Cookies
    cookies: HashMap<String, String>,
    /// Request params
    params: HashMap<String, String>,
    /// Request body (not implemented multi-part yet)
    body: Vec<u8>
}

impl RequestBuilder {
    /// Default constructor
    pub fn new(method: HttpMethod, url: &str) -> RequestBuilder {
        RequestBuilder {
            method,
            url: String::from(url),
            config: HttpConfigBuilder::default().build(),
            headers: CaseInsensitiveHashMap::new(),
            cookies: HashMap::new(),
            params: HashMap::new(),
            body: Vec::new()
        }
    }

    /// Creates a `CONNECT` request builder
    pub fn connect(url: &str) -> RequestBuilder {
        Self::new(HttpMethod::CONNECT, url)
    }

    /// Creates a `DELETE` request builder
    pub fn delete(url: &str) -> RequestBuilder {
        Self::new(HttpMethod::DELETE, url)
    }

    /// Creates a `GET` request builder
    pub fn get(url: &str) -> RequestBuilder {
        Self::new(HttpMethod::GET, url)
    }

    /// Creates a `HEAD` request builder
    pub fn head(url: &str) -> RequestBuilder {
        Self::new(HttpMethod::HEAD, url)
    }

    /// Creates a `OPTIONS` request builder
    pub fn options(url: &str) -> RequestBuilder {
        Self::new(HttpMethod::OPTIONS, url)
    }

    /// Creates a `PATCH` request builder
    pub fn patch(url: &str) -> RequestBuilder {
        Self::new(HttpMethod::PATCH, url)
    }

    /// Creates a `POST` request builder
    pub fn post(url: &str) -> RequestBuilder {
        Self::new(HttpMethod::POST, url)
    }

    /// Creates a `PUT` request builder
    pub fn put(url: &str) -> RequestBuilder {
        Self::new(HttpMethod::PUT, url)
    }
    
    /// Creates a `TRACE` request builder
    pub fn trace(url: &str) -> RequestBuilder {
        Self::new(HttpMethod::TRACE, url)
    }


    /// Sets the `Request` configuration
    pub fn config( mut self, data: HttpConfig) -> RequestBuilder {
        self.config = data;
        self
    }

    /// Adds a set of headers. If there is an existing header with the same key,
    /// it is overrriden. 
    ///
    /// **Note**: header names are case-insensitive.
    pub fn headers( mut self, data: HashMap<String, String>) -> RequestBuilder {
        self.headers.extend(data);
        self
    }

    /// Adds a header. If there is an existing header with the same `name',
    /// it is overrriden. 
    ///
    /// **Note**: header names are case-insensitive.
    pub fn header(mut self, name: &str, value: &str) -> RequestBuilder {
        self.headers.insert(String::from(name), String::from(value));
        self
    }

    /// Adds a set of parameters. If there is an existing parameter with the same key,
    /// it is overrriden. 
    ///
    /// **Note**: parameter names are case-sensitive.
    pub fn params( mut self, data: HashMap<String, String>) -> RequestBuilder {
        self.params.extend(data);
        self
    }

    /// Adds a parameter. If there is an existing parameter with the same key,
    /// it is overrriden. 
    ///
    /// **Note**: parameter names are case-sensitive.
    pub fn param(mut self, name: &str, value: &str) -> RequestBuilder {
        self.params.insert(String::from(name), String::from(value));
        self
    }

    /// Adds a set of cookies. If there is an existing cookie with the same key,
    /// it is overrriden. 
    ///
    /// **Note**: cookie names are case-sensitive.
    pub fn cookies( mut self, data: HashMap<String, String>) -> RequestBuilder {
        self.params.extend(data);
        self
    }

    /// Adds a cookie. If there is an existing cookie with the same key,
    /// it is overrriden. 
    ///
    /// **Note**: cookie names are case-sensitive.
    pub fn cookie(mut self, name: &str, value: &str) -> RequestBuilder {
        self.cookies.insert(String::from(name), String::from(value));
        self
    }

    /// Sets a request body. The `Request` takes ownership of the `data` buffer.
    pub fn body(mut self, data: Vec<u8>) -> RequestBuilder {
        self.body = data;
        self
    }

    /// Sets a json object as request body. The `data` object is marshaled into a buffer using UTF8 coding.
    pub fn json(mut self, data: &JsonValue) -> RequestBuilder {
        let pretty = data.pretty(4);
        self.body = pretty.into_bytes();
        self.headers.insert(String::from(CONTENT_TYPE), String::from(CONTENT_TYPE_JSON));
        self
    }

    /// Creates a [Request](crate::Request) struct.
    pub fn build(self) -> Request {
        Request {
            method: self.method,
            url: self.url,
            parsed_url: None,
            config: self.config,
            headers: self.headers,
            cookies: self.cookies,
            params: self.params,
            body: self.body
        }

    }
}


/// HTTP Response status code
pub type HttpStatusCode = u16;

/// HTTP 100 CONTINUE status code
pub const HTTP_100_CONTINUE: u16 = 100;
/// HTTP 101 SWITCHING_PROTOCOLS status code
pub const HTTP_101_SWITCHING_PROTOCOLS: u16 = 101;
/// HTTP 200 OK status code
pub const HTTP_200_OK: u16 = 200;
/// HTTP 201 CREATED status code
pub const HTTP_201_CREATED: u16 = 201;
/// HTTP 202 ACCEPTED status code
pub const HTTP_202_ACCEPTED: u16 = 202;
/// HTTP 204 NO CONTENT status code
pub const HTTP_204_NO_CONTENT: u16 = 204;
/// HTTP 205 RESET CONTENT status code
pub const HTTP_205_RESET_CONTENT: u16 = 205;
/// HTTP 400 BAD REQUEST status code
pub const HTTP_400_BAD_REQUEST: u16 = 400;
/// HTTP 401 UNAUTHORIZED status code
pub const HTTP_401_UNAUTHORIZED: u16 = 401;
/// HTTP 402 BAD REQUEST status code
pub const HTTP_402_FORBIDDEN: u16 = 402;
/// HTTP 404 NOT FOUND status code
pub const HTTP_404_NOT_FOUND: u16 = 404;
/// HTTP 405 METHOD NOT ALLOWED status code
pub const HTTP_405_METHOD_NOT_ALLOWED: u16 = 405;
/// HTTP 406 NOT ACCEPTABLE status code
pub const HTTP_406_NOT_ACCEPTABLE: u16 = 406;
/// HTTP 408 REQUEST_TIMEOUT status code
pub const HTTP_408_REQUEST_TIMEOUT: u16 = 408;
/// HTTP 500 INTERNAL_SERVE_ERROR status code
pub const HTTP_500_INTERNAL_SERVE_ERROR: u16 = 500;
/// HTTP 501 NOT IMPLEMENTED status code
pub const HTTP_501_NOT_IMPLEMENTED: u16 = 501;


/// List of `Set-Cookie` headers in a HTTP Response
pub type SetCookies = Vec<Cookie>;

/// HTTP Response
/// An HTTP Response is formed by:
/// * Status code
/// * (optional) Response headers
/// * (optional) Server's cookies (header `Set-Cookie`)
/// * (optional) Response body
/// 
/// For mor information see [HTTP Response](https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages#http_responses)
pub struct Response {
    /// Response status code
    pub(crate) status_code: HttpStatusCode,
    /// Response headers
    pub(crate) headers: HashMap<String, String>,
    /// Response cookies
    pub(crate) cookies: SetCookies,
    /// Response body
    pub(crate) body: Vec<u8>
}

impl Response {
    /// Response default constructor, only sets the status code.
    /// After constructing the value, as struct members are public, they can be
    /// accessed directly
    pub fn new(status: HttpStatusCode) -> Response {
        Response {
            headers: HashMap::new(),
            cookies: SetCookies::new(),
            status_code: status,
            body: Vec::new()
        }
    }

    /// Get the Response status code
    pub fn status_code(&self) -> HttpStatusCode {
        self.status_code
    }

    /// Get Response Headers.
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Get Request Cookies.
    pub fn cookie(&self) -> &SetCookies {
        &self.cookies
    }

    /// returns if the Response has body
    pub fn has_body(&self) -> bool {self.body.len() > 0}

    /// Response's body builder.
    pub fn body(& self) -> &Vec<u8> {
        &self.body
    }

    /// Checks if the Response has body and tries to parse as a `json::JsonValue'
    pub fn json(&self) -> Result<JsonValue, Error> {
        if self.body.is_empty() {
            return Err(Error::new(ErrorKind::InvalidData, "Empty body"));
        }

        let str_body = from_utf8(&self.body);

        if str_body.is_err() {
            return Err(Error::new(ErrorKind::InvalidData, str_body.err().unwrap()));
        }

        let result = json::parse(str_body.unwrap());

        return if result.is_ok() {
            Ok(result.unwrap())
        } else {
            Err(Error::new(ErrorKind::InvalidData, result.err().unwrap()))
        }
    }
}

#[cfg(test)]
mod test;


