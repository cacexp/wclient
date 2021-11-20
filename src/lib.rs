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
//! * HTTP 1.1 [Request](crate::Request) and [Response](crate::Response) over plain TCP/IP and TLS
//! //! * HTTP [Session](crate::Session) to share configuration and a cookie jar among requests
//! * HTTP 1.1 Single Body
//! * HTTPS (v1.1) with default site certificate verification (only with host CA certificates)
//! * HTTPS custom site certificate validation (local directory or certificate chain) in *.pem format
//! * HTTPS client certificate authentication
//! * HTTP Connection pooling
//!
//! # Future Features
//! * Multipart
//! * HTTP 2.0
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
//! ```no_run
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
//! ## HTTP Connection configuration
//! 
//! The `RequestBuilder` has a function to set a [HttpConfig](crate::config::HttpConfig). Currently, it can be configured:
//! * The Root CA certificates to authenticate the server with HTTPS, see [HttpsVerify](crate::config::HttpsVerify)
//! * The client certificate to be authenticated against the serve with HTTPS, see [HttpsCert](crate::config::HttpsCert)

//! ### Server authentication
//! 
//! By default, `wclient`uses the system CA certificates directory (for example, `/etc/ssl/certs`). Trusted CA can be also passed as a `.pem` file path or a 
//! directory containing certificate files:
//! 
//! ```no_run
//! 
//! use wclient::RequestBuilder;
//! use wclient::config::{HttpsVerify, HttpConfigBuilder};
//! 
//! let config = HttpConfigBuilder::default()
//!    .verify(HttpsVerify::Path(String::from("./config/server.pem")))
//!    .build();
//! 
//! let request = RequestBuilder::get("https://web.myservice.com/user")
//!     .header("Accept", "application/json")
//!     .config(&config);
//! 
//! ```
//! 
//! ### Client authentication
//! 
//! The client app can be authenticated against the HTTPS using a certificate and the assotiated private key by using the [HttpsCert](crate::config::HttpsCert) enum.
//!
//!  **_NOTE:_**  If the client certificate is self-signed or signed by CA that is not in the system or custom CA certificates list, the client certificate must contain
//! the certificate chain to the root CA. In this case, the fist certificate in the file must be the client certificate.
//! 
//! ```no_run
//! 
//! use wclient::RequestBuilder;
//! use wclient::config::{HttpsCert, HttpConfigBuilder};
//! 
//! let config = HttpConfigBuilder::default()
//!    .cert(HttpsCert::CertKey{cert: String::from("/path/client.crt"), key: String::from("/path/client.key")})
//!    .build();
//! 
//! let request = RequestBuilder::get("https://web.myservice.com/user")
//!     .header("Accept", "application/json")
//!     .config(&config)
//!     .build();
//! 
//! ```
//! 
//! ## HTTP Sessions
//! 
//! The [Session](crate::Session) type allows to store common configurations and share cookies through an internal or custom set cookie jar.
//! 
//! `Session` values are constructed through the [SessionBuilder](crate::SessionBuilder) builder that allows to set a `HttpConfig` value 
//! and a shared pointer to a shared `CookieJar` trait implementation.
//! 
//! ```no_run
//! 
//! use wclient::SessionBuilder;
//! use wclient::config::{HttpsCert,HttpConfigBuilder};
//! 
//! 
//! let config = HttpConfigBuilder::default()
//!    .cert(HttpsCert::CertKey{cert: String::from("/path/client.crt"), key: String::from("/path/client.key")})
//!    .build();
//!     
//! let session = SessionBuilder::new()
//!    .config(&config)
//!    .build();
//! 
//! ```
//! 
//! Once built, the `Session` value allows to create `RequestBuilder` for each HTTP method that shares the `HttpConfig` and `CookieJar`. 
//! The `RequestBuilder` can override the shared config and cookie jar.
//! 
//! ```no_run
//! use wclient::SessionBuilder;
//! 
//! let mut session = SessionBuilder::new().build();
//! 
//! let mut request = session.get("https://service.com/user")
//!     .header("Accept", "application/json")
//!     .build();
//! 
//! let response = request.send();
//! 
//!  ```
//! 

#![allow(dead_code)]

pub mod config;

pub mod cookie;

mod constants;

mod http;

use std::sync::Mutex;
use crate::cookie::MemCookieJar;
use crate::cookie::CookieJar;
use std::sync::Arc;
use crate::cookie::Cookie;
use crate::config::{HttpConfig, HttpConfigBuilder};

use crate::constants::{CONTENT_TYPE, CONTENT_TYPE_JSON};
use crate::http::{parse_url, EndPoint, HttpScheme, ClientConnectionFactory};

use std::str::from_utf8;
use std::io::{Error, ErrorKind};
use std::fmt;

use std::collections::HashMap;
use case_insensitive_hashmap::CaseInsensitiveHashMap;
use json::JsonValue;


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
    /// Target URL
    pub(crate) url: String,
    /// Request endpoint
    pub(crate) endpoint: Option<EndPoint>,
    /// Request path
    pub path: String, 
    /// HTTP version
    pub(crate) config: HttpConfig,
    /// Request headers
    pub(crate) headers: CaseInsensitiveHashMap<String>,
    /// CookieJar to get/save cookies
    pub (crate) jar: Option<Arc<Mutex<dyn CookieJar>>>,
    // Request Cookies
    pub(crate) cookies: HashMap<String, String>,
    /// Request params
    pub(crate) params: HashMap<String, String>,
    /// Request body (not implemented multi-part yet)
    pub(crate) body: Vec<u8>,
    /// Session's connection factory
    factory: Option<Arc<Mutex<ClientConnectionFactory>>>,
    /// On-build error
    init_error: Option<Error>
}


impl Request {
   
    /// Checks if this request has body
    pub fn has_body(&self) -> bool {
        self.body.len() > 0
    }

    pub fn url(&self) -> &str {
        self.url.as_str()
    }

    pub (crate) fn endpoint(&self) -> Result<&EndPoint, Error> {
        if self.endpoint.is_none() {
            return Err(Error::new(ErrorKind::InvalidData, "URL has not got a valid endpoint"));
        }

        Ok(self.endpoint.as_ref().unwrap())
    }

    pub (crate) fn path(&self) ->  &str {
        // if no errors path should be always good
        self.path.as_str()
    }

     /// Sends the request to the target URL.
    /// Returns the Response message or `std::io::Error` if any issue happened.
    pub fn send(&mut self) -> Result<Response, Error> {
        
        if let Some(ref error) = self.init_error {
            return Err(Error::new(error.kind(), error.get_ref().unwrap().to_string()));
        }

        if self.endpoint.is_none(){
            return Err(Error::new(ErrorKind::InvalidData, "Cannot get host from URL"));
        }

        let endpoint = self.endpoint.as_ref().unwrap();

        // Get cookies from cookie jar (if any)
        if let Some(ref cookie_jar) = self.jar {
            let active_cookies = cookie_jar.lock().as_mut().unwrap().active_cookies(endpoint.host.as_str(), &self.path, endpoint.scheme == HttpScheme::HTTPS);

            for cookie in active_cookies {
                            // request cookies have prevalence over cookie jar's ones

                if self.cookies.contains_key(&cookie.0) {
                    continue;
                }

                self.cookies.insert(cookie.0, cookie.1);
            }
        }

        let connection = if let Some(ref factory) = &self.factory {
            factory.lock().unwrap().get_connection(endpoint, &self.config)?
        } else {
            ClientConnectionFactory::client_connection(endpoint, &self.config)?
        };
        
        return connection.lock().unwrap().send(self);
        
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
    /// CookieJar to get/store server cookies
    jar: Option<Arc<Mutex<dyn CookieJar>>>,
    // Request Cookies
    cookies: HashMap<String, String>,
    /// Request params
    params: HashMap<String, String>,
    /// Request body (not implemented multi-part yet)
    body: Vec<u8>,
    /// Session's connection factory
    factory: Option<Arc<Mutex<ClientConnectionFactory>>>    
}

impl RequestBuilder {
    /// Default constructor
    pub fn new(method: HttpMethod, url: &str) -> RequestBuilder {
        RequestBuilder {
            method,
            url: String::from(url),
            config: HttpConfigBuilder::default().build(),
            headers: CaseInsensitiveHashMap::new(),
            jar: None,
            cookies: HashMap::new(),
            params: HashMap::new(),
            body: Vec::new(),
            factory: None
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
    pub fn config( mut self, data: &HttpConfig) -> RequestBuilder {
        self.config = data.clone();
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

    /// Sets a CookieJar to get/save session cookies
    
    pub fn cookie_jar(mut self, jar: Arc<Mutex<dyn CookieJar>>) -> RequestBuilder {
        self.jar = Some(jar);
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

    /// Sets Connection Factory
    fn factory(mut self, factory: Arc<Mutex<ClientConnectionFactory>>) -> RequestBuilder {
        self.factory = Some(factory);
        self
    }

    /// Creates a [Request](crate::Request) struct.
    pub fn build(self) -> Request {

        let mut init_error: Option<Error> = None;
        let mut endpoint_holder: Option<EndPoint> = None;

        let url = parse_url(&self.url);

        let path = String::from(
            if url.is_ok() {
                url.as_ref().unwrap().path()
            } else {
                "/"
            }
        );
        
        if url.is_ok() {

            let endpoint = EndPoint::from_url(url.as_ref().unwrap());
            
            if endpoint.is_err() {
                init_error = Some(endpoint.err().unwrap());
            } else {
                endpoint_holder = Some(endpoint.unwrap());
            }
        } else {
            init_error = url.err();
        } 

        Request {
            method: self.method,
            url: self.url,
            endpoint: endpoint_holder,
            path, 
            config: self.config,
            headers: self.headers,
            jar: self.jar,
            cookies: self.cookies,
            params: self.params,
            body: self.body,
            factory: self.factory,
            init_error
        }
    }
}

/// HTTP session used to share configuration and cookies among different requests and responses
/// 
/// The `Session` is constructed by a [SessionBuilder](crate::SessionBuilder) which accepts an [HttpConfig](crate::SessionBuilder) and 
/// a shared [CookieJar](crate::cookie::CookieJar).
/// 
/// When constructed, a `Session` can generate request builders with shared config and cookie environment. 
/// 
/// See [modules documentation](index.html#http-sessions) for session user manual.
/// 
pub struct Session {
    config: HttpConfig,
    jar: Arc<Mutex<dyn CookieJar>>,
    factory: Arc<Mutex<ClientConnectionFactory>>
}

impl Session {
    /// Gets session config
    pub fn config(&self) -> &HttpConfig {
        &self.config
    }

    /// Gets session's cookie jar
    pub fn cookie_jar(&self) -> Arc<Mutex<dyn CookieJar>> {
        self.jar.clone()
    }

   /// Creates a `CONNECT` request builder
   pub fn connect(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::CONNECT, url)
        .config(&self.config)
        .cookie_jar(self.jar.clone())
    }

    /// Creates a `DELETE` request builder
    pub fn delete(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::DELETE, url)
        .config(&self.config)
        .cookie_jar(self.jar.clone())

    }

    /// Creates a `GET` request builder
    pub fn get(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::GET, url)
        .config(&self.config)
        .cookie_jar(self.jar.clone())
    }

    /// Creates a `HEAD` request builder
    pub fn head(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::HEAD, url)
        .config(&self.config)
        .cookie_jar(self.jar.clone())
    }

    /// Creates a `OPTIONS` request builder
    pub fn options(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::OPTIONS, url)
        .config(&self.config)
        .cookie_jar(self.jar.clone())
    }

    /// Creates a `PATCH` request builder
    pub fn patch(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::PATCH, url)
        .config(&self.config)
        .cookie_jar(self.jar.clone())
    }

    /// Creates a `POST` request builder
    pub fn post(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::POST, url)
        .config(&self.config)
        .cookie_jar(self.jar.clone())
    }

    /// Creates a `PUT` request builder
    pub fn put(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::PUT, url)
        .config(&self.config)
        .cookie_jar(self.jar.clone())
    }


    /// Creates a `TRACE` request builder
    pub fn trace(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new(HttpMethod::TRACE, url)
        .config(&self.config)
        .cookie_jar(self.jar.clone())
    }
}

/// [Session](crate::Session) Builder class.
/// 
/// Usage example:
/// 
/// ```no_run
/// use wclient::SessionBuilder;
/// use wclient::config::HttpConfigBuilder;
/// 
/// let config = HttpConfigBuilder::default()
///     // Set config here
///     .build();
/// 
/// let session = SessionBuilder::new()
///     .config(&config)
///     .build();
/// ```
/// 
pub struct SessionBuilder {
    config: Option<HttpConfig>,
    jar: Option<Arc<Mutex<dyn CookieJar>>>
}

impl SessionBuilder {

    /// Constructor
    pub fn new() -> SessionBuilder {
        SessionBuilder {
            config: None,
            jar: None
        }
    }

    /// Sets the `Request` configuration
    pub fn config( mut self, data: &HttpConfig) -> SessionBuilder {
        self.config = Some(data.clone());
        self
    }

     /// Sets a CookieJar to get/save session cookies, uf not provided defauls is [MemCookieJar](crate::cookie::MemCookieJar) 
     pub fn cookie_jar(mut self, jar: Arc<Mutex<dyn CookieJar>>) -> SessionBuilder {
        self.jar = Some(jar);
        self
    }

    /// `Session` Builder
    pub fn build(mut self) -> Session {
        if self.jar.is_none() {
            self.jar = Some(Arc::new(Mutex::new(MemCookieJar::new())));
        }

        if self.config.is_none() {
            self.config = Some(HttpConfigBuilder::default().build());
        }
        Session {
            config: self.config.unwrap(),
            jar: self.jar.unwrap().clone(),
            factory: Arc::new(Mutex::new(ClientConnectionFactory::new()))
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


