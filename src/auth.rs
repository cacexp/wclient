//! HTTP Authentication module
//! 
//! This module defines the [crate::auth::AuthManager] and some implementations to deal with `WWW-Authenticate" header
//! in `401 Not Authenticated' HTTP responses:
//! 
//! * [crate::auth::HttpBasicAuth] that generates `Authenticate: Basic ...` headers for a news authenticated request

use crate::Request;
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use data_encoding;
use std::fmt;

/// Error produced when an [AuthManager](crate::auth::AuthManager) cannot generate a valid authorization header
#[derive(Debug, Clone)]
pub enum CannotAuthorize {
    /// The requested authorization method (for example `Digest`) is not supported. `String` member is the supported schema.
    UnsuportedAuthScheme(String),
    /// There was an error while generating the `Authorization` headers
    Err
}

impl fmt::Display for CannotAuthorize {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::UnsuportedAuthScheme(ref scheme) => write!(f, "Unsupported authorization scheme. Expected {}", scheme),
            Self::Err => write!(f, "Error while generating authorization")
        }
    }
}

/// Trait that generates `Authentication` headers.
/// Trait used by `Request` to include the `Authentication` header when requested by the server.
/// The `challenge` is the value content of the `WWW-Authenticate` header send by the server on an
/// `401 Unauthorized` response. This is defined on [RFC 7235](https://www.rfc-editor.org/rfc/rfc7235).
/// 
/// Custom authentication managers can be provied by implementing this trait.
pub trait AuthManager: Sync {
    /// Checks if the Auth Manager supports `scheme` (e.g. `Basic`, `Digest`, ...)
    fn support_scheme(&self, scheme: &str) -> bool;
    /// Calculates at least the `Authrization` header or generates a [std::io::Error] 
    /// if not capable to generate this headers returns 'CannotAuthorize`.
    /// Params:
    /// 
    /// * `request`: request to be sent to the server
    /// * `challenge`: vector of the values of `WWW-Authorize` headers received in a `HTTP 401` response.
    /// 
    /// Returns result with:
    /// 
    /// * Vector with authorization headers: typically opne header with `Authorization` key and value should be generated. or,
    /// * 'CannotAuthorize' error when the requested authorization type cannot be handle by this `AuthManager` or requested
    /// authorization cannot be generated
    fn authorization(&mut self, request: &Request, challenge: &Vec<&str>) -> Result<Vec<(String, String)>, CannotAuthorize>;
}

/// HTTP Basic Authorization based on [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html)
/// It takes a `user`and `password` and generates an authorization header:
/// 
/// `Authorization: Basic basic-credentials-base64` 
/// 
/// Basic authorization header is always set.
/// 
/// **Note:** for compatibility `user`and `password` should be formed by ASCII characters.
pub struct HttpBasicAuth {
    user: String,
    password: String
}

impl AuthManager for HttpBasicAuth {

    fn support_scheme(& self, scheme: &str) -> bool {
        return scheme.to_lowercase().as_str() == "basic"
    }

    fn authorization(&mut self, _request: &Request, challenges: &Vec<&str>) -> Result<Vec<(String, String)>, CannotAuthorize> {

        if challenges.len() > 0 {
            if ! HttpBasicAuth::basic_scheme_requested(challenges) {
                return Err(CannotAuthorize::UnsuportedAuthScheme(String::from("Basic")));
            }
        }

        let payout = format!("{}:{}", self.user, self.password);
        let encoded = data_encoding::BASE64.encode(payout.as_bytes());

        Ok(vec!((String::from("Authorization"), format!("Basic {}", encoded))))
    }
}

impl HttpBasicAuth {
    pub fn new(user: &str, password: &str) -> HttpBasicAuth {
        HttpBasicAuth{
            user: String::from(user),
            password: String::from(password)
        }
    }
    fn basic_scheme_requested(challenges: &Vec<& str>) -> bool {
        for value in challenges {
            if let Ok(_) = BasicChallenge::from_str(value) {
                return true;
            }
        }
        return false;
    }
}

struct BasicChallenge {
    realm: Option<String>,
    charset: Option<String>
}

impl FromStr for BasicChallenge {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let params_str = s.trim().strip_prefix("Basic").ok_or(parse_basic_error())?;

        let params = parse_challenge_params(params_str.trim_start())?;
        
        let mut result = BasicChallenge{
            realm: None,
            charset: None
        };

        for (key,value) in params {
            let val = Some(String::from(value));
            match key.to_lowercase().as_str() {
                "realm" => result.realm = val,
                "encoding" => result.charset = val,
                _ => continue // Ignore other parameters
            }
        }

        return Ok(result);
        
    }
}


fn parse_authorize_error() -> Error {
    Error::new(ErrorKind::InvalidData, "Invalid WWW-Authorize header")
}

fn parse_basic_error() -> Error {
    Error::new(ErrorKind::InvalidData, "Invalid Basic WWW-Authorize header")
}

fn parse_digest_error() -> Error {
    Error::new(ErrorKind::InvalidData, "Invalid Digest WWW-Authorize header")
}

/// Prase key/value params from `WWW-Authorize` header
fn parse_challenge_params<'a>(s: &'a str) -> Result<Vec<(&'a str, &'a str)>, Error> {

    let mut result: Vec<(&'a str, &'a str)> = Vec::new();

    let mut cursor = s;

    loop {

        let equal_pos = cursor.find("=").ok_or(parse_basic_error())?;

        let key = &cursor[0..equal_pos];

        cursor = &cursor[equal_pos+1 ..];

        if cursor.len() == 0 {
            return Err(parse_basic_error());
        }

        if let Some(param_start) = cursor.find("\"") {
            cursor = &cursor[param_start ..];
            let param_end = cursor.find('\"').ok_or(parse_basic_error())? - 1;
            let value = &cursor[..param_end];
            result.push((key, value));
            if let Some(comma_pos) = cursor.find(',') {
                if comma_pos == cursor.len() -1 {
                    return Err(parse_basic_error());
                }
                cursor = &cursor[comma_pos..];
            } else {
                break; // end of params
            }            
        } else {
            if let Some(param_end) = cursor.find(',') {
                let value = &cursor[..(param_end-1)];
                result.push((key,value));
                cursor = &cursor[param_end..];
            } else {  // last param
                let value = &cursor.trim_end();
                result.push((key,value));
                break;
            }
        }
    }
    
    return Ok(result);
}