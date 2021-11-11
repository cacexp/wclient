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

use std::str::FromStr;
use std::io::{Error, ErrorKind};
use httpdate::parse_http_date;
use std::time::{Duration, SystemTime};
use std::ops::Add;

pub(crate) const COOKIE: &str = "cookie";
pub(crate) const COOKIE_EXPIRES: &str = "expires";
pub(crate) const COOKIE_MAX_AGE: &str = "max-age";
pub(crate) const COOKIE_DOMAIN: &str = "domain";
pub(crate) const COOKIE_PATH: &str = "path";
pub(crate) const COOKIE_SAME_SITE: &str = "samesite";
pub(crate) const COOKIE_SAME_SITE_STRICT: &str = "strict";
pub(crate) const COOKIE_SAME_SITE_LAX: &str = "lax";
pub(crate) const COOKIE_SAME_SITE_NONE: &str = "none";
pub(crate) const COOKIE_SECURE: &str = "secure";
pub(crate) const COOKIE_HTTP_ONLY: &str = "httponly";

/// Enum with `SameSite` possible values for `Set-Cookie` attribute
#[derive(Debug,Copy,Clone,PartialEq)]
pub enum SameSiteValue {Strict, Lax, None}

impl FromStr for SameSiteValue {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        return match s {
            COOKIE_SAME_SITE_STRICT => Ok(SameSiteValue::Strict),
            COOKIE_SAME_SITE_LAX => Ok(SameSiteValue::Lax),
            COOKIE_SAME_SITE_NONE => Ok(SameSiteValue::None),
            _ => Err(
                Error::new(ErrorKind::InvalidData,
                           format!("Invalid SameSite cookie directive value: {}", s)))
        }

    }
}

/// Represents a cookie created from `Set-Cookie` response header. 
/// 
/// A `Cookie` can be parsed from the `Set-Cookie` value from an HTTP `Response` using the trait `FromStr`:
///
///  `let cookie = Cookie::from_str("id=a3fWa; Expires=Wed, 21 Oct 2022 07:28:00 GMT");`
/// 
/// See [Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) for more information.

pub struct Cookie {
    /// Cookie name
    pub(crate) name: String,
    /// Cookie value
    pub (crate) value: String,
    /// Cookie domain (optional)
    pub(crate) domain: Option<String>,
    /// Cookie path (optional)
    pub(crate) path: Option<String>,
    /// When the Cookie expires, if None, it does not expire.
    /// This value is obtained from Max-Age and Expires attributes (Max-Age has precedence)
    pub(crate) expires: Option<SystemTime>,
    /// Cookie same site value (option)
    pub(crate) same_site: Option<SameSiteValue>,
    /// Cookie requires HTTPS
    pub(crate) secure: bool,
    /// Browsers does not allow Javascript access to this cookie (this directive should be ignored)
    pub(crate) http_only: bool       
}


impl Cookie {
    /// Constructor. It takes ownership of `name` and `value` strings.
    pub fn new (name: String, value: String) -> Cookie {
        Cookie {
            name,
            value,
            domain: None,
            path: None,
            expires: None,
            same_site: None,
            secure: false,
            http_only: false
        }
    }

    /// Cookie name
    pub fn name(& self) -> &str {
        self.name.as_str()
    }

    /// Cookie value
    pub fn value(& self) -> &str {
        self.value.as_str()
    }

    /// Cookie domain (optional)
    pub fn domain(& self) -> Option<&String> {
        self.domain.as_ref()
    }

    /// Cookie path (optional)
    pub fn path(& self) -> Option<&String> {
        self.path.as_ref()
    }
    /// When the Cookie expires, if `None`, it does not expire.
    /// This value is obtained from `Max-Age` and `Expires` attributes (Max-Age has precedence)
    pub fn expires(& self) -> Option<SystemTime> {
        self.expires.clone()
    }

    /// Cookie `Same-Site` value (optional)
    pub fn same_site(& self) -> Option<SameSiteValue> {
        self.same_site.clone()
    }
    /// Cookie requires HTTPS
    pub fn secure(& self) -> bool {
        self.secure
    }
    /// Cookie requires HTTP only
    pub fn http_only(& self) -> bool {
        self.http_only
    }
   
}

/// Traid to parse a Cookie from an string. This is usefull when receiving the `Set-Cookie` header from an HTTP response.
impl FromStr for Cookie {
    
    type Err = Error;

    fn from_str(s: &str) ->  Result<Cookie, Self::Err> {
        let mut components = s.split(';');

        return if let Some(slice) = components.next() {
            let (key, value) = parse_cookie_value(slice)?;
            let mut cookie = Cookie::new(key, value);
            while let Some(param) = components.next() {
                let directive = CookieDirective::from_str(param)?;
                match directive {
                    CookieDirective::Expires(date) => {
                        if cookie.expires().is_none() {  // Max-Age already parsed, it has precedence
                            cookie.expires = Some(date);
                        }
                    },
                    CookieDirective::MaxAge(seconds) => {
                        cookie.expires = Some(SystemTime::now().add(seconds));
                    },
                    CookieDirective::Domain(url) => cookie.domain = Some(url),
                    CookieDirective::Path(path) => cookie.path = Some(path),
                    CookieDirective::SameSite(val) => cookie.same_site = Some(val),
                    CookieDirective::Secure => cookie.secure = true,
                    CookieDirective::HttpOnly => cookie.http_only = true
                }
            }
            Ok(cookie)
        } else {
            let (key, value) = parse_cookie_value(s)?;
            Ok(Cookie::new(key, value))
        }
    }
}

/// Helper function to parse the `Cookie` name and value
pub(crate) fn parse_cookie_value(cookie: &str) -> Result<(String, String), Error>{
    if let Some(index) = cookie.find('=') {
        let key = String::from(cookie[0..index].trim());
        let value = String::from(cookie[index + 1..].trim());
        return Ok((key, value))
    } else {
        Err(Error::new(ErrorKind::InvalidData,
                       format!("Malformed HTTP cookie: {}", cookie)))
    }
}

/// Helper enum to parse directives and set up the `Cookie` values
enum CookieDirective {
    Expires(SystemTime),
    MaxAge(Duration),
    Domain(String),
    Path(String),
    SameSite(SameSiteValue),
    Secure,
    HttpOnly
}

/// Helper function to parse `CookieDirective`
impl FromStr for CookieDirective {
    
    type Err = Error;

    fn from_str(s: &str) -> Result<CookieDirective,Error> {
        if let Some(index) = s.find('=') { // Cookie param with value
            let key = s[0..index].trim().to_ascii_lowercase();
            let value = s[index + 1..].trim();
            return match key.as_str() {
                COOKIE_EXPIRES => {
                    let expires = parse_http_date(value).or_else (|_| Err(Error::new(ErrorKind::InvalidData, format!("Invalid date: {}", s))))?;                    
                    Ok(CookieDirective::Expires(expires))
                },
                COOKIE_MAX_AGE => {  // Max-age value in seconds
                    let digit = u64::from_str(value)
                        .or_else(|e|  {
                            Err(Error::new(ErrorKind::InvalidData, e))
                        })?;
                    Ok(CookieDirective::MaxAge(Duration::from_secs(digit)))
                },
                COOKIE_DOMAIN => {
                    Ok(CookieDirective::Domain(String::from(value)))
                },
                COOKIE_PATH => {
                    Ok(CookieDirective::Path(String::from(value)))
                }
                COOKIE_SAME_SITE => {
                    let lower_case = value.to_ascii_lowercase();
                    match SameSiteValue::from_str(lower_case.as_str()) {
                        Ok(site_value) => Ok(CookieDirective::SameSite(site_value)),
                        Err(e) => Err(e)
                    }
                },
                _ => return Err(
                    Error::new(ErrorKind::InvalidData,
                            format!("Invalid HTTP cookie directive: {}", &key)))
            }
        } else {
            match s {
                COOKIE_SECURE => Ok(CookieDirective::Secure),
                COOKIE_HTTP_ONLY => Ok(CookieDirective::HttpOnly),
                _ => return Err(
                    Error::new(ErrorKind::InvalidData,
                            format!("Invalid HTTP cookie directive: {}", s)))
            }
        }
    }
}

#[cfg(test)]
mod cookie_test;