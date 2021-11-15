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

use chrono::Utc;
use chrono::NaiveDate;
use std::time::UNIX_EPOCH;
use chrono::DateTime;
use std::str::FromStr;
use std::io::{Error, ErrorKind};
use std::time::{Duration, SystemTime};
use std::ops::Add;
use std::collections::{HashMap, HashSet};
use std::cmp::{PartialEq, Eq};
use std::hash::{Hash, Hasher};
use lazy_static::lazy_static;
use regex::Regex;

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
/// See [RFC6265 Set-Cookie](https://datatracker.ietf.org/doc/html/rfc6265#section-4.2) for more information.

#[derive(Debug,Clone)]
pub struct Cookie {
    /// Cookie name
    pub(crate) name: String,
    /// Cookie value
    pub (crate) value: String,
    /// Cookie domain, by default is the originating domain of the request
    pub(crate) domain: String,
    /// Cookie path, by default, it is the request's path
    pub(crate) path: String,
    /// When the Cookie expires, if None, it does not expire.
    /// This value is obtained from Max-Age and Expires attributes (Max-Age has precedence)
    pub(crate) expires: Option<SystemTime>,
    /// Cookie same site value (option)
    pub(crate) same_site: SameSiteValue,
    /// Cookie requires HTTPS
    pub(crate) secure: bool,
    /// Browsers does not allow Javascript access to this cookie
    pub(crate) http_only: bool,
    /// Other Set-Cookie extensions
    pub(crate) extensions: HashMap<String, String>    
}


impl Cookie {
    /// Constructor. It takes ownership params:
    ///
    /// * `name`: Cookie name
    /// * `value`: Cookie value, for binary data it is recommended [Base64](https://en.wikipedia.org/wiki/Base64) encoding.
    /// * `domain`: Cookie domain, sets hosts (domain and subdomains) to which the cookie will be sent, in includes subdomains.
    /// If not present in `Set-Cookie` header, it is taken from the HTTP request `Host` header
    /// * `path`: Cookie path, paths (same path or children) to which the cookie will be sent
    /// If not present in `Set-Cookie` header, it is taken from the HTTP request path

    pub fn new (name: String, value: String, domain: String, path: String) -> Cookie {
        Cookie {
            name,
            value,
            domain,
            path,
            expires: None,
            same_site: SameSiteValue::Lax,
            secure: false,
            http_only: false,
            extensions: HashMap::new()            
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

    /// Cookie domain: hosts to which the cookie will be sent
    pub fn domain(& self) -> &str {
        self.domain.as_str()
    }

    /// Cookie path
    pub fn path(& self) -> &str {
        self.path.as_str()
    }
    /// When the Cookie expires, if `None`, it does not expire.
    /// This value is obtained from `Max-Age` and `Expires` attributes (Max-Age has precedence)
    pub fn expires(& self) -> Option<SystemTime> {
        self.expires.clone()
    }

    /// Cookie `Same-Site` value (optional)
    pub fn same_site(& self) -> SameSiteValue {
        self.same_site
    }
    /// Cookie requires HTTPS
    pub fn secure(& self) -> bool {
        self.secure
    }
    /// Cookie requires HTTP only
    pub fn http_only(& self) -> bool {
        self.http_only
    }

    /// Cookie extendions
    pub fn extensions(&self) -> &HashMap<String, String> {
        &self.extensions
    }

    /// Checks if the request path match the cookie path. 
    /// 
    /// Using [RFC6265 Section 5.1.4](https://datatracker.ietf.org/doc/html/rfc6265#section-5.1.4) Algorithm.    
    pub fn path_match(&self, request_path: &str) -> bool {
        
        let cookie_path = self.path();

        let cookie_path_len = cookie_path.len();
        let request_path_len = request_path.len();
 
       
        if !request_path.starts_with(cookie_path) {  // A. cookie path is a prefix of request path
            return false;
        }
    
        return request_path_len ==  cookie_path_len // 1. They are identical, or
            // 2. A and cookie path ends with an slash
            || cookie_path.chars().nth(cookie_path_len - 1).unwrap() == '/' 
            // 3. A and the first char of request path that is not incled in request path is an slash
            || request_path.chars().nth(cookie_path_len).unwrap() == '/'; 
    }

    /// Checks if the request domain match the cookie domain. 
    /// 
    /// Using [RFC6265 Section 4.1.1.3](https://datatracker.ietf.org/doc/html/rfc6265#section-4.1.2.3).
    pub fn domain_match(&self, request_domain: &str) -> bool {
        let cookie_domain = self.domain();
        
        if let Some(index) = request_domain.rfind(cookie_domain) {
            if index == 0 { // same domain
                return true;
            }
            // The cookie domain is a subdomain of request domain, acccept
            return request_domain.chars().nth(index-1).unwrap() == '.';
        }
         
        return false;
    }

    /// Checks if the cookie can be used on this request
    pub fn request_match(&self, request_domain: &str, request_path: &str, secure: bool) -> bool {

        // Match Secure restrictions 

        if self.secure && !secure {
            return false;
        }        
    
        // Strict behaviour: it is only same-site if the domain is the same

        if self.same_site == SameSiteValue::Strict && self.domain != request_domain {
            return false;
        }

        // Lax behaviour: allow cross-site from subdomain to father domain
        if self.same_site() == SameSiteValue::Lax && !self.domain_match(request_domain) {
            return false;
        }

        // None: allow all cookies transfer but only it HTTPS is in use
        if self.same_site == SameSiteValue::None && ! self.secure {
            return false;
        }

        // PATH filtering

        return self.path_match(request_path);      
    }

     /// Parses a cookie value and modifiers from a 'Set-Cookie'header
    pub fn parse(s: &str, domain: &str, path: &str) ->  Result<Cookie, Error> {
    let mut components = s.split(';');
 
        return if let Some(slice) = components.next() {
            let (key, value) = parse_cookie_value(slice)?;
            let mut cookie = Cookie::new(key, value, String::from(domain), String::from(path));
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
                    CookieDirective::Domain(url) => {   // starting dot is ignored                      
                       cookie.domain = if let Some(stripped) = url.as_str().strip_prefix(".") {
                           String::from(stripped)
                       } else {
                           url
                       }    
                    },
                    CookieDirective::Path(path) => cookie.path = path,
                    CookieDirective::SameSite(val) => cookie.same_site = val,
                    CookieDirective::Secure => cookie.secure = true,
                    CookieDirective::HttpOnly => cookie.http_only = true,
                    CookieDirective::Extension(name, value) => {
                        let _res = cookie.extensions.insert(name, value);
                    }
                }
            }         
            Ok(cookie)
        } else {
            if CookieDirective::from_str(s).is_ok() {
                return Err(Error::new(ErrorKind::InvalidData, "Cookie has not got name/value"));
            };

            let (key, value) = parse_cookie_value(s)?;            
            Ok(Cookie::new(key, value, String::from(domain),  String::from(path)))
        }
    }
}

impl PartialEq for Cookie {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name 
    }    
}

impl Eq for Cookie{}

impl Hash for Cookie {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.domain.hash(state);
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
    HttpOnly,
    Extension(String, String)
}

// 
const DATE_FORMAT_850: &str= "(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|Mon|Tue|Wed|Thu|Fri|Sat|Sun), \
(0[1-9]|[123][0-9])-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-([0-9]{4}|[0-9]{2}) \
([0-1][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]) GMT";

// Regex for dates Sun, 06 Nov 1994 08:49:37 GMT
const DATE_FORMAT_1123: &str= "(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \
(0[1-9]|[123][0-9]) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9]{4}) \
([0-1][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]) GMT";


// Regex for dates Sun Nov 6 08:49:37 1994 
const DATE_FORMAT_ASCT: &str= "(Mon|Tue|Wed|Thu|Fri|Sat|Sun) \
(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[ ]{1,2}([1-9]|0[1-9]|[123][0-9]) \
([0-1][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]) ([0-9]{4})";

/// Parses RFC 850 dates, with extension. 
/// For example,  `Wed, 15-Nov-23 09:13:29 GMT` and  `Wed, 15-Nov-23 09:13:29 GMT` 
/// or `Sunday, 06-Nov-94 08:49:37 GMT` dates.
fn parse_rfc_850_date(date: &str) -> Result<SystemTime, Error> {
    lazy_static! {
        static ref RE: Regex = Regex::new(DATE_FORMAT_850).unwrap();
    }

    
    if let Some(captures) = RE.captures(date) {
        // Capture 0 is the full match and  1 is the day of the week name
        let day : u32 = captures.get(2).unwrap().as_str().parse().unwrap();
        let month = match captures.get(3).unwrap().as_str() {
            "Jan" => 1,
            "Feb" => 2,
            "Mar" => 3,
            "Apr" => 4,
            "May" => 5,
            "Jun" => 6,
            "Jul" => 7,
            "Aug" => 8,
            "Sep" => 9,
            "Oct" => 10,
            "Nov" => 11,
            "Dec" => 12,
            _ => return Err(Error::new(ErrorKind::InvalidData, "Invalid date"))
        };

        let mut year: i32 = captures.get(4).unwrap().as_str().parse().unwrap();
        // Fix millenium, for 2 digit year
        year+= if year < 70 {2000} else if year < 100 {1900} else {0};

        let hour : u32 = captures.get(5).unwrap().as_str().parse().unwrap();
        let min : u32 = captures.get(6).unwrap().as_str().parse().unwrap();
        let secs : u32 = captures.get(7).unwrap().as_str().parse().unwrap();

        let naive =
            NaiveDate::from_ymd(year, month, day)
            .and_hms(hour,min,secs);
        let time = DateTime::<Utc>::from_utc(naive, Utc);
        let millis = Duration::from_millis(time.timestamp_millis() as u64);
        let time = UNIX_EPOCH.clone().add(millis);

        return Ok(time);


    } else {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid date"));
    }
}

/// Parses RFC 1123 dates. 
/// For example,  `Sun, 06 Nov 1994 08:49:37 GMT` date.
fn parse_rfc_1123_date(date: &str) -> Result<SystemTime, Error> {
    lazy_static! {
        static ref RE: Regex = Regex::new(DATE_FORMAT_1123).unwrap();
    }

    
    if let Some(captures) = RE.captures(date) {
        // Capture 0 is the full match and  1 is the day of the week name
        let day : u32 = captures.get(2).unwrap().as_str().parse().unwrap();
        let month = match captures.get(3).unwrap().as_str() {
            "Jan" => 1,
            "Feb" => 2,
            "Mar" => 3,
            "Apr" => 4,
            "May" => 5,
            "Jun" => 6,
            "Jul" => 7,
            "Aug" => 8,
            "Sep" => 9,
            "Oct" => 10,
            "Nov" => 11,
            "Dec" => 12,
            _ => return Err(Error::new(ErrorKind::InvalidData, "Invalid date"))
        };

        let year: i32 = captures.get(4).unwrap().as_str().parse().unwrap();

        let hour : u32 = captures.get(5).unwrap().as_str().parse().unwrap();
        let min : u32 = captures.get(6).unwrap().as_str().parse().unwrap();
        let secs : u32 = captures.get(7).unwrap().as_str().parse().unwrap();

        let naive =
            NaiveDate::from_ymd(year, month, day)
            .and_hms(hour,min,secs);
        let time = DateTime::<Utc>::from_utc(naive, Utc);
        let millis = Duration::from_millis(time.timestamp_millis() as u64);
        let time = UNIX_EPOCH.clone().add(millis);

        return Ok(time);


    } else {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid date"));
    }
}

/// Parses Asct dates, with extension. 
/// For example,  `Sun Nov 6 08:49:37 1994` dates.
fn parse_asct_date(date: &str) -> Result<SystemTime, Error> {
    lazy_static! {
        static ref RE: Regex = Regex::new(DATE_FORMAT_ASCT).unwrap();
    }

    
    if let Some(captures) = RE.captures(date) {
        // Capture 0 is the full match and  1 is the day of the week name
        let month = match captures.get(2).unwrap().as_str() {
            "Jan" => 1,
            "Feb" => 2,
            "Mar" => 3,
            "Apr" => 4,
            "May" => 5,
            "Jun" => 6,
            "Jul" => 7,
            "Aug" => 8,
            "Sep" => 9,
            "Oct" => 10,
            "Nov" => 11,
            "Dec" => 12,
            _ => return Err(Error::new(ErrorKind::InvalidData, "Invalid date"))
        };

        let day : u32 = captures.get(3).unwrap().as_str().parse().unwrap();
        
        let hour : u32 = captures.get(4).unwrap().as_str().parse().unwrap();
        let min :  u32 = captures.get(5).unwrap().as_str().parse().unwrap();
        let secs : u32 = captures.get(6).unwrap().as_str().parse().unwrap();

        let year: i32 = captures.get(7).unwrap().as_str().parse().unwrap();
       
        let naive =
            NaiveDate::from_ymd(year, month, day)
            .and_hms(hour,min,secs);
        let time = DateTime::<Utc>::from_utc(naive, Utc);
        let millis = Duration::from_millis(time.timestamp_millis() as u64);
        let time = UNIX_EPOCH.clone().add(millis);

        return Ok(time);


    } else {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid date"));
    }
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
                    let expires = parse_rfc_1123_date(value)
                        .or_else(|_| parse_rfc_850_date(value))
                        .or_else(|_| parse_asct_date(value))?; 

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
                _ => Ok(CookieDirective::Extension(key, value.to_string()))
            }
        } else {
            match s.trim().to_ascii_lowercase().as_str() {
                COOKIE_SECURE => Ok(CookieDirective::Secure),
                COOKIE_HTTP_ONLY => Ok(CookieDirective::HttpOnly),
                _ => return Err(
                    Error::new(ErrorKind::InvalidData,
                            format!("Invalid HTTP cookie directive: {}", s)))
            }
        }
    }
}

/// Cookies repository trait. Keeps active cookies from a session.
pub trait CookieJar {
    /// Adds a cookie to the jar, if 'value' has no 'domain' member, 'request_domain' is used
    fn cookie(&mut self, value: Cookie, request_domain: &str);

    /// Gets the active cookie name/value list for the given domain (expired are deleted)
    fn active_cookies(&mut self, request_domain: &str, request_path: &str, secure: bool) -> Vec<(String, String)>;
 }


 pub struct MemCookieJar {
    // Hash set of cookies by target domain
    cookies: HashSet<Cookie>
 }

 impl MemCookieJar {
     pub fn new() -> MemCookieJar{
        MemCookieJar {
            cookies: HashSet::new()
        }
     }
 }

 
 impl CookieJar for MemCookieJar {
    fn cookie(&mut self, value: Cookie, request_domain: &str) {

        if !value.domain_match(request_domain) {
            return; // Discard different domain
        } 
        let now =  SystemTime::now();

        if let Some(expires) = value.expires() {
            if expires < now {
                return; // Discard expired 
            }
        }
       
        self.cookies.insert(value);
    }

    fn active_cookies(&mut self, request_domain: &str, request_path: &str, secure: bool) -> Vec<(String, String)> {
        
        let mut result = Vec::new();

        // First clean expired cookies
        let now =  SystemTime::now();

        self.cookies.retain( |c| {
            if let Some(time) = c.expires {
                return time < now;
            }
            return true;
        });
                
        for cookie in self.cookies.iter() {
            if cookie.request_match(request_domain, request_path, secure) {
                result.push((cookie.name.clone(), cookie.value.clone()));
            }
        }

        return result;
    }
 }

#[cfg(test)]
mod cookie_test;