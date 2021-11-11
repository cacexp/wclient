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

use crate::cookie::*;
use std::io::ErrorKind;
use chrono::{DateTime, Utc, NaiveDate};
use std::time::{UNIX_EPOCH, Duration};
use std::ops::Add;

macro_rules! assert_invalid_data {
    ($a: expr) => {
        assert!($a.is_err());

        let error = $a.err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    };
    ($a: expr, $b: expr) => {
        assert!($a.is_err());

        let error = $a.err().unwrap();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert_eq!(error.to_string(), $b);
    };
}

#[test]
fn test_parse_cookie_value_right1() {
    let right = "name=value";
    let result = parse_cookie_value(right);

    assert!(result.is_ok());

    let (key, value) = result.unwrap();

    assert_eq!(key.as_str(), "name");
    assert_eq!(value.as_str(), "value");
}

#[test]
fn test_parse_cookie_value_right2() {
    let right = "  name=value";
    let result = parse_cookie_value(right);

    assert!(result.is_ok());

    let (key, value) = result.unwrap();

    assert_eq!(key.as_str(), "name");
    assert_eq!(value.as_str(), "value");
}

#[test]
fn test_parse_cookie_value_right3() {
    let right = "  name=value ";
    let result = parse_cookie_value(right);

    assert!(result.is_ok());

    let (key, value) = result.unwrap();

    assert_eq!(key.as_str(), "name");
    assert_eq!(value.as_str(), "value");
}

#[test]
fn test_parse_cookie_value_right4() {
    let right = "  name=value ";
    let result = parse_cookie_value(right);

    assert!(result.is_ok());

    let (key, value) = result.unwrap();

    assert_eq!(key.as_str(), "name");
    assert_eq!(value.as_str(), "value");
}

#[test]
fn test_parse_cookie_value_wrong1() {
    let wrong = "name:value";
    let wrong_message = format!("Malformed HTTP cookie: {}", wrong);

    let result = parse_cookie_value(wrong);

    assert_invalid_data!(result, wrong_message);
}

#[test]
fn test_parse_cookie_value_wrong2() {
    let wrong = "name";
    let wrong_message = format!("Malformed HTTP cookie: {}", wrong);

    let result = parse_cookie_value(wrong);

    assert_invalid_data!(result, wrong_message);
}

#[test]
fn test_parse_cookie_samesite_right1() {
    let right = "SameSite=Strict";
    let result = CookieDirective::from_str(right);

    assert!(result.is_ok());

    let directive = result.unwrap();

    if let CookieDirective::SameSite(value) = directive {
        assert_eq!(value, SameSiteValue::Strict);
    } else {
        assert!(false, "Expected CookieDirective::SameSite");
    }
}

#[test]
fn test_parse_cookie_samesite_right2() {
    let right = "SameSite=Lax";
    let result = CookieDirective::from_str(right);

    assert!(result.is_ok());

    let directive = result.unwrap();

    if let CookieDirective::SameSite(value) = directive {
        assert_eq!(value, SameSiteValue::Lax);
    } else {
        assert!(false, "Expected CookieDirective::SameSite");
    }
}

#[test]
fn test_parse_cookie_samesite_right3() {
    let right = "SameSite=None";
    let result = CookieDirective::from_str(right);

    assert!(result.is_ok());

    let directive = result.unwrap();

    if let CookieDirective::SameSite(value) = directive {
        assert_eq!(value, SameSiteValue::None);
    } else {
        assert!(false, "Expected CookieDirective::SameSite");
    }
}

#[test]
fn test_parse_cookie_samesite_right4() {
    let right = "SameSite=lax";
    let result = CookieDirective::from_str(right);

    assert!(result.is_ok());

    let directive = result.unwrap();

    if let CookieDirective::SameSite(value) = directive {
        assert_eq!(value, SameSiteValue::Lax);
    } else {
        assert!(false, "Expected CookieDirective::SameSite");
    }
}

#[test]
fn test_parse_cookie_samesite_right5() {
    let right = "sameSite=Lax";
    let result = CookieDirective::from_str(right);

    assert!(result.is_ok());

    let directive = result.unwrap();

    if let CookieDirective::SameSite(value) = directive {
        assert_eq!(value, SameSiteValue::Lax);
    } else {
        assert!(false, "Expected CookieDirective::SameSite");
    }
}

#[test]
fn test_parse_cookie_samesite_wrong1() {
    let right = "SameSite=Void";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}

#[test]
fn test_parse_cookie_samesite_wrong2() {
    let right = "SameSite";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}

#[test]
fn test_parse_cookie_samesite_wrong3() {
    let right = "SameSite:Lax";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}

#[test]
fn test_parse_cookie_samesite_wrong4() {
    let right = "SameSite=";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}

#[test]
fn test_parse_cookie_expires_right1() {
    let right = "Expires=Wed, 21 Oct 2015 07:28:00 GMT";
    let result = CookieDirective::from_str(right);

    assert!(result.is_ok());

    if let CookieDirective::Expires(date) = result.unwrap() {
        let naive =
            NaiveDate::from_ymd(2015,10,21)
            .and_hms(7,28,0);
        let time = DateTime::<Utc>::from_utc(naive, Utc);
        let millis = Duration::from_millis(time.timestamp_millis() as u64);
        let expired = UNIX_EPOCH.clone().add(millis);
        assert_eq!(date,expired);
    } else {
        assert!(false, "Expected CookieDirective::Expires")
    }
}

#[test]
fn test_parse_cookie_expires_right2() {
    let right = "Expires=Sunday, 06-Nov-94 08:49:37 GMT";
    let result = CookieDirective::from_str(right);
   
    assert!(result.is_ok());

    if let CookieDirective::Expires(date) = result.unwrap() {
        let naive =
            NaiveDate::from_ymd(1994,11,06)
            .and_hms(8,49,37);
        let time = DateTime::<Utc>::from_utc(naive, Utc);
        let millis = Duration::from_millis(time.timestamp_millis() as u64);
        let expired = UNIX_EPOCH.clone().add(millis);
        assert_eq!(date,expired);
    } else {
        assert!(false, "Expected CookieDirective::Expires")
    }
}

#[test]
fn test_parse_cookie_expires_right3() {
    let right = "Expires=Sun Nov  6 08:49:37 1994";
    let result = CookieDirective::from_str(right);

    if result.is_err() {
        println!("{}", result.as_ref().err().unwrap());
    }
    assert!(result.is_ok());

    if let CookieDirective::Expires(date) = result.unwrap() {
        let naive =
            NaiveDate::from_ymd(1994,11,06)
            .and_hms(8,49,37);
        let time = DateTime::<Utc>::from_utc(naive, Utc);
        let millis = Duration::from_millis(time.timestamp_millis() as u64);
        let expired = UNIX_EPOCH.clone().add(millis);
        assert_eq!(date,expired);
    } else {
        assert!(false, "Expected CookieDirective::Expires")
    }
}

#[test]
fn test_parse_cookie_expires_wrong1() {
    let right = "Expires=21 Octubre 2015 07:28:00 UTC";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}

#[test]
fn test_parse_cookie_expires_wrong2() {
    let right = "Expires=21 Octubre 2015 07:28:00 +0200";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}

#[test]
fn test_parse_cookie_expires_wrong3() {
    let right = "Expires=Sunday, 06-Nov-94 08:49:37 UTC";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}
#[test]
fn test_parse_cookie_expires_wrong4() {
    let right = "Expires=Sunday, 06-Nov-94 08:49:37 +0200";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}
#[test]
fn test_parse_cookie_expires_wrong5() {
    let right = "Expires=Sun, 06-Nov-94 08:49:37 GMT";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}

#[test]
fn test_parse_cookie_max_age_right1() {
    let right = "Max-Age=3600";
    let result = CookieDirective::from_str(right);

    assert!(result.is_ok());

    if let CookieDirective::MaxAge(seconds) = result.unwrap() {
        assert_eq!(seconds, Duration::from_secs(3600));
    } else {
        panic!()
    }
}

#[test]
fn test_parse_cookie_max_age_right2() {
    let right = "Max-Age=0";
    let result = CookieDirective::from_str(right);

    assert!(result.is_ok());

    if let CookieDirective::MaxAge(seconds) = result.unwrap() {
        assert_eq!(seconds, Duration::from_secs(0));
    } else {
        panic!()
    }
}

#[test]
fn test_parse_cookie_max_age_right3() {
    let right = "max-Age=1200";  // attributes are case-insensitive
    let result = CookieDirective::from_str(right);

    assert!(result.is_ok());

    if let CookieDirective::MaxAge(seconds) = result.unwrap() {
        assert_eq!(seconds, Duration::from_secs(1200));
    } else {
        panic!()
    }
}


#[test]
fn test_parse_cookie_max_age_wrong1() {
    let right = "Max-Age=21 Octubre 2015 07:28:00 UTC";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}

#[test]
fn test_parse_cookie_max_age_wrong2() {
    let right = "Max-Age=-1200";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}

#[test]
fn test_parse_cookie_max_age_wrong3() {
    let right = "Max-Age";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}

#[test]
fn test_parse_cookie_max_age_wrong5() {
    let right = "Max-Age=1A200";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}

#[test]
fn test_parse_cookie_domain_right1() {
    let right = "Domain=example.com";  // attributes are case-insentitive
    let result = CookieDirective::from_str(right);

    assert!(result.is_ok());
}

#[test]
fn test_parse_cookie_domain_right2() {
    let right = "domain=example.com";  // attributes are case-insentitive
    let result = CookieDirective::from_str(right);

    assert!(result.is_ok());
}

#[test]
fn test_parse_cookie_domain_wrong1() {
    let right = "Domain:example.com";
    let result = CookieDirective::from_str(right);

    assert_invalid_data!(result);
}
