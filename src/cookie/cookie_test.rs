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

const TEST_DOMAIN: &str = "test.com";
const TEST_SUBDOMAIN: &str = "www.test.com";
const TEST_OTHER_DOMAIN: &str = "test.es";
const TEST_DOT_DOMAIN: &str = "est.com";
const TEST_ROOT_PATH: &str = "/";
const TEST_PATH: &str = "/users/";
const TEST_SUBPATH: &str = "/users/private";
const TEST_OTHER_PATH: &str = "/public";

const TEST_COOKIE_2: &str = "cookie2=222222; Secure";
const TEST_COOKIE_3: &str = "cookie3=3333222; SameSite=None; Secure";

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
    let right = "Expires=Sun, 06 Nov 1994 08:49:37 GMT";
    let result = CookieDirective::from_str(right);

    assert!(result.is_ok());

    if let CookieDirective::Expires(date) = result.unwrap() {
        let naive =
            NaiveDate::from_ymd(1994,11,6)
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
fn test_parse_cookie_expires_right2() {
    let right = "Expires=Sunday, 06-Nov-1994 08:49:37 GMT";
    let result = CookieDirective::from_str(right);
   
    assert!(result.is_ok());

    if let CookieDirective::Expires(date) = result.unwrap() {
        let naive =
            NaiveDate::from_ymd(1994,11,6)
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
    let right = "Expires=Sun Nov 6 08:49:37 1994";
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
fn test_parse_cookie_expires_right4() {
    let right = "Expires=Wed, 15-Nov-2023 09:13:29 GMT";
    let result = CookieDirective::from_str(right);

    if result.is_err() {
        println!("{}", result.as_ref().err().unwrap());
    }
    assert!(result.is_ok());

    if let CookieDirective::Expires(date) = result.unwrap() {
        let naive =
            NaiveDate::from_ymd(2023,11,15)
            .and_hms(9,13,29);
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
    let right = "Expires=21 October 2015 07:28:00 +0200";
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

fn test_cookie_path(creator_path: &str, target_path: &str, success: bool) {
    
    let mut jar = MemCookieJar::new();

    let cookie1 = Cookie::parse(format!("cookie1=122343; Path= {}", creator_path).as_str(), TEST_DOMAIN, creator_path);
        
    assert!(cookie1.is_ok());

    jar.cookie(cookie1.unwrap(), TEST_DOMAIN);

    let cookies = jar.active_cookies(TEST_DOMAIN, target_path, true);

    if success {
        assert_eq!(cookies.len(), 1);

        assert_eq!(cookies.get(0).unwrap().0, "cookie1");
        assert_eq!(cookies.get(0).unwrap().1, "122343");
    } else {
        assert_eq!(cookies.len(), 0);
    }
}

#[test]
fn test_mem_cookie_jar_path1() {
    test_cookie_path(TEST_SUBPATH, TEST_OTHER_PATH, false);    
}

#[test]
fn test_mem_cookie_jar_path2() {
    test_cookie_path(TEST_PATH, TEST_SUBPATH, true);
}

#[test]
fn test_mem_cookie_jar_path3(){
    test_cookie_path(TEST_SUBPATH,TEST_PATH, false);
}

#[test]
fn test_mem_cookie_jar_path4() {
    test_cookie_path(TEST_SUBPATH, TEST_OTHER_PATH, false);    
}

#[test]
fn test_cookie_match1() {
    let cookie1 = Cookie::parse("cookie1=122343; Domain=b.a", "b.a", "/");
    assert!(cookie1.is_ok());
    assert!(cookie1.unwrap().domain_match("b.a"));
}

#[test]
fn test_cookie_match2() {
    let cookie1 = Cookie::parse("cookie1=122343; Domain=b.a", "b.a", "/");
    assert!(cookie1.is_ok());
    assert!(cookie1.unwrap().domain_match("c.b.a"));
}

#[test]
fn test_cookie_match3() {
    let cookie1 = Cookie::parse("cookie1=122343; Domain=b.a", "b.a", "/");
    assert!(cookie1.is_ok());
    assert!(cookie1.unwrap().domain_match("d.c.b.a"));
}

#[test]
fn test_cookie_match4() {
    let cookie1 = Cookie::parse("cookie1=122343; Domain=b.a", "b.a", "/");
    assert!(cookie1.is_ok());
    assert!(!cookie1.unwrap().domain_match("xb.a"));
}
#[test]
fn test_cookie_match5() {
    let cookie1 = Cookie::parse("cookie1=122343; Domain=b.a", "b.a", "/");
    assert!(cookie1.is_ok());
    assert!(!cookie1.unwrap().domain_match("x.a"));
}

#[test]
fn test_cookie_match6() {
    let cookie1 = Cookie::parse("cookie1=122343; Domain=c.b.a", "b.a", "/");
    assert!(cookie1.is_ok());
    assert!(!cookie1.unwrap().domain_match("b.a"));
}

fn test_cookie_domain(init_request_domain: &str, init_cookie_domain: &str, target_domain: &str, success: bool) {
    let mut jar = MemCookieJar::new();

    let cookie1 = Cookie::parse(format!("cookie1=122343; Domain={}", init_cookie_domain).as_str(), init_request_domain, TEST_PATH);

    assert!(cookie1.is_ok());

    jar.cookie(cookie1.unwrap(), init_request_domain);

    let cookies = jar.active_cookies(target_domain, TEST_PATH, false);

    // Cookie is discarded as the request is not secure
    assert_eq!(cookies.len(), if success {1} else {0}, "Cookie create by {}, with domain {} for target {}", init_request_domain, init_cookie_domain, target_domain);

}

#[test]
fn test_mem_cookie_domain1() {
    test_cookie_domain(TEST_DOMAIN, TEST_DOMAIN, TEST_DOMAIN, true);
}

#[test]
fn test_mem_cookie_domain2() {
    test_cookie_domain(TEST_SUBDOMAIN, TEST_DOMAIN, TEST_DOMAIN , true);
}

#[test]
fn test_mem_cookie_domain3() {
    test_cookie_domain(TEST_SUBDOMAIN, TEST_SUBDOMAIN, TEST_DOMAIN, false);
}

#[test]
fn test_mem_cookie_domain4() {
    test_cookie_domain(TEST_DOMAIN, TEST_SUBDOMAIN, TEST_SUBDOMAIN, false);
}

#[test]
fn test_mem_cookie_domain5() {
    test_cookie_domain(TEST_DOMAIN, TEST_DOMAIN, TEST_SUBDOMAIN, true);
}

#[test]
fn test_mem_cookie_domain6() {
    test_cookie_domain(TEST_DOMAIN, TEST_DOMAIN, TEST_OTHER_DOMAIN, false);
}
