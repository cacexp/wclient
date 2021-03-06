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

use std::path::PathBuf;
use crate::*;
use crate::config::*;
use crate::http::parse_url;
use crate::constants::*;
use json::*;

use env_logger;
use log::LevelFilter;

fn init() {
    let _ = env_logger::builder().filter_level(LevelFilter::Error).try_init();
}

#[test]
fn build_simple_request() {
    let request = RequestBuilder::get("http://web.myservice.com").build();

    assert_eq!("http://web.myservice.com", request.url.as_str());
    assert_eq!(HttpMethod::GET, request.method);
}

#[test]
fn request_header_1() {
    let request = RequestBuilder::get("http://web.myservice.com")
        .header(ACCEPT, CONTENT_TYPE_JSON)
        .build();
    
    assert_eq!(HttpMethod::GET, request.method);
    assert_eq!(&CONTENT_TYPE_JSON, request.headers.get("accept").unwrap())
}

#[test]
fn request_header_2() {
    // Test Request Headers are case insensitive, insert twice same header with
    // different case sensitive names
    let request = RequestBuilder::get("http://web.myservice.com")
        .header(ACCEPT, CONTENT_TYPE_JSON)
        .header("accept", "text")
        .build();

    assert_eq!(HttpMethod::GET, request.method);
    assert_eq!(&"text", request.headers.get(ACCEPT).unwrap());
}


#[test]
fn request_cookie_1() {
    let request =
        RequestBuilder::get("http://web.myservice.com")
        .cookie("name", "1234")
        .build();

    assert_eq!(HttpMethod::GET, request.method);
    assert_eq!(&"1234", request.cookies.get("name").unwrap());
}

#[test]
fn request_cookie_2() {
    // Test Request cookie names are case sensitive, insert twice same cookie with
    // different case sensitive names
    let request =
        RequestBuilder::get("http://web.myservice.com")
        .cookie("name", "0000")
        .cookie("name", "1234")
        .build();

    assert_eq!(HttpMethod::GET, request.method);
    assert_eq!(&"1234", request.cookies.get("name").unwrap());
}


#[test]
fn build_request_1() {
    let request = RequestBuilder::get("http://web.myservice.com")
        .header(ACCEPT, CONTENT_TYPE_JSON)
        .param("id", "12345")
        .build();

    assert_eq!(HttpMethod::GET, request.method);
    assert_eq!(&CONTENT_TYPE_JSON, request.headers.get(ACCEPT).unwrap())
}


#[test]
fn build_request_2() {
    let data = object! {
        name: "John",
        surname: "Smith"
    };

    let request = RequestBuilder::post("http://web.myservice.com/user")
        .header(ACCEPT, CONTENT_TYPE_JSON)
        .param("id", "12345")
        .json(&data)
        .build();
    
    assert_eq!(HttpMethod::POST, request.method);
    assert_eq!(&CONTENT_TYPE_JSON, request.headers.get(ACCEPT).unwrap());

}


#[test]
fn test_url_ok1() {
    assert!(parse_url("http://web.myservice.com/user").is_ok());
}

#[test]
fn test_url_ok2() {
    assert!(parse_url("Http://web.myservice.com/user").is_ok());
} 

#[test]
fn test_url_ok3() {
    assert!(parse_url("HTTP://WEB.MYSERVICE.COM/user").is_ok());
} 

#[test]
fn test_url_ok4() {
    assert!(parse_url("https://web.myservice.com/user").is_ok());
}

#[test]
fn test_url_nok1() {
    assert!(parse_url("ftp://web.myservice.com/user").is_err());
}

#[test]
fn test_echo1() {
    let mut request =
        RequestBuilder::get("http://localhost:8080/user").build();
    
    let response = request.send();

    assert!(response.is_ok());
    assert_eq!(response.unwrap().status_code, 200);
}

#[test]
fn test_echo2() {
    init();

    let data = object! {
        name: "John",
        surname: "Smith"
    };

    let mut request = RequestBuilder::get("http://localhost:8080/user")
        .header(ACCEPT, CONTENT_TYPE_JSON)
        .json(&data)
        .build();

    let result = request.send();

    assert!(result.is_ok());

    let response = result.unwrap();

    assert_eq!(response.status_code, 200);

    let result_json = response.json();

    assert!(result_json.is_ok());

    let result_data = result_json.unwrap();

    assert_eq!(result_data.has_key("json"), true);

    assert_eq!(result_data["json"], data);

    println!("{:?}", result_data["json"].as_str() )

}

#[test]
fn test_ip() {

    init();
    let mut request =  RequestBuilder::get("http://ip-api.com/json/")
    .header(ACCEPT, CONTENT_TYPE_JSON)
    .param("fields", "24576")
    .build();

    let result = request.send();

    if let Some(e) = result.as_ref().err(){
        println!("{}", e);
    }

    assert!(result.is_ok());

    let response = result.unwrap();

    assert_eq!(response.status_code, 200);

    assert_eq!(response.headers()[CONTENT_TYPE], "application/json; charset=utf-8");

    let result_json = response.json();

    if let Some(e) = result_json.as_ref().err(){
        println!("{}", e);
    }

    assert!(result_json.is_ok());

    let result_data = result_json.unwrap();

    assert!(result_data.has_key("status"));
    assert_eq!(result_data["status"], "success");
    assert_eq!(result_data.has_key("query"), true);

}

use std::result::Result;
use std::io::Error;

fn request_boreapy_with_config(config: &HttpConfig) -> Result<Response, Error> {
    RequestBuilder::get("https://www.boredapi.com/api/activity")
        .header(ACCEPT, CONTENT_TYPE_JSON)
        .param("participants", "2")
        .config(&config)
        .build()
        .send()
}

fn request_local_with_config(config: &HttpConfig) -> Result<Response, Error> {
    return RequestBuilder::get("https://localhost:4443/auth/auth.json")
        .header(ACCEPT, "*/*")
        .config(&config)
        .build()        
        .send()
}

fn http_boreapy_ok(result: Result<Response, Error>) {
    if let Some(e) = result.as_ref().err(){
        println!("{}", e);
    }

    assert!(result.is_ok());

    let response = result.unwrap();

    assert_eq!(response.status_code, 200);

    let body = String::from_utf8(response.body().clone());

    assert!(body.is_ok());

    assert_eq!(response.headers()[CONTENT_TYPE], "application/json; charset=utf-8");

    let result_json = response.json();

    if let Some(e) = result_json.as_ref().err(){
        println!("{}", e);
    }

    assert!(result_json.is_ok());

    let result_data = result_json.unwrap();

    assert!(result_data.has_key("activity"));

}

fn http_local_ok(result: Result<Response, Error>) {
    if let Some(e) = result.as_ref().err(){
        println!("{}", e);
    }

    assert!(result.is_ok());

    let response = result.unwrap();

    assert_eq!(response.status_code, 200);

    let body = String::from_utf8(response.body().clone());

    assert!(body.is_ok());

    let result_json = response.json();

    if let Some(e) = result_json.as_ref().err(){
        println!("{}", e);
    }

    assert!(result_json.is_ok());

    let result_data = result_json.unwrap();

    assert!(result_data.has_key("auth"));

}

#[test]
fn test_https_default() {

    init();

    let config = HttpConfigBuilder::default().build();

    let result = request_boreapy_with_config(&config);

    http_boreapy_ok(result);
  

}

#[test]
fn test_https_custom_server_ca() {

    init();

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("test_resources/server_certs");

    let config = HttpConfigBuilder::default()
        .verify(HttpsVerify::Path(String::from(path.as_path().to_str().unwrap())))
        .build();

    let result = request_boreapy_with_config(&config);

    http_boreapy_ok(result);

}

#[test]
fn test_https_custom_server_ca_file() {

    init();

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("test_resources/server_certs/lets-encrypt-r3.pem");

    let config = HttpConfigBuilder::default()
        .verify(HttpsVerify::Path(String::from(path.as_path().to_str().unwrap())))
        .build();

    let result = request_boreapy_with_config(&config);

    http_boreapy_ok(result);

}

#[test]
fn test_https_custom_server_ca_file2() {

    init();

    let mut ca_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    ca_path.push("test_resources/test-ca/ca.crt");
    let ca = String::from(ca_path.to_str().unwrap());

    let config = HttpConfigBuilder::default()
        .verify(HttpsVerify::Path(ca))
        .build();

    let result = request_local_with_config(&config);

    http_local_ok(result);

}

#[test]
fn test_https_client_cert1() {

    init();

    let mut cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cert_path.push("test_resources/test-ca/full_client.crt");

    let cert = String::from(cert_path.to_str().unwrap());

    let mut key_path =  PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    key_path.push("test_resources/test-ca/client.key");

    let key = String::from(key_path.to_str().unwrap());
    let config = HttpConfigBuilder::default()
        .cert(HttpsCert::CertKey{cert,key})
        .build();

    let result = request_local_with_config(&config);

    http_local_ok(result);

}


#[test]
fn test_https_wrong_client_cert1() {

    init();

    let mut cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cert_path.push("test_resources/other-ca/full_client.crt");

    let cert = String::from(cert_path.to_str().unwrap());

    let mut key_path =  PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    key_path.push("test_resources/other-ca/client.key");

    let key = String::from(key_path.to_str().unwrap());

    let config = HttpConfigBuilder::default()
        .cert(HttpsCert::CertKey{cert,key})
        .build();

    let result = request_local_with_config(&config);

    assert!(result.is_err());

    let error = result.err().unwrap();
    
    println!("{}", &error);

}

#[test]
fn test_https_wrong_server_ca() {

    init();

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("test_resources/wrong_server_certs");

    let config = HttpConfigBuilder::default()
        .verify(HttpsVerify::Path(String::from(path.as_path().to_str().unwrap())))
        .build();

    let result = request_boreapy_with_config(&config);

    assert!(result.is_err());
    
    println!("{}", result.err().unwrap());

}

#[test]
fn test_https_wrong_server_ca_file() {

    init();

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("test_resources/wrong_server_certs/DigiCertAssuredIDRootCA.crt.pem");

    let config = HttpConfigBuilder::default()
        .verify(HttpsVerify::Path(String::from(path.as_path().to_str().unwrap())))
        .build();

    let result = request_boreapy_with_config(&config);

    assert!(result.is_err());
    
    println!("{}", result.err().unwrap());

}


#[test]
#[cfg(feature = "dangerous_configuration")]
fn test_https_no_verify() {

    init();

    let config = HttpConfigBuilder::default()
        .verify(HttpsVerify::False)
        .build();

    let result = request_boreapy_with_config(&config);

    http_boreapy_ok(result);
  

}


#[test]
fn test_session() {

    init();

    let session = SessionBuilder::new()
        .build();

    let mut request1 = session.get("https://en.wikipedia.org")
        .header("Accept", "identity")
        .build();

    let response1 = request1.send();
    
    assert!(response1.is_ok());

    let cookies1 = session.jar.lock().unwrap().active_cookies("en.wikipedia.org", "/", true);

    assert_eq!(cookies1.len(),1);

    let cookies2 = session.jar.lock().unwrap().active_cookies("wikipedia.org", "/", true);

    assert_eq!(cookies2.len(),1);
 
}

#[test]
fn test_session_connections1() {

    init();

    let session = SessionBuilder::new()
        .build();

    
    let mut request1 = session.get("https://en.wikipedia.org")
        .header("Accept", "identity")
        .build();

    let response1 = request1.send();
    
    assert!(response1.is_ok());

    let mut request2 = session.get("https://en.wikipedia.org")
        .header("Accept", "identity")
        .build();

    let response2 = request2.send();
    
    assert!(response2.is_ok());
}

#[test]
 fn test_basic_auth_1() {
     init();
     let manager = Arc::new(Mutex::new(crate::auth::HttpBasicAuth::new("wclient", "user,1234")));
     let mut request = RequestBuilder::get("http://localhost:8000/users/12/")
        .auth(manager)
        .build();

     let response = request.send();

     assert!(response.is_ok());

     let not_auth = response.unwrap();

     assert_eq!(not_auth.status_code(), 200);

 }

 #[test]
 fn test_session_basic_auth_1() {
    init();
    let mut ca_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    ca_path.push("test_resources/test-ca/ca.crt");
    let ca = String::from(ca_path.to_str().unwrap());

    let config = HttpConfigBuilder::default()
        .verify(HttpsVerify::Path(ca))
        .build();

     let manager = Arc::new(Mutex::new(crate::auth::HttpBasicAuth::new("wclient", "user,1234")));

     let session = SessionBuilder::new()
        .auth(manager)
        .config(&config)
        .build(); 

     let mut request = session.get("https://localhost:4443/users/12/").build();

     let response = request.send();

     assert!(response.is_ok());

     let not_auth = response.unwrap();

     assert_eq!(not_auth.status_code(), 200);

 }

 #[test]
 fn test_basic_auth_err_1() {
     let mut request = RequestBuilder::get("http://localhost:8000/users/12/").build();
     let response = request.send();

     assert!(response.is_ok());

     let not_auth = response.unwrap();

     assert_eq!(not_auth.status_code(), 401);

 }

#[test]
fn test_basic_wrong_2() {
    let manager = Arc::new(Mutex::new(crate::auth::HttpBasicAuth::new("wclient", "1234")));

    let mut request = RequestBuilder::get("http://localhost:8000/users/12/")
        .auth(manager.clone())
        .build();

    let response = request.send();

    assert!(response.is_ok());

    let not_auth = response.unwrap();

    assert_eq!(not_auth.status_code(), 401);

}