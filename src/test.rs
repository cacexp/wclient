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

use crate::*;
use crate::http::parse_url;
use crate::constants::*;
use json::*;

use env_logger;
use log::LevelFilter;

fn init() {
    let _ = env_logger::builder().filter_level(LevelFilter::Debug).try_init();
}

#[test]
fn build_simple_request() {
    let request = RequestBuilder::get("Http://web.myservice.com").build();
    assert_eq!("Http://web.myservice.com", request.url);
    assert_eq!(HttpMethod::GET, request.method);
}

#[test]
fn request_header_1() {
    let request = RequestBuilder::get("Http://web.myservice.com")
        .header(ACCEPT, CONTENT_TYPE_JSON)
        .build();

    assert_eq!(HttpMethod::GET, request.method);
    assert_eq!(&CONTENT_TYPE_JSON, request.headers.get("accept").unwrap())
}

#[test]
fn request_header_2() {
    // Test Request Headers are case insensitive, insert twice same header with
    // different case sensitive names
    let request = RequestBuilder::get("Http://web.myservice.com")
        .header(ACCEPT, CONTENT_TYPE_JSON)
        .header("accept", "text")
        .build();

    assert_eq!(HttpMethod::GET, request.method);
    assert_eq!(&"text", request.headers.get(ACCEPT).unwrap());
}


#[test]
fn request_cookie_1() {
    let request =
        RequestBuilder::get("Http://web.myservice.com")
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
        RequestBuilder::get("Http://web.myservice.com")
        .cookie("name", "0000")
        .cookie("name", "1234")
        .build();

    assert_eq!(HttpMethod::GET, request.method);
    assert_eq!(&"1234", request.cookies.get("name").unwrap());


}


#[test]
fn build_request_1() {
    let request = RequestBuilder::get("Http://web.myservice.com")
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

    let request = RequestBuilder::post("Http://web.myservice.com/user")
        .header(ACCEPT, CONTENT_TYPE_JSON)
        .param("id", "12345")
        .json(&data)
        .build();

    assert_eq!(HttpMethod::POST, request.method);
    assert_eq!(&CONTENT_TYPE_JSON, request.headers.get(ACCEPT).unwrap());

}


#[test]
fn test_url_ok1() {
    assert_eq!(parse_url("Http://web.myservice.com/user").is_ok(), true);
}

#[test]
fn test_url_nok1() {
    assert_eq!(parse_url("ftp://web.myservice.com/user").is_err(), false);
}

#[test]
fn test_echo1() {
    let mut request =
        RequestBuilder::get("Http://localhost/user").build();

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

    let result = RequestBuilder::get("Http://localhost/user")
        .header(ACCEPT, CONTENT_TYPE_JSON)
        .json(&data)
        .build()
        .send();

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
    let result = RequestBuilder::get("http://ip-api.com/json/")
        .header(ACCEPT, CONTENT_TYPE_JSON)
        .param("fields", "24576")
        .build()
        .send();


    if let Some(e) = result.as_ref().err(){
        println!("{}", e);
    }

    assert!(result.is_ok());

    let response = result.unwrap();

    assert_eq!(response.status_code, 200);

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