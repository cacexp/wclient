use wclient::*;

// This Example makes a simple request to the service ip-api.com to get the public IP used to get access to Internet

pub fn main() {

    // Request builder and send method
    let result = RequestBuilder::get("http://ip-api.com/json/")
        .header("Accept", "Content-Type: application/json")
        .param("fields", "24576")
        .build()
        .send();


    if let Some(e) = result.as_ref().err(){
        println!("{}", e);
        return;
    }

    let response = result.unwrap();

    assert_eq!(response.status_code(), 200);

    let result_json = response.json();

    if let Some(e) = result_json.as_ref().err(){
        println!("{}", e);
    }

    let result_data = result_json.unwrap();

    assert!(result_data.has_key("status"));
    assert_eq!(result_data["status"], "success");
    assert_eq!(result_data.has_key("query"), true);

    println!("My public IP is: {}", result_data["query"])

}