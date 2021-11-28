use wclient::SessionBuilder;

fn main() {

    println!("Example of accessing public APIs, please, do not overload the servers");
    println!("Getting your weather forecast");

    // Get IP latitude/longitude to as for the weather
    let session = SessionBuilder::new().build();

    let ip_result = session.get("http://ip-api.com/json/")
    .param("fields", "16576")
    .build()
    .send();

    assert!(ip_result.is_ok());

    let ip_response = ip_result.unwrap();

    assert!(ip_response.status_code() == 200);
    assert_eq!(ip_response.headers()["Content-Type"], "application/json; charset=utf-8");

    let ip_json = ip_response.json();

    assert!(ip_json.is_ok());

    let ip = ip_json.unwrap();

    assert!(ip.is_object());

    
    assert!(ip.has_key("status"));
    assert_eq!(ip["status"], "success");
    assert!(ip.has_key("lat"));
    assert!(ip.has_key("lon"));

    let lat = &ip["lat"];
    let lon = &ip["lon"];
    println!("My IP is at LAT {} LON {}", lat, lon);

    // Get the Weather location

    let loc_result = session.get("https://www.metaweather.com/api/location/search/")
        .header("Accept", "application/json")
        .param("lattlong", format!("{},{}", lat, lon).as_str())
        .build()
        .send();
    
    assert!(loc_result.is_ok());

    let loc_response = loc_result.unwrap();

    assert!(loc_response.status_code() == 200);   

    let loc_json = loc_response.json();

    assert!(loc_json.is_ok());

    let loc = loc_json.unwrap();

    assert!(loc.is_array());
    assert!(loc.len() > 0);

    // Get the forecast for the city location

    let woeid = &loc[0]["woeid"];

    let url = format!("https://www.metaweather.com/api/location/{}/", woeid);

    let forecast_result = session.get(url.as_str())
        .header("Accept", "application/json")
        .build()
        .send();

    assert!(forecast_result.is_ok());

    let forecast_response = forecast_result.unwrap();

    assert!(forecast_response.status_code() == 200);   

    let forecast_json = forecast_response.json();

    assert!(forecast_json.is_ok());

    let forecast = forecast_json.unwrap();

    println!("Forecast is:");
    println!("{}", forecast.pretty(2));

}