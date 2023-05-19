use actix_web::{web, App, HttpServer, Result};
use serde::Deserialize;

use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;

#[derive(Deserialize)]
struct Info {
    ssid: String,
    passphrase: String,
}

fn print_hello(ssid: String, passphrase: String) {
    println!("Received {:?} {:?}", ssid, passphrase);
}

async fn index(info: web::Json<Info>) -> Result<String> {
    print_hello(info.ssid.clone(), info.passphrase.clone());
    Ok(format!("You sent SSID {}!", info.ssid))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let network_interfaces = NetworkInterface::show().unwrap();

    // Get ip4 address of the interface to bind to
    let interface_to_bind_to = "wlan0";
    let mut ip_to_bind_to = String::new();

    for itf in network_interfaces.iter() {
        if itf.name == interface_to_bind_to {
            for address in itf.addr.iter() {
                match address {
                    network_interface::Addr::V4 (ip) => {
                        println!("ipv4: {:?}", ip.ip);
                        ip_to_bind_to = ip.ip.to_string();
                    }
                    network_interface::Addr::V6 (ip) => {
                        println!("ipv6, not interested");
                    }
                }
            }
        }
    }

    HttpServer::new(|| App::new().route("/", web::post().to(index)))
        .bind((ip_to_bind_to, 8080))?
        .run()
        .await
}