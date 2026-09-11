use anyhow::{Context, Result};
use hickory_server::{Server, server::RequestHandler};
use std::{net::SocketAddr, time::Duration};
use tokio::net::{TcpListener, UdpSocket};

pub async fn register<T: RequestHandler>(
    server: &mut Server<T>,
    address: SocketAddr,
) -> Result<()> {
    let udp = UdpSocket::bind(address).await.context("binding DNS UDP")?;
    let address = udp.local_addr()?;
    let tcp = TcpListener::bind(address)
        .await
        .context("binding DNS TCP")?;
    server.register_socket(udp);
    server.register_listener(tcp, Duration::from_secs(10), 16);
    println!("DNS listening on {address} (UDP/TCP)");
    Ok(())
}
