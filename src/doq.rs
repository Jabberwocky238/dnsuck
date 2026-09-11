use anyhow::{Context, Result};
use hickory_server::{Server, server::RequestHandler};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::UdpSocket;

pub async fn register<T: RequestHandler>(
    server: &mut Server<T>,
    address: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
) -> Result<()> {
    let socket = UdpSocket::bind(address)
        .await
        .context("binding DoQ UDP listener")?;
    let bound = socket.local_addr()?;
    server.register_quic_listener_and_tls_config(socket, Duration::from_secs(10), tls)?;
    println!("DoQ listening on {bound}");
    Ok(())
}
