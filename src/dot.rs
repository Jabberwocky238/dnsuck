use anyhow::{Context, Result};
use hickory_server::{Server, server::RequestHandler};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpListener;

pub async fn register<T: RequestHandler>(
    server: &mut Server<T>,
    address: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let listener = TcpListener::bind(address)
        .await
        .context("binding DoT TCP listener")?;
    let bound = listener.local_addr()?;
    match tls {
        Some(tls) => {
            server.register_tls_listener_with_tls_config(listener, Duration::from_secs(10), tls)?
        }
        None => server.register_listener(listener, Duration::from_secs(10), 16),
    }
    println!("DoT listening on {bound}");
    Ok(())
}
