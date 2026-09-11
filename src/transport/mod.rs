//! DNS transport listeners and their startup/shutdown lifecycle.

pub mod dns;
pub mod doh;
pub mod doq;
pub mod dot;

use crate::{
    config::{Prepared, Tls},
    dnslogic::resolver::SharedResolver,
};
use anyhow::{Context, Result};
use hickory_server::Server;
use std::sync::Arc;
use tokio::{net::TcpListener, sync::watch, task::JoinSet};

pub struct Running {
    server: Server<SharedResolver>,
    http: JoinSet<Result<()>>,
    shutdown: watch::Sender<bool>,
    has_dns: bool,
}

impl Running {
    pub async fn start(prepared: &Prepared) -> Result<Self> {
        let (shutdown, _) = watch::channel(false);
        let config = &prepared.config;
        let mut running = Self {
            server: Server::new(SharedResolver(prepared.resolver.clone())),
            http: JoinSet::new(),
            shutdown,
            has_dns: config.dns.is_some() || config.dot.is_some() || config.doq.is_some(),
        };
        if let Err(error) = running.bind(prepared).await {
            running.stop().await.context("cleaning up failed startup")?;
            return Err(error);
        }
        Ok(running)
    }

    async fn bind(&mut self, prepared: &Prepared) -> Result<()> {
        let config = &prepared.config;
        if let Some(address) = config.dns {
            dns::register(&mut self.server, address).await?;
        }
        if let Some(address) = config.dot {
            dot::register(&mut self.server, address, prepared.dot.clone()).await?;
        }
        if let Some(address) = config.doq {
            doq::register(
                &mut self.server,
                address,
                prepared.doq.clone().expect("validated QUIC TLS"),
            )
            .await?;
        }
        if let Some(address) = config.doh {
            let listener = TcpListener::bind(address).await.context("binding DoH")?;
            println!("DoH listening on {} (/dns-query)", listener.local_addr()?);
            self.http_listener(listener, prepared.doh.clone(), prepared, false)?;
        }
        let listener = TcpListener::bind(config.listen)
            .await
            .context("binding management HTTP")?;
        println!(
            "GraphQL listening on http://{}/graphql",
            listener.local_addr()?
        );
        self.http_listener(listener, None, prepared, true)?;
        Ok(())
    }

    fn http_listener(
        &mut self,
        listener: TcpListener,
        tls: Option<Tls>,
        prepared: &Prepared,
        management: bool,
    ) -> Result<()> {
        let api = Arc::new(doh::Api {
            resolver: prepared.resolver.clone(),
            schema: crate::graphql::schema(prepared.resolver.clone()),
            management,
        });
        self.http
            .spawn(doh::serve(listener, tls, api, self.shutdown.subscribe())?);
        Ok(())
    }

    pub async fn wait(&mut self) -> Result<()> {
        tokio::select! {
            result = self.server.block_until_done(), if self.has_dns => result.context("DNS server stopped"),
            result = self.http.join_next() => result.context("HTTP server missing")?.context("HTTP task failed")?,
        }
    }

    pub async fn stop(&mut self) -> Result<()> {
        let _ = self.shutdown.send(true);
        self.server.shutdown_gracefully().await?;
        while let Some(task) = self.http.join_next().await {
            task??;
        }
        Ok(())
    }
}
