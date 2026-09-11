use crate::{
    Store,
    dnssec::SignedZone,
    resolver::{Resolver, SharedResolver},
};
use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use hickory_server::Server;
use std::{
    net::{IpAddr, SocketAddr},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket, UnixListener, UnixStream},
    sync::watch,
    task::JoinSet,
};

#[derive(Parser, Clone)]
#[command(
    name = "dnsuck",
    version,
    about = "LMDB DNS server with DoH, DoT, DoQ, DNSSEC and GraphQL"
)]
pub struct Config {
    /// Read configuration exclusively from a TOML file.
    #[arg(short = 'c', long = "config", value_name = "PATH", conflicts_with_all = ["dns", "database", "doh", "doh_cert", "doh_key", "doh_no_cert", "dot", "dot_cert", "dot_key", "dot_no_cert", "doq", "doq_cert", "doq_key", "listen", "dnssec_zone", "dnssec_key_file"], global = true)]
    pub config: Option<PathBuf>,
    /// Reload the running config-file instance for this user.
    #[arg(long, conflicts_with_all = ["config", "dns", "database", "doh", "doh_cert", "doh_key", "doh_no_cert", "dot", "dot_cert", "dot_key", "dot_no_cert", "doq", "doq_cert", "doq_key", "listen", "dnssec_zone", "dnssec_key_file"], global = true)]
    pub reload: bool,
    /// Enable UDP/TCP DNS, at the specified address and port.
    #[arg(long, value_name = "ADDRESS:PORT", global = true)]
    pub dns: Option<SocketAddr>,
    #[arg(long, default_value = "data/lmdb", global = true)]
    pub database: PathBuf,
    /// Enable DNS over HTTPS, at the specified address and port.
    #[arg(
        long,
        value_name = "ADDRESS:PORT",
        requires = "doh_security",
        global = true
    )]
    pub doh: Option<SocketAddr>,
    #[arg(long, requires_all = ["doh", "doh_key"], group = "doh_security", global = true)]
    pub doh_cert: Option<PathBuf>,
    #[arg(long, requires_all = ["doh", "doh_cert"], global = true)]
    pub doh_key: Option<PathBuf>,
    /// Accept plaintext from a proxy that terminates TLS.
    #[arg(long, requires = "doh", conflicts_with_all = ["doh_cert", "doh_key"], group = "doh_security", global = true)]
    pub doh_no_cert: bool,
    /// Enable DNS over TLS, at the specified address and port.
    #[arg(
        long,
        value_name = "ADDRESS:PORT",
        requires = "dot_security",
        global = true
    )]
    pub dot: Option<SocketAddr>,
    #[arg(long, requires_all = ["dot", "dot_key"], group = "dot_security", global = true)]
    pub dot_cert: Option<PathBuf>,
    #[arg(long, requires_all = ["dot", "dot_cert"], global = true)]
    pub dot_key: Option<PathBuf>,
    /// Accept plaintext from a proxy that terminates TLS.
    #[arg(long, requires = "dot", conflicts_with_all = ["dot_cert", "dot_key"], group = "dot_security", global = true)]
    pub dot_no_cert: bool,
    /// Enable DNS over QUIC, at the specified address and port.
    #[arg(long, value_name = "ADDRESS:PORT", requires_all = ["doq_cert", "doq_key"], global = true)]
    pub doq: Option<SocketAddr>,
    #[arg(long, requires = "doq", global = true)]
    pub doq_cert: Option<PathBuf>,
    #[arg(long, requires = "doq", global = true)]
    pub doq_key: Option<PathBuf>,
    /// Management HTTP bind address.
    #[arg(
        long,
        value_name = "ADDRESS:PORT",
        default_value = "127.0.0.1:3080",
        global = true
    )]
    pub listen: SocketAddr,
    #[arg(long, requires = "dnssec_key_file", global = true)]
    pub dnssec_zone: Option<String>,
    #[arg(long, requires = "dnssec_zone", global = true)]
    pub dnssec_key_file: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Clone)]
pub enum Command {
    /// Replace an A or AAAA RRset.
    Put {
        name: String,
        ip: IpAddr,
        #[arg(default_value_t = 300)]
        ttl: u32,
    },
    /// Write one record directly to LMDB using structured fields.
    Record {
        name: String,
        record_type: String,
        data: String,
        #[arg(long, default_value_t = 300)]
        ttl: u32,
        /// Interpret data as base64-encoded wire RDATA.
        #[arg(long)]
        raw: bool,
    },
    /// Atomically write a JSON array of RecordInput objects from stdin to LMDB.
    Write,
}

impl Config {
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        use anyhow::{Context, bail};
        let path = std::fs::canonicalize(path).context("locating config file")?;
        let text = std::fs::read_to_string(&path).context("reading config file")?;
        let values: std::collections::BTreeMap<String, toml::Value> =
            toml::from_str(&text).context("parsing TOML config")?;
        let mut args = vec![std::ffi::OsString::from("dnsuck")];
        for (name, value) in values {
            let flag = name.replace('_', "-");
            let boolean = matches!(flag.as_str(), "doh-no-cert" | "dot-no-cert");
            let file = matches!(
                flag.as_str(),
                "database"
                    | "doh-cert"
                    | "doh-key"
                    | "dot-cert"
                    | "dot-key"
                    | "doq-cert"
                    | "doq-key"
                    | "dnssec-key-file"
            );
            if !boolean
                && !file
                && !matches!(
                    flag.as_str(),
                    "dns" | "doh" | "dot" | "doq" | "listen" | "dnssec-zone"
                )
            {
                bail!("unknown configuration key: {name}");
            }
            if boolean {
                match value.as_bool() {
                    Some(true) => args.push(format!("--{flag}").into()),
                    Some(false) => {}
                    None => bail!("{name} must be a boolean"),
                }
            } else {
                let value = value
                    .as_str()
                    .with_context(|| format!("{name} must be a string"))?;
                args.push(format!("--{flag}").into());
                args.push(if file {
                    path.parent()
                        .expect("absolute file parent")
                        .join(value)
                        .into_os_string()
                } else {
                    value.into()
                });
            }
        }
        let mut config = Self::try_parse_from(args).context("invalid TOML settings")?;
        config.config = Some(path);
        Ok(config)
    }
}

fn directory() -> PathBuf {
    // geteuid has no preconditions and identifies the installation's Unix user.
    let uid = unsafe { libc::geteuid() };
    std::env::temp_dir().join(format!("dnsuck-control-{uid}"))
}

pub struct Control {
    pub listener: UnixListener,
    path: PathBuf,
}

impl Control {
    pub fn bind() -> Result<Self> {
        let directory = directory();
        match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = std::fs::symlink_metadata(&directory)?;
        let uid = unsafe { libc::geteuid() };
        ensure!(
            metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
            "reload directory must be owned by this user with mode 0700"
        );
        let path = directory.join("reload.sock");
        let listener = UnixListener::bind(&path).with_context(|| format!(
            "binding {}; only one config-file instance per user is reloadable; remove a stale socket only after its server has stopped", path.display()))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self { listener, path })
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        if let Some(directory) = self.path.parent() {
            let _ = std::fs::remove_dir(directory);
        }
    }
}

pub async fn request_reload() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut stream = UnixStream::connect(directory().join("reload.sock"))
            .await
            .context("no reloadable server; start the server with -c PATH as this user")?;
        stream.write_all(b"reload\n").await?;
        let mut response = String::new();
        stream.take(8192).read_to_string(&mut response).await?;
        ensure!(response == "OK\n", "{}", response.trim());
        println!("Configuration reloaded");
        Ok(())
    })
    .await
    .context("reload timed out")?
}

pub async fn read_reload_request(stream: &mut UnixStream) -> Result<()> {
    let mut request = [0; 7];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut request)).await??;
    ensure!(&request == b"reload\n", "invalid reload request");
    Ok(())
}

type Tls = Arc<rustls::ServerConfig>;

#[derive(Clone)]
pub struct Prepared {
    pub config: Config,
    resolver: Arc<Resolver>,
    doh: Option<Tls>,
    dot: Option<Tls>,
    doq: Option<Tls>,
}

impl Prepared {
    /// Validate and load all key material before disturbing the current listeners.
    pub async fn new(config: Config, store: Arc<Store>) -> Result<Self> {
        let signed = config
            .dnssec_zone
            .as_ref()
            .map(|zone| {
                SignedZone::load(
                    zone,
                    config
                        .dnssec_key_file
                        .as_ref()
                        .expect("validated DNSSEC key"),
                )
                .map(Arc::new)
            })
            .transpose()?;
        let resolver = Arc::new(Resolver { store, signed });
        resolver.warm_signed().await?;
        let load = |address: Option<std::net::SocketAddr>,
                    no_cert: bool,
                    cert: &Option<std::path::PathBuf>,
                    key: &Option<std::path::PathBuf>,
                    alpn: &[&[u8]],
                    quic: bool| {
            if address.is_some() && !no_cert {
                crate::doh::server_config(
                    cert.as_deref().expect("validated cert"),
                    key.as_deref().expect("validated key"),
                    alpn,
                    quic,
                )
                .map(Some)
            } else {
                Ok(None)
            }
        };
        let doh = load(
            config.doh,
            config.doh_no_cert,
            &config.doh_cert,
            &config.doh_key,
            &[b"h2", b"http/1.1"],
            false,
        )?;
        let dot = load(
            config.dot,
            config.dot_no_cert,
            &config.dot_cert,
            &config.dot_key,
            &[b"dot"],
            false,
        )?;
        let doq = load(
            config.doq,
            false,
            &config.doq_cert,
            &config.doq_key,
            &[b"doq"],
            true,
        )?;
        Ok(Self {
            config,
            resolver,
            doh,
            dot,
            doq,
        })
    }
}

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
            let udp = UdpSocket::bind(address).await.context("binding DNS UDP")?;
            let address = udp.local_addr()?;
            let tcp = TcpListener::bind(address)
                .await
                .context("binding DNS TCP")?;
            self.server.register_socket(udp);
            self.server
                .register_listener(tcp, Duration::from_secs(10), 16);
            println!("DNS listening on {address} (UDP/TCP)");
        }
        if let Some(address) = config.dot {
            crate::dot::register(&mut self.server, address, prepared.dot.clone()).await?;
        }
        if let Some(address) = config.doq {
            crate::doq::register(
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
        let api = Arc::new(crate::doh::Api {
            resolver: prepared.resolver.clone(),
            schema: crate::graphql::schema(prepared.resolver.clone()),
            management,
        });
        self.http.spawn(crate::doh::serve(
            listener,
            tls,
            api,
            self.shutdown.subscribe(),
        )?);
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

/// Supervise config-file reloads and restore the previous listeners on bind failure.
pub async fn serve(config: Config, store: Arc<Store>) -> Result<()> {
    let control = config
        .config
        .as_ref()
        .map(|_| Control::bind())
        .transpose()?;
    let mut prepared = Prepared::new(config, store.clone()).await?;
    let mut running = Running::start(&prepared).await?;
    loop {
        tokio::select! {
            result = running.wait() => {
                running.stop().await?;
                return result;
            },
            result = tokio::signal::ctrl_c() => {
                running.stop().await?;
                return result.context("listening for Ctrl-C");
            },
            request = async {
                match &control {
                    Some(control) => control.listener.accept().await,
                    None => std::future::pending().await,
                }
            } => {
                let (mut stream, _) = request?;
                if read_reload_request(&mut stream).await.is_err() { continue; }
                let candidate = async {
                    let next = Config::from_file(prepared.config.config.as_ref().expect("config-file instance"))?;
                    anyhow::ensure!(next.database == prepared.config.database,
                        "database path cannot change during reload; restart the server");
                    Prepared::new(next, store.clone()).await
                }.await;
                let result = match candidate {
                    Err(error) => Err(error),
                    Ok(next) => {
                        running.stop().await?;
                        match Running::start(&next).await {
                            Ok(next_running) => { running = next_running; prepared = next; Ok(()) },
                            Err(error) => {
                                running = Running::start(&prepared).await.context("restoring previous listeners after failed reload")?;
                                Err(error.context("reload rejected; previous configuration restored"))
                            }
                        }
                    }
                };
                let response = match result {
                    Ok(()) => "OK\n".to_string(),
                    Err(error) => format!("ERROR: {error:#}\n"),
                };
                let _ = stream.write_all(response.as_bytes()).await;
            }
        }
    }
}
