use crate::graphql::ManagementSchema;
use crate::resolver::Resolver;
use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer,
    http::{Method, StatusCode},
    web,
};
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hickory_server::{
    net::{NetError, runtime::TokioTime, xfer::Protocol},
    proto::{rr::Record, serialize::binary::BinEncoder},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponse,
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use std::{path::Path, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{net::TcpListener, sync::watch};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Option<Vec<u8>>>>);

#[async_trait::async_trait]
impl ResponseHandler for Capture {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(u16::MAX);
        let info = response.destructive_emit(&mut encoder)?;
        *self.0.lock().expect("response capture poisoned") = Some(bytes);
        Ok(info)
    }
}

pub async fn answer(resolver: &Resolver, wire: Vec<u8>, peer: SocketAddr) -> Result<Vec<u8>> {
    // TCP semantics avoid imposing UDP's size limit on a DoH response.
    let request = Request::from_bytes(wire, peer, Protocol::Tcp)?;
    let capture = Capture::default();
    resolver
        .handle_request::<Capture, TokioTime>(&request, capture.clone())
        .await;
    capture
        .0
        .lock()
        .map_err(|_| anyhow::anyhow!("response capture poisoned"))?
        .take()
        .context("DNS handler did not produce a response")
}

pub struct Api {
    pub resolver: Arc<Resolver>,
    pub schema: ManagementSchema,
    pub token: Option<String>,
    pub management: bool,
}

fn response(
    status: StatusCode,
    content_type: &'static str,
    body: impl Into<web::Bytes>,
) -> HttpResponse {
    HttpResponse::build(status)
        .insert_header(("content-type", content_type))
        .insert_header(("cache-control", "no-store"))
        .body(body.into())
}

fn error(status: StatusCode, message: &'static str) -> HttpResponse {
    response(status, "text/plain", message)
}

pub async fn route(
    request: HttpRequest,
    api: web::Data<Arc<Api>>,
    payload: web::Payload,
) -> HttpResponse {
    match request.uri().path() {
        "/dns-query" if !api.management => {
            let wire = if request.method() == Method::GET {
                let Some(query) = request.uri().query() else {
                    return error(StatusCode::BAD_REQUEST, "missing dns parameter");
                };
                let mut values = url::form_urlencoded::parse(query.as_bytes())
                    .filter(|(key, _)| key == "dns")
                    .map(|(_, value)| value);
                let Some(value) = values.next() else {
                    return error(StatusCode::BAD_REQUEST, "missing dns parameter");
                };
                if values.next().is_some() {
                    return error(StatusCode::BAD_REQUEST, "duplicate dns parameter");
                }
                match URL_SAFE_NO_PAD.decode(value.as_bytes()) {
                    Ok(wire) if wire.len() <= 65535 => wire,
                    _ => return error(StatusCode::BAD_REQUEST, "invalid dns parameter"),
                }
            } else if request.method() == Method::POST {
                if request
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.split(';').next().unwrap().trim())
                    != Some("application/dns-message")
                {
                    return error(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "expected application/dns-message",
                    );
                }
                match payload.to_bytes_limited(65535).await {
                    Ok(Ok(body)) => body.to_vec(),
                    Ok(Err(_)) => return error(StatusCode::BAD_REQUEST, "invalid request body"),
                    Err(_) => {
                        return error(StatusCode::PAYLOAD_TOO_LARGE, "DNS body exceeds limit");
                    }
                }
            } else {
                return error(StatusCode::METHOD_NOT_ALLOWED, "use GET or POST");
            };
            match answer(
                &api.resolver,
                wire,
                request.peer_addr().expect("TLS peer address"),
            )
            .await
            {
                Ok(wire) => response(StatusCode::OK, "application/dns-message", wire),
                Err(_) => error(StatusCode::BAD_REQUEST, "invalid DNS message"),
            }
        }
        "/graphql" if api.management => {
            let supplied = request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("");
            if let Some(token) = &api.token
                && !bool::from(supplied.as_bytes().ct_eq(token.as_bytes()))
            {
                return error(StatusCode::UNAUTHORIZED, "invalid bearer token");
            }
            if request.method() != Method::POST {
                return error(StatusCode::METHOD_NOT_ALLOWED, "use POST");
            }
            if request
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(';').next().unwrap().trim())
                != Some("application/json")
            {
                return error(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "expected application/json",
                );
            }
            let bytes = match payload.to_bytes_limited(1024 * 1024).await {
                Ok(Ok(body)) => body,
                Ok(Err(_)) => return error(StatusCode::BAD_REQUEST, "invalid request body"),
                Err(_) => {
                    return error(StatusCode::PAYLOAD_TOO_LARGE, "GraphQL body exceeds limit");
                }
            };
            let query = match serde_json::from_slice::<async_graphql::Request>(&bytes) {
                Ok(query) => query,
                Err(_) => return error(StatusCode::BAD_REQUEST, "invalid GraphQL request"),
            };
            let result = api.schema.execute(query).await;
            response(
                StatusCode::OK,
                "application/json",
                serde_json::to_vec(&result).expect("GraphQL response serialization"),
            )
        }
        _ => error(StatusCode::NOT_FOUND, "not found"),
    }
}

pub fn server_config(
    cert: &Path,
    key: &Path,
    alpn: &[&[u8]],
    quic: bool,
) -> Result<Arc<rustls::ServerConfig>> {
    let cert = std::fs::read(cert).context("reading TLS certificate")?;
    let key = std::fs::read(key).context("reading TLS private key")?;
    let certificates =
        rustls_pemfile::certs(&mut cert.as_slice()).collect::<Result<Vec<_>, _>>()?;
    let key =
        rustls_pemfile::private_key(&mut key.as_slice())?.context("TLS file has no private key")?;
    let versions = if quic {
        &[&rustls::version::TLS13][..]
    } else {
        rustls::DEFAULT_VERSIONS
    };
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(versions)?
    .with_no_client_auth()
    .with_single_cert(certificates, key)?;
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    // Do not accept replayable 0-RTT requests.
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

pub fn serve(
    listener: TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    api: Arc<Api>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<impl Future<Output = Result<()>> + Send> {
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(api.clone()))
            .default_service(web::to(route))
    })
    .workers(2)
    .disable_signals()
    .client_request_timeout(Duration::from_secs(10))
    .shutdown_timeout(5);
    let listener = listener.into_std()?;
    let server = match tls {
        Some(tls) => server.listen_rustls_0_23(listener, tls.as_ref().clone())?,
        None => server.listen(listener)?,
    }
    .run();
    let handle = server.handle();
    Ok(async move {
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result.context("HTTP server stopped"),
            _ = shutdown.changed() => {
                let (_, result) = tokio::join!(handle.stop(true), &mut server);
                result.context("HTTP shutdown")
            }
        }
    })
}
