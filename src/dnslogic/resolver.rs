use crate::Store;
use hickory_server::{
    net::runtime::Time,
    proto::{
        op::{Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode},
        rr::DNSClass,
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};
use std::sync::Arc;

pub struct DnsHandler(pub Arc<Store>);

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response: R,
    ) -> ResponseInfo {
        let mut meta = Metadata::new(
            request.metadata.id,
            MessageType::Response,
            request.metadata.op_code,
        );
        meta.recursion_desired = request.metadata.recursion_desired;
        let mut answers = Vec::new();
        if request.metadata.message_type != MessageType::Query {
            meta.response_code = ResponseCode::FormErr;
        } else if request.metadata.op_code != OpCode::Query {
            meta.response_code = ResponseCode::NotImp;
        } else if let Ok(info) = request.request_info() {
            if info.query.query_class() != DNSClass::IN {
                meta.response_code = ResponseCode::Refused;
            } else if matches!(u16::from(info.query.query_type()), 0 | 41 | 249..=254) {
                meta.response_code = ResponseCode::NotImp;
            } else {
                let store = self.0.clone();
                let name = info.query.name().to_string();
                let kind = info.query.query_type();
                // Keep LMDB transactions and page faults off Tokio's worker threads.
                match tokio::task::spawn_blocking(move || store.lookup(&name, kind)).await {
                    Ok(Ok(Some(records))) => answers = records,
                    Ok(Ok(None)) => meta.response_code = ResponseCode::NXDomain,
                    error => {
                        eprintln!("LMDB lookup failed: {error:?}");
                        meta.response_code = ResponseCode::ServFail;
                    }
                }
            }
        } else {
            meta.response_code = ResponseCode::FormErr;
        }
        let fallback = ResponseInfo::from(Header {
            metadata: meta,
            counts: HeaderCounts::default(),
        });
        let message = MessageResponseBuilder::from_message_request(request).build(
            meta,
            &answers,
            &[],
            &[],
            &[],
        );
        match response.send_response(message).await {
            Ok(info) => info,
            Err(error) => {
                eprintln!("DNS response failed: {error}");
                fallback
            }
        }
    }
}

pub struct Resolver {
    pub store: Arc<Store>,
    pub signed: Option<Arc<crate::dnslogic::dnssec::SignedZone>>,
    pub ordering: Arc<Ordering>,
}

impl Resolver {
    pub async fn warm_signed(&self) -> anyhow::Result<()> {
        if let Some(signed) = &self.signed {
            let signed = signed.clone();
            let store = self.store.clone();
            tokio::task::spawn_blocking(move || signed.catalog(&store)).await??;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl RequestHandler for Resolver {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response: R,
    ) -> ResponseInfo {
        let mut response = OrderedResponse {
            inner: response,
            store: self.store.clone(),
            ordering: self.ordering.clone(),
            peer: request.src(),
        };
        if let Some(signed) = &self.signed
            && request
                .request_info()
                .is_ok_and(|info| signed.origin.zone_of(info.query.original().name()))
        {
            let signed = signed.clone();
            let store = self.store.clone();
            let info = request.request_info().expect("validated query");
            let name = info.query.name().to_string();
            let kind = info.query.query_type();
            match tokio::task::spawn_blocking(move || signed.catalog_for(&store, &name, kind))
                .await
                .map_err(anyhow::Error::from)
                .and_then(|result| result)
            {
                Ok(catalog) => return catalog.handle_request::<_, T>(request, response).await,
                Err(error) => {
                    eprintln!("DNSSEC zone refresh failed: {error:?}");
                    let message = MessageResponseBuilder::from_message_request(request)
                        .error_msg(&request.metadata, ResponseCode::ServFail);
                    return response.send_response(message).await.unwrap_or_else(|_| {
                        let mut metadata = Metadata::new(
                            request.metadata.id,
                            MessageType::Response,
                            request.metadata.op_code,
                        );
                        metadata.response_code = ResponseCode::ServFail;
                        Header {
                            metadata,
                            counts: HeaderCounts::default(),
                        }
                        .into()
                    });
                }
            }
        }
        DnsHandler(self.store.clone())
            .handle_request::<_, T>(request, response)
            .await
    }
}

pub struct SharedResolver(pub Arc<Resolver>);
#[async_trait::async_trait]
impl hickory_server::server::RequestHandler for SharedResolver {
    async fn handle_request<
        R: hickory_server::server::ResponseHandler,
        T: hickory_server::net::runtime::Time,
    >(
        &self,
        request: &hickory_server::server::Request,
        response: R,
    ) -> hickory_server::server::ResponseInfo {
        self.0.handle_request::<_, T>(request, response).await
    }
}

use crate::dnslogic::records::{OrderMode, OrderModes};
use hickory_server::{
    net::{NetError, xfer::Protocol},
    proto::{
        op::Message,
        rr::{RData, Record},
        serialize::binary::BinEncoder,
    },
    zone_handler::MessageResponse,
};
use rand::seq::SliceRandom;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{
        RwLock,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
    },
};

type CursorMap = BTreeMap<(String, u16), Arc<AtomicUsize>>;

/// Only the policy is persisted. Best-effort lb cursors live in this process.
#[derive(Default)]
pub struct Ordering {
    geo: Option<maxminddb::Reader<Vec<u8>>>,
    cursors: RwLock<CursorMap>,
}

impl Ordering {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        Ok(Self {
            geo: path.map(maxminddb::Reader::open_readfile).transpose()?,
            cursors: RwLock::default(),
        })
    }

    pub fn has_geo(&self) -> bool {
        self.geo.is_some()
    }

    fn country(&self, ip: IpAddr) -> Option<String> {
        let result = self.geo.as_ref()?.lookup(ip.to_canonical()).ok()?;
        let value = result.decode::<maxminddb::geoip2::Country>().ok()??;
        value
            .country
            .iso_code
            .or(value.registered_country.iso_code)
            .map(str::to_owned)
    }

    pub fn sort(
        &self,
        records: &mut [Record],
        modes: &OrderModes,
        sources: &BTreeMap<String, String>,
        peer: IpAddr,
    ) {
        let mut groups: BTreeMap<(String, u16), Vec<usize>> = BTreeMap::new();
        for (index, record) in records.iter().enumerate() {
            let key = (
                crate::dnslogic::records::name_text(&record.name).to_ascii_lowercase(),
                u16::from(record.record_type()),
            );
            let source = (
                sources
                    .get(&key.0)
                    .cloned()
                    .unwrap_or_else(|| key.0.clone()),
                key.1,
            );
            if modes.contains_key(&source) {
                groups.entry(key).or_default().push(index);
            }
        }
        for (key, indices) in groups {
            if indices.len() < 2 {
                continue;
            }
            let mut values: Vec<_> = indices
                .iter()
                .map(|&index| records[index].clone())
                .collect();
            let key = (sources.get(&key.0).cloned().unwrap_or(key.0), key.1);
            match modes[&key] {
                OrderMode::Lb => {
                    let existing = self
                        .cursors
                        .read()
                        .expect("lb cursors poisoned")
                        .get(&key)
                        .cloned();
                    let cursor = existing.unwrap_or_else(|| {
                        self.cursors
                            .write()
                            .expect("lb cursors poisoned")
                            .entry(key)
                            .or_default()
                            .clone()
                    });
                    // Relaxed counter allocation does not impose response order across clients.
                    let offset = cursor.fetch_add(1, AtomicOrdering::Relaxed) % values.len();
                    values.rotate_left(offset);
                }
                OrderMode::Random => values.shuffle(&mut rand::rng()),
                OrderMode::Geo => {
                    if let Some(country) = self.country(peer) {
                        values.sort_by_cached_key(|record| {
                            let ip = match &record.data {
                                RData::A(ip) => Some(IpAddr::V4(ip.0)),
                                RData::AAAA(ip) => Some(IpAddr::V6(ip.0)),
                                _ => None,
                            };
                            ip.and_then(|ip| self.country(ip)).as_deref() != Some(country.as_str())
                        });
                    }
                }
            }
            for (index, record) in indices.into_iter().zip(values) {
                records[index] = record;
            }
        }
    }
}

#[derive(Clone)]
struct OrderedResponse<R> {
    inner: R,
    store: Arc<Store>,
    ordering: Arc<Ordering>,
    peer: SocketAddr,
}

#[async_trait::async_trait]
impl<R: ResponseHandler> ResponseHandler for OrderedResponse<R> {
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
        let store = self.store.clone();
        let modes = tokio::task::spawn_blocking(move || store.modes())
            .await
            .map_err(std::io::Error::other)?
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if modes.is_empty() {
            return self.inner.send_response(response).await;
        }
        // Hickory owns parsing/encoding. Reordering leaves every RRset and RRSIG intact.
        let mut wire = Vec::new();
        let mut encoder = BinEncoder::new(&mut wire);
        encoder.set_max_size(u16::MAX);
        response.destructive_emit(&mut encoder)?;
        let mut message = Message::from_vec(&wire)?;
        if message.signature.is_none() {
            let store = self.store.clone();
            let (mut ordered, sources) = tokio::task::spawn_blocking(move || {
                let sources = store.sources(&message.answers)?;
                anyhow::Ok((message, sources))
            })
            .await
            .map_err(std::io::Error::other)?
            .map_err(|error| std::io::Error::other(error.to_string()))?;
            self.ordering
                .sort(&mut ordered.answers, &modes, &sources, self.peer.ip());
            message = ordered;
        }
        let request = Request::from_bytes(wire, self.peer, Protocol::Tcp)?;
        let mut builder = MessageResponseBuilder::from_message_request(&request);
        if let Some(edns) = &message.edns {
            builder.edns(edns);
        }
        let mut response = builder.build(
            message.metadata,
            &message.answers,
            &message.authorities,
            &[],
            &message.additionals,
        );
        if let Some(signature) = message.signature {
            response.set_signature(signature);
        }
        self.inner.send_response(response).await
    }
}
