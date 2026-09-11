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
    pub signed: Option<Arc<crate::dnssec::SignedZone>>,
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
        mut response: R,
    ) -> ResponseInfo {
        if let Some(signed) = &self.signed
            && request
                .request_info()
                .is_ok_and(|info| signed.origin.zone_of(info.query.original().name()))
        {
            let signed = signed.clone();
            let store = self.store.clone();
            match tokio::task::spawn_blocking(move || signed.catalog(&store))
                .await
                .map_err(anyhow::Error::from)
                .and_then(|result| result)
            {
                Ok(catalog) => return catalog.handle_request::<R, T>(request, response).await,
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
            .handle_request::<R, T>(request, response)
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
        self.0.handle_request::<R, T>(request, response).await
    }
}
