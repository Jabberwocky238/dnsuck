use crate::{RecordInput, decode_inputs, records::OrderMode, resolver::Resolver};
use async_graphql::{Context, EmptySubscription, Object, Schema, SimpleObject};
use hickory_server::proto::rr::{Record, RecordType};
use std::sync::Arc;

pub type ManagementSchema = Schema<Query, Mutation, EmptySubscription>;

pub fn schema(resolver: Arc<Resolver>) -> ManagementSchema {
    Schema::build(Query, Mutation, EmptySubscription)
        .data(resolver)
        .limit_depth(8)
        .limit_complexity(1000)
        .finish()
}

#[derive(SimpleObject)]
pub struct DnsRecord {
    name: String,
    record_type: String,
    ttl: u32,
    data: String,
    mode: Option<OrderMode>,
}
impl From<Record> for DnsRecord {
    fn from(record: Record) -> Self {
        Self {
            name: crate::records::name_text(&record.name),
            record_type: domain::base::iana::Rtype::from(u16::from(record.record_type()))
                .to_string(),
            ttl: record.ttl,
            data: record.data.to_string(),
            mode: None,
        }
    }
}

fn kind(value: &str) -> async_graphql::Result<RecordType> {
    let kind: domain::base::iana::Rtype = value.to_ascii_uppercase().parse()?;
    Ok(RecordType::from(kind.to_int()))
}

pub struct Query;
#[Object]
impl Query {
    async fn records(
        &self,
        ctx: &Context<'_>,
        name: String,
        record_type: Option<String>,
    ) -> async_graphql::Result<Vec<DnsRecord>> {
        let store = ctx.data::<Arc<Resolver>>()?.store.clone();
        let kind = record_type.as_deref().map(kind).transpose()?;
        let (records, modes) = tokio::task::spawn_blocking(move || {
            Ok::<_, anyhow::Error>((store.records(&name)?, store.modes()?))
        })
        .await??;
        Ok(records
            .into_iter()
            .filter(|r| kind.is_none_or(|kind| kind == RecordType::ANY || kind == r.record_type()))
            .map(|record| {
                let mode = modes
                    .get(&(
                        crate::records::name_text(&record.name),
                        u16::from(record.record_type()),
                    ))
                    .copied();
                let mut result = DnsRecord::from(record);
                result.mode = mode;
                result
            })
            .collect())
    }

    async fn names(
        &self,
        ctx: &Context<'_>,
        prefix: Option<String>,
        after: Option<String>,
        #[graphql(default = 100)] limit: i32,
    ) -> async_graphql::Result<Vec<String>> {
        if !(1..=500).contains(&limit) {
            return Err("limit must be between 1 and 500".into());
        }
        let store = ctx.data::<Arc<Resolver>>()?.store.clone();
        Ok(tokio::task::spawn_blocking(move || {
            store.names(
                &prefix.unwrap_or_default(),
                &after.unwrap_or_default(),
                limit as usize,
            )
        })
        .await??)
    }
}

pub struct Mutation;
#[Object]
impl Mutation {
    /// Atomically append distinct records, preserving the existing RRsets.
    async fn add(
        &self,
        ctx: &Context<'_>,
        records: Vec<RecordInput>,
        mode: Option<OrderMode>,
    ) -> async_graphql::Result<i32> {
        let resolver = ctx.data::<Arc<Resolver>>()?;
        if mode == Some(OrderMode::Geo) && !resolver.ordering.has_geo() {
            return Err("configure --mmdb before enabling geo".into());
        }
        let store = resolver.store.clone();
        let count = tokio::task::spawn_blocking(move || {
            store.write_records(decode_inputs(records)?, false, mode)
        })
        .await??;
        Ok(count.try_into()?)
    }

    /// Atomically replace the supplied RRsets in LMDB.
    async fn upsert(
        &self,
        ctx: &Context<'_>,
        records: Vec<RecordInput>,
        mode: Option<OrderMode>,
    ) -> async_graphql::Result<i32> {
        let resolver = ctx.data::<Arc<Resolver>>()?.clone();
        if mode == Some(OrderMode::Geo) && !resolver.ordering.has_geo() {
            return Err("configure --mmdb before enabling geo".into());
        }
        let count = tokio::task::spawn_blocking(move || {
            let records = decode_inputs(records)?;
            resolver.store.write_records(records, true, mode)
        })
        .await??;
        Ok(count.try_into()?)
    }

    /// Delete a value, an RRset, or all records at a name.
    async fn delete(
        &self,
        ctx: &Context<'_>,
        name: String,
        record_type: Option<String>,
        data: Option<String>,
        rdata_base64: Option<String>,
    ) -> async_graphql::Result<i32> {
        let resolver = ctx.data::<Arc<Resolver>>()?.clone();
        let kind = record_type.as_deref().map(kind).transpose()?;
        if let Some(signed) = &resolver.signed
            && crate::records::canonical(&name)? == signed.origin.to_ascii()
            && kind.is_none_or(|k| matches!(k, RecordType::SOA | RecordType::NS))
        {
            return Err("cannot delete the configured signed zone's apex SOA or NS".into());
        }
        let record = if data.is_some() || rdata_base64.is_some() {
            let record_type = record_type.ok_or("recordType is required when deleting a value")?;
            Some(
                RecordInput {
                    name: name.clone(),
                    record_type,
                    ttl: 0,
                    data,
                    rdata_base64,
                }
                .into_record()?,
            )
        } else {
            None
        };
        Ok(tokio::task::spawn_blocking(move || match record {
            Some(record) => resolver.store.delete_record(&record),
            None => resolver.store.delete(&name, kind),
        })
        .await??
        .try_into()?)
    }
}
