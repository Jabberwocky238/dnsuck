use crate::{RecordInput, decode_inputs, resolver::Resolver};
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
}
impl From<Record> for DnsRecord {
    fn from(record: Record) -> Self {
        Self {
            name: record.name.to_ascii(),
            record_type: domain::base::iana::Rtype::from(u16::from(record.record_type()))
                .to_string(),
            ttl: record.ttl,
            data: record.data.to_string(),
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
        let records = tokio::task::spawn_blocking(move || store.records(&name)).await??;
        Ok(records
            .into_iter()
            .filter(|r| kind.is_none_or(|kind| kind == RecordType::ANY || kind == r.record_type()))
            .map(Into::into)
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
    /// Atomically replace the supplied RRsets in LMDB.
    async fn upsert(
        &self,
        ctx: &Context<'_>,
        records: Vec<RecordInput>,
    ) -> async_graphql::Result<i32> {
        let resolver = ctx.data::<Arc<Resolver>>()?.clone();
        let count = tokio::task::spawn_blocking(move || {
            let records = decode_inputs(records)?;
            resolver.store.put_records(records)
        })
        .await??;
        Ok(count.try_into()?)
    }

    /// Delete one RRset, or all records at a name if recordType is omitted.
    async fn delete(
        &self,
        ctx: &Context<'_>,
        name: String,
        record_type: Option<String>,
    ) -> async_graphql::Result<i32> {
        let resolver = ctx.data::<Arc<Resolver>>()?.clone();
        let kind = record_type.as_deref().map(kind).transpose()?;
        if let Some(signed) = &resolver.signed
            && crate::records::canonical(&name)? == signed.origin.to_ascii()
            && kind.is_none_or(|k| matches!(k, RecordType::SOA | RecordType::NS))
        {
            return Err("cannot delete the configured signed zone's apex SOA or NS".into());
        }
        Ok(
            tokio::task::spawn_blocking(move || resolver.store.delete(&name, kind))
                .await??
                .try_into()?,
        )
    }
}
