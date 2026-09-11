pub mod config;
pub mod dnslogic;
pub mod graphql;
pub mod transport;

pub use dnslogic::{
    records::{RecordInput, decode_inputs},
    resolver::DnsHandler,
    store::Store,
};
