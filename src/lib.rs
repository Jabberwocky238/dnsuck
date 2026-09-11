pub mod config;
pub mod dnssec;
pub mod doh;
pub mod doq;
pub mod dot;
pub mod graphql;
pub mod records;
pub mod resolver;
pub mod store;

pub use records::{RecordInput, decode_inputs};
pub use resolver::DnsHandler;
pub use store::Store;
