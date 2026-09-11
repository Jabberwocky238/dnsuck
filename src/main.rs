use anyhow::Result;
use clap::Parser;
use dnsuck::{
    RecordInput, Store,
    config::{Command, Config, request_reload},
    decode_inputs,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Config::parse();
    anyhow::ensure!(
        !(args.config.is_some() || args.reload) || args.command.is_none(),
        "-c and --reload cannot be combined with command parameters"
    );
    if args.reload {
        return request_reload().await;
    }
    let config = match &args.config {
        Some(path) => Config::from_file(path)?,
        None => args,
    };
    let store = Arc::new(Store::open(&config.database)?);
    if let Some(command) = &config.command {
        match command {
            Command::Put { name, ip, ttl } => {
                store.put(name, *ip, *ttl)?;
                println!("Stored {name} -> {ip} (TTL {ttl})");
            }
            Command::Record {
                name,
                record_type,
                data,
                ttl,
                raw,
            } => {
                let input = RecordInput {
                    name: name.clone(),
                    record_type: record_type.clone(),
                    ttl: *ttl,
                    data: (!raw).then(|| data.clone()),
                    rdata_base64: raw.then(|| data.clone()),
                };
                store.put_records(vec![input.into_record()?])?;
                println!("Stored record");
            }
            Command::Write => {
                let inputs: Vec<RecordInput> = serde_json::from_reader(std::io::stdin().lock())?;
                println!(
                    "Stored {} records",
                    store.put_records(decode_inputs(inputs)?)?
                );
            }
        }
        return Ok(());
    }
    dnsuck::config::serve(config, store).await
}
