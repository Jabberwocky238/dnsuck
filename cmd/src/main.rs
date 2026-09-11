mod batch;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    name = "dnsuck",
    about = "Manage the LMDB DNS server through GraphQL",
    version = env!("DNSUCK_BUILD_VERSION"),
    long_version = concat!(env!("DNSUCK_BUILD_VERSION"), "\nBuilt: ", env!("DNSUCK_BUILD_TIME"), "\nCommit: ", env!("DNSUCK_BUILD_COMMIT")),
    after_help = concat!("Version: ", env!("DNSUCK_BUILD_VERSION"), "\nBuilt: ", env!("DNSUCK_BUILD_TIME"), "\nCommit: ", env!("DNSUCK_BUILD_COMMIT"))
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:3080/graphql", global = true)]
    endpoint: String,
    #[arg(long, global = true)]
    ca_cert: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Execute get/add/put/del CSV items in order, stopping at the first error.
    Batch {
        #[arg(long = "item", required = true)]
        items: Vec<String>,
    },
    /// Delete one value, or the entire RRset when no value is given.
    Del {
        domain: String,
        record_type: String,
        value: Option<String>,
        #[arg(long, requires = "value")]
        raw: bool,
    },
    /// Get records of the requested type.
    Get { domain: String, record_type: String },
    /// Append a distinct record, preserving existing values.
    Add(WriteArgs),
    /// Replace the requested RRset with this value (set is an alias).
    #[command(visible_alias = "set")]
    Put(WriteArgs),
}

#[derive(clap::Args)]
struct WriteArgs {
    /// Order all returned records: best-effort lb, geo country match, or random.
    #[arg(long, value_enum)]
    mode: Option<OrderMode>,
    /// Exact name, * (one layer), or parenthesized Rust regex segments, e.g. (.+).
    domain: String,
    record_type: String,
    value: String,
    #[arg(long, default_value_t = 300)]
    ttl: u32,
    /// Interpret value as base64-encoded wire RDATA.
    #[arg(long)]
    raw: bool,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum OrderMode {
    Lb,
    Geo,
    Random,
}
impl OrderMode {
    fn graphql(self) -> &'static str {
        match self {
            Self::Lb => "LB",
            Self::Geo => "GEO",
            Self::Random => "RANDOM",
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let url = reqwest::Url::parse(&args.endpoint).context("invalid API endpoint")?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "GraphQL endpoint must use HTTP or HTTPS"
    );
    let (commands, is_batch) = match args.command {
        Command::Batch { items } => (batch::parse(items)?, true),
        command => (vec![command], false),
    };
    let mut client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(path) = args.ca_cert {
        client = client.add_root_certificate(reqwest::Certificate::from_pem(
            &std::fs::read(path).context("reading API CA certificate")?,
        )?);
    }
    let client = client.build()?;
    let mut results = Vec::with_capacity(commands.len());
    for (index, command) in commands.into_iter().enumerate() {
        let result = execute(&client, &url, command).with_context(|| {
            if is_batch {
                format!(
                    "batch item {} failed; earlier items have already completed",
                    index + 1
                )
            } else {
                "command failed".to_owned()
            }
        })?;
        results.push(result);
    }
    let output = if is_batch {
        Value::Array(results)
    } else {
        results.remove(0)
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn execute(
    client: &reqwest::blocking::Client,
    url: &reqwest::Url,
    command: Command,
) -> Result<Value> {
    let append = matches!(&command, Command::Add(_));
    let (query, variables) = match command {
        Command::Del {
            domain,
            record_type,
            value,
            raw,
        } => (
            "mutation($name:String!,$type:String,$data:String,$raw:String){delete(name:$name,recordType:$type,data:$data,rdataBase64:$raw)}",
            json!({"name":domain,"type":record_type,"data":if raw {None} else {value.clone()},"raw":if raw {value} else {None}}),
        ),
        Command::Get {
            domain,
            record_type,
        } => (
            "query($name:String!,$type:String){records(name:$name,recordType:$type){name recordType ttl data mode}}",
            json!({"name":domain,"type":record_type}),
        ),
        Command::Put(WriteArgs {
            domain,
            record_type,
            value,
            ttl,
            raw,
            mode,
        })
        | Command::Add(WriteArgs {
            domain,
            record_type,
            value,
            ttl,
            raw,
            mode,
        }) => {
            let mut record = json!({"name":domain,"recordType":record_type,"ttl":ttl});
            record[if raw { "rdataBase64" } else { "data" }] = json!(value);
            (
                if append {
                    "mutation($records:[RecordInput!]!,$mode:OrderMode){add(records:$records,mode:$mode)}"
                } else {
                    "mutation($records:[RecordInput!]!,$mode:OrderMode){upsert(records:$records,mode:$mode)}"
                },
                json!({"records":[record], "mode":mode.map(OrderMode::graphql)}),
            )
        }
        Command::Batch { .. } => anyhow::bail!("nested batches are not supported"),
    };
    let request = client.post(url.clone());
    let result: Value = request
        .json(&json!({"query":query,"variables":variables}))
        .send()
        .context("GraphQL request failed")?
        .error_for_status()
        .context("GraphQL HTTP error")?
        .json()?;
    if let Some(errors) = result.get("errors").and_then(Value::as_array)
        && !errors.is_empty()
    {
        anyhow::bail!("GraphQL errors: {}", serde_json::to_string(errors)?);
    }
    Ok(result["data"].clone())
}
