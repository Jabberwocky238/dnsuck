use crate::Command;
use anyhow::{Context, Result};

/// Parse each --item with the csv crate, before making any HTTP requests.
pub fn parse(items: Vec<String>) -> Result<Vec<Command>> {
    items
        .into_iter()
        .enumerate()
        .map(|(index, item)| {
            parse_item(&item).with_context(|| format!("invalid batch item {}", index + 1))
        })
        .collect()
}

fn parse_item(item: &str) -> Result<Command> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(item.as_bytes());
    let rows = reader.records().collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(rows.len() == 1, "expected one CSV record per --item");
    let fields = &rows[0];
    anyhow::ensure!(
        fields.len() >= 3 && !fields[1].is_empty() && !fields[2].is_empty(),
        "expected get/del,domain,record or set,domain,record,value"
    );
    match (&fields[0], fields.len()) {
        ("del", 3) => Ok(Command::Del {
            domain: fields[1].into(),
            record_type: fields[2].into(),
        }),
        ("get", 3) => Ok(Command::Get {
            domain: fields[1].into(),
            record_type: fields[2].into(),
        }),
        ("set", 4) => Ok(Command::Set {
            domain: fields[1].into(),
            record_type: fields[2].into(),
            value: fields[3].into(),
            ttl: 300,
            raw: false,
        }),
        _ => anyhow::bail!("expected get/del,domain,record or set,domain,record,value"),
    }
}
