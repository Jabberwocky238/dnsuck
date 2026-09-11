use anyhow::{Context, Result};
use async_graphql::InputObject;
use base64::{Engine, engine::general_purpose::STANDARD};
use hickory_server::proto::{
    op::{Message, MessageType, OpCode},
    rr::{Name, RData, Record, RecordType, rdata::NULL},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, InputObject)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordInput {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub data: Option<String>,
    pub rdata_base64: Option<String>,
}

pub(crate) fn canonical(name: &str) -> Result<String> {
    let name = parse_name(name)?.to_lowercase();
    Ok(name_text(&name))
}

/// Keep DNS name parsing in existing libraries; Hickory's text parser rejects **.
pub(crate) fn parse_name(text: &str) -> Result<Name> {
    let mut name = match Name::from_ascii(text) {
        Ok(name) => name,
        Err(error) => {
            let parsed: domain::base::Name<Vec<u8>> = text.parse()?;
            if !parsed.iter().any(|label| label.as_ref() == b"**") {
                return Err(error.into());
            }
            Name::read(&mut BinDecoder::new(parsed.as_slice()))?
        }
    };
    name.set_fqdn(true);
    Ok(name)
}

pub(crate) fn name_text(name: &Name) -> String {
    if !name.iter().any(|label| label == b"**") {
        return name.to_ascii();
    }
    let labels: Vec<_> = name
        .iter()
        .map(|label| {
            if label == b"**" {
                "**".to_string()
            } else {
                Name::from_labels([label])
                    .expect("validated label")
                    .to_ascii()
                    .strip_suffix('.')
                    .expect("absolute label")
                    .to_string()
            }
        })
        .collect();
    format!("{}.", labels.join("."))
}

pub fn record_type(value: &str) -> Result<RecordType> {
    let kind: domain::base::iana::Rtype = value.to_ascii_uppercase().parse()?;
    Ok(RecordType::from(kind.to_int()))
}

impl RecordInput {
    pub fn into_record(self) -> Result<Record> {
        let kind = record_type(&self.record_type)?;
        anyhow::ensure!(
            !matches!(u16::from(kind), 0 | 41 | 249..=255),
            "query/pseudo types cannot be stored"
        );
        let data = match (self.data, self.rdata_base64) {
            (Some(text), None) => {
                if u16::from(kind) == 99 {
                    let txt = RData::try_from_str(RecordType::TXT, &text)?;
                    let mut bytes = Vec::new();
                    txt.emit(&mut BinEncoder::new(&mut bytes))?;
                    RData::Unknown {
                        code: kind,
                        rdata: NULL::with(bytes),
                    }
                } else {
                    RData::try_from_str(kind, &text)
                        .context("unsupported RDATA text; supply rdataBase64 for this type")?
                }
            }
            (None, Some(encoded)) => RData::Unknown {
                code: kind,
                rdata: NULL::with(STANDARD.decode(encoded)?),
            },
            _ => anyhow::bail!("supply exactly one of data or rdataBase64"),
        };
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.answers.push(Record::from_rdata(
            parse_name(&canonical(&self.name)?)?,
            self.ttl,
            data,
        ));
        // Let Hickory validate binary RDATA for known types before any LMDB write.
        Ok(Message::from_vec(&message.to_vec()?)?.answers.remove(0))
    }
}

pub fn decode_inputs(inputs: Vec<RecordInput>) -> Result<Vec<Record>> {
    inputs.into_iter().map(RecordInput::into_record).collect()
}

/// Ordering changes only the order of records, never their membership.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, async_graphql::Enum,
)]
#[serde(rename_all = "lowercase")]
pub enum OrderMode {
    Lb,
    Geo,
    Random,
}

pub type OrderModes = std::collections::BTreeMap<(String, u16), OrderMode>;

pub(crate) fn mode_key(name: &str, kind: RecordType) -> String {
    format!("mode:{}:{name}", u16::from(kind))
}
