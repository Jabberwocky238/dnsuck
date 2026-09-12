use anyhow::{Context, Result};
use async_graphql::InputObject;
use base64::{Engine, engine::general_purpose::STANDARD};
use hickory_server::proto::{
    op::{Message, MessageType, OpCode},
    rr::{Name, RData, Record, RecordType, rdata::NULL},
    serialize::binary::{BinEncodable, BinEncoder},
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

#[derive(Clone, Debug, PartialEq)]
pub struct StoredRecord {
    pub key: String,
    pub record: Record,
    pub template: Option<String>,
}
impl std::ops::Deref for StoredRecord {
    type Target = Record;
    fn deref(&self) -> &Record {
        &self.record
    }
}

impl std::ops::DerefMut for StoredRecord {
    fn deref_mut(&mut self) -> &mut Record {
        &mut self.record
    }
}

fn placeholders() -> &'static regex::Regex {
    static PLACEHOLDERS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PLACEHOLDERS.get_or_init(|| regex::Regex::new(r"\{([0-9]+)\}").unwrap())
}

impl StoredRecord {
    pub(crate) fn materialize(
        &self,
        owner: &Name,
        captures: &regex::Captures<'_>,
    ) -> Result<Record> {
        let Some(template) = &self.template else {
            let mut record = self.record.clone();
            record.name = owner.clone();
            return Ok(record);
        };
        let mut text = String::new();
        let mut end = 0;
        for placeholder in placeholders().captures_iter(template) {
            let span = placeholder.get(0).unwrap();
            text.push_str(&template[end..span.start()]);
            let index: usize = placeholder[1].parse()?;
            let value = captures
                .get(index + 1)
                .context("template capture did not participate in match")?;
            text.push_str(value.as_str());
            end = span.end();
        }
        text.push_str(&template[end..]);
        // Parse the expanded text as ordinary RDATA; never interpret it as another template.
        let record = RecordInput {
            name: owner.to_ascii(),
            record_type: format!("TYPE{}", u16::from(self.record_type())),
            ttl: self.ttl,
            data: Some(text),
            rdata_base64: None,
        };
        Ok(record.into_static_record()?.record)
    }
}

pub(crate) fn parse_name(text: &str) -> Result<Name> {
    let mut name = Name::from_ascii(text)?;
    name.set_fqdn(true);
    Ok(name)
}

pub(crate) fn name_text(name: &Name) -> String {
    name.to_ascii()
}

pub(crate) fn is_pattern(text: &str) -> bool {
    text.contains('(') || text.contains('*')
}

pub(crate) fn canonical(text: &str) -> Result<String> {
    if is_pattern(text) {
        return Ok(pattern(text)?.0);
    }
    Ok(parse_name(text)?.to_lowercase().to_ascii())
}

/// Parse only the domain envelope here. regex-syntax owns group boundaries,
/// nested groups, escapes, character classes, and regex validation.
pub(crate) fn pattern(text: &str) -> Result<(String, regex::Regex, usize)> {
    anyhow::ensure!(text.len() <= 480, "domain pattern exceeds 480 bytes");
    let lower = text.to_ascii_lowercase();
    let mut prefix = "qzxvjk0123456789_"
        .chars()
        .find(|&c| !lower.contains(c))
        .map(|c| c.to_string())
        .unwrap_or_else(|| "_r".into());
    while text.to_ascii_lowercase().contains(&prefix) {
        prefix.push('_');
    }
    let mut groups = std::collections::VecDeque::new();
    let mut envelope = String::new();
    let mut remaining = text;
    while let Some(start) = remaining.find('(') {
        envelope.push_str(&remaining[..start]);
        let expression = &remaining[start..];
        let end = expression
            .match_indices(')')
            .map(|(end, _)| end + 1)
            .find(|&end| {
                matches!(
                    regex_syntax::ast::parse::Parser::new().parse(&expression[..end]),
                    Ok(regex_syntax::ast::Ast::Group(_))
                )
            })
            .context("invalid or unclosed parenthesized regex")?;
        groups.push_back(expression[..end].to_owned());
        envelope.push_str(&prefix);
        remaining = &expression[end..];
    }
    envelope.push_str(remaining);
    anyhow::ensure!(!envelope.contains("**"), "** was removed; use * or (.+)");
    let name = parse_name(&envelope)?.to_lowercase();
    let mut keys = Vec::new();
    let mut expressions = Vec::new();
    let mut fixed = 0;
    for label in name.iter() {
        let literal = Name::from_labels([label])?.to_ascii();
        let literal = literal.strip_suffix('.').expect("absolute label");
        if literal == prefix {
            let expression = groups.pop_front().context("invalid regex segment")?;
            keys.push(expression.clone());
            expressions.push(expression);
        } else if label == b"*" {
            keys.push("*".into());
            expressions.push(r"((?:\\.|[^.\\])+)".into());
        } else {
            anyhow::ensure!(
                !literal.contains(&prefix),
                "regex groups must occupy whole domain segments"
            );
            fixed += 1;
            keys.push(literal.into());
            expressions.push(regex::escape(literal));
        }
    }
    anyhow::ensure!(
        groups.is_empty(),
        "regex groups must occupy whole domain segments"
    );
    let expression = format!(r"\A(?:{})\z", expressions.join(r"\."));
    let regex = regex::RegexBuilder::new(&expression)
        .case_insensitive(true)
        .size_limit(256 * 1024)
        .build()
        .context("invalid domain regex")?;
    Ok((format!("{}.", keys.join(".")), regex, fixed))
}

pub fn record_type(value: &str) -> Result<RecordType> {
    let kind: domain::base::iana::Rtype = value.to_ascii_uppercase().parse()?;
    Ok(RecordType::from(kind.to_int()))
}

impl RecordInput {
    pub fn into_record(self) -> Result<StoredRecord> {
        if let Some(text) = &self.data
            && placeholders().is_match(text)
            && is_pattern(&self.name)
        {
            anyhow::ensure!(
                self.rdata_base64.is_none(),
                "supply exactly one of data or rdataBase64"
            );
            let (key, regex, _) = pattern(&self.name)?;
            for capture in placeholders().captures_iter(text) {
                let index: usize = capture[1].parse().context("invalid capture index")?;
                anyhow::ensure!(
                    index < regex.captures_len() - 1,
                    "capture index {{{index}}} out of range"
                );
            }
            let kind = record_type(&self.record_type)?;
            anyhow::ensure!(
                !matches!(u16::from(kind), 0 | 41 | 249..=255),
                "query/pseudo types cannot be stored"
            );
            return Ok(StoredRecord {
                key,
                record: Record::from_rdata(
                    Name::root(),
                    self.ttl,
                    RData::Unknown {
                        code: kind,
                        rdata: NULL::new(),
                    },
                ),
                template: self.data,
            });
        }
        self.into_static_record()
    }

    fn into_static_record(self) -> Result<StoredRecord> {
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
        let key = canonical(&self.name)?;
        let owner = if is_pattern(&key) {
            Name::root()
        } else {
            parse_name(&key)?
        };
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message
            .answers
            .push(Record::from_rdata(owner, self.ttl, data));
        // Let Hickory validate binary RDATA for known types before any LMDB write.
        Ok(StoredRecord {
            key,
            template: None,
            record: Message::from_vec(&message.to_vec()?)?.answers.remove(0),
        })
    }
}

pub fn decode_inputs(inputs: Vec<RecordInput>) -> Result<Vec<StoredRecord>> {
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
