use crate::records::{OrderMode, OrderModes, canonical, mode_key, parse_name};
use anyhow::{Context, Result};
use hickory_server::proto::{
    op::{Message, MessageType, OpCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use lmdb::{
    Cursor, Database, DatabaseFlags, Environment, EnvironmentFlags, Transaction, WriteFlags,
};
use std::{collections::BTreeMap, fs, net::IpAddr, path::Path, sync::Mutex};

pub struct Store {
    env: Environment,
    db: Database,
    meta: Database,
    wildcards: Mutex<Option<(u64, Wildcards)>>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        fs::create_dir_all(path).context("creating LMDB directory")?;
        let env = Environment::new()
            // Tokio reuses many blocking workers; release reader slots with each transaction.
            .set_flags(EnvironmentFlags::NO_TLS)
            .set_max_readers(1024)
            .set_max_dbs(2)
            .set_map_size(64 * 1024 * 1024)
            .open(path)
            .context("opening LMDB")?;
        let db = env.create_db(Some("records"), DatabaseFlags::empty())?;
        let meta = env.create_db(Some("metadata"), DatabaseFlags::empty())?;
        Ok(Self {
            env,
            db,
            meta,
            wildcards: Mutex::new(None),
        })
    }

    /// Replace the address RRset of the same family, preserving other types.
    pub fn put(&self, name: &str, ip: IpAddr, ttl: u32) -> Result<()> {
        let data = match ip {
            IpAddr::V4(ip) => RData::A(A(ip)),
            IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
        };
        self.put_records(vec![Record::from_rdata(
            parse_name(&canonical(name)?)?,
            ttl,
            data,
        )])?;
        Ok(())
    }

    /// Atomically replace the supplied RRsets, preserving other names/types.
    pub fn put_records(&self, records: Vec<Record>) -> Result<usize> {
        self.write_records(records, true, None)
    }

    /// Append distinct records atomically, preserving existing RRsets.
    pub fn add_records(&self, records: Vec<Record>) -> Result<usize> {
        self.write_records(records, false, None)
    }

    pub fn write_records(
        &self,
        records: Vec<Record>,
        replace: bool,
        mode: Option<OrderMode>,
    ) -> Result<usize> {
        let count = records.len();
        let mut added = 0;
        let mut changed = false;
        let mut groups: BTreeMap<String, Vec<Record>> = BTreeMap::new();
        for mut record in records {
            let key = canonical(&record.name.to_ascii())?;
            record.name = parse_name(&key)?;
            groups.entry(key).or_default().push(record);
        }
        let mut txn = self.env.begin_rw_txn()?;
        for (key, incoming) in groups {
            let mut values = match txn.get(self.db, &key) {
                Ok(bytes) => decode(&key, bytes)?,
                Err(lmdb::Error::NotFound) => Vec::new(),
                Err(error) => return Err(error.into()),
            };
            if let Some(mode) = mode {
                for record in &incoming {
                    anyhow::ensure!(
                        mode != OrderMode::Geo
                            || matches!(record.record_type(), RecordType::A | RecordType::AAAA),
                        "geo ordering requires A or AAAA records"
                    );
                    let key = mode_key(&key, record.record_type());
                    let bytes = serde_json::to_vec(&mode)?;
                    if txn.get(self.meta, &key).ok() != Some(bytes.as_slice()) {
                        txn.put(self.meta, &key, &bytes, WriteFlags::empty())?;
                        changed = true;
                    }
                }
            }
            let old_len = values.len();
            if replace {
                values.retain(|old| {
                    !incoming
                        .iter()
                        .any(|new| new.record_type() == old.record_type())
                });
            }
            values.extend(incoming);
            // Validate TTLs before deduplication: DNS record equality can omit TTL.
            for record in &values {
                anyhow::ensure!(
                    values
                        .iter()
                        .filter(|r| r.record_type() == record.record_type())
                        .all(|r| r.ttl == record.ttl),
                    "RRset TTLs must match at {key}"
                );
            }
            let mut unique = Vec::with_capacity(values.len());
            for record in values {
                if !unique.contains(&record) {
                    unique.push(record);
                }
            }
            let values = unique;
            let cnames = values
                .iter()
                .filter(|r| r.record_type() == RecordType::CNAME)
                .count();
            anyhow::ensure!(
                cnames == 0
                    || (cnames == 1
                        && values.iter().all(|r| matches!(
                            r.record_type(),
                            RecordType::CNAME | RecordType::RRSIG | RecordType::NSEC
                        ))),
                "CNAME must be the only record at {key}"
            );
            if !replace {
                let new_count = values.len().saturating_sub(old_len);
                added += new_count;
                if new_count == 0 {
                    continue;
                }
            }
            changed = true;
            let mut message = Message::new(0, MessageType::Response, OpCode::Query);
            message.answers = values;
            let mut bytes = b"DNS1".to_vec();
            bytes.extend(message.to_vec()?);
            txn.put(self.db, &key, &bytes, WriteFlags::empty())?;
        }
        if changed {
            self.bump_revision(&mut txn)?;
        }
        txn.commit()?;
        Ok(if replace { count } else { added })
    }

    /// Persisted per-RRset ordering policies; lb cursors are never stored here.
    pub fn modes(&self) -> Result<OrderModes> {
        let txn = self.env.begin_ro_txn()?;
        let mut cursor = txn.open_ro_cursor(self.meta)?;
        let mut modes = OrderModes::new();
        for (key, value) in cursor.iter() {
            let key = std::str::from_utf8(key)?;
            if let Some(key) = key.strip_prefix("mode:") {
                let (kind, name) = key.split_once(':').context("invalid ordering key")?;
                modes.insert((name.into(), kind.parse()?), serde_json::from_slice(value)?);
            }
        }
        Ok(modes)
    }

    fn revision_in(&self, txn: &impl Transaction) -> Result<u64> {
        match txn.get(self.meta, &"revision") {
            Ok(bytes) => Ok(u64::from_be_bytes(bytes.try_into()?)),
            Err(lmdb::Error::NotFound) => Ok(0),
            Err(error) => Err(error.into()),
        }
    }

    fn bump_revision(&self, txn: &mut lmdb::RwTransaction<'_>) -> Result<()> {
        let revision = self
            .revision_in(txn)?
            .checked_add(1)
            .context("revision overflow")?;
        txn.put(
            self.meta,
            &"revision",
            &revision.to_be_bytes(),
            WriteFlags::empty(),
        )?;
        Ok(())
    }

    pub fn revision(&self) -> Result<u64> {
        self.revision_in(&self.env.begin_ro_txn()?)
    }

    pub fn snapshot(&self) -> Result<(u64, Vec<Record>)> {
        let txn = self.env.begin_ro_txn()?;
        self.snapshot_in(&txn)
    }

    fn snapshot_in(&self, txn: &impl Transaction) -> Result<(u64, Vec<Record>)> {
        let revision = self.revision_in(txn)?;
        let mut cursor = txn.open_ro_cursor(self.db)?;
        let mut records = Vec::new();
        for (key, bytes) in cursor.iter() {
            records.extend(decode(std::str::from_utf8(key)?, bytes)?);
        }
        Ok((revision, records))
    }

    pub fn records(&self, name: &str) -> Result<Vec<Record>> {
        let key = canonical(name)?;
        let txn = self.env.begin_ro_txn()?;
        match txn.get(self.db, &key) {
            Ok(bytes) => decode(&key, bytes),
            Err(lmdb::Error::NotFound) => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn names(&self, prefix: &str, after: &str, limit: usize) -> Result<Vec<String>> {
        let txn = self.env.begin_ro_txn()?;
        let mut cursor = txn.open_ro_cursor(self.db)?;
        let mut names = Vec::new();
        let prefix = prefix.to_ascii_lowercase();
        for (key, _) in cursor.iter() {
            let name = std::str::from_utf8(key)?;
            if name > after && name.starts_with(&prefix) {
                names.push(name.to_owned());
                if names.len() == limit {
                    break;
                }
            }
        }
        Ok(names)
    }

    pub fn delete(&self, name: &str, kind: Option<RecordType>) -> Result<usize> {
        self.delete_matching(name, kind, None)
    }

    pub fn delete_record(&self, record: &Record) -> Result<usize> {
        self.delete_matching(
            &record.name.to_ascii(),
            Some(record.record_type()),
            Some(&record.data),
        )
    }

    fn delete_matching(
        &self,
        name: &str,
        kind: Option<RecordType>,
        data: Option<&RData>,
    ) -> Result<usize> {
        let key = canonical(name)?;
        let mut txn = self.env.begin_rw_txn()?;
        let mut records = match txn.get(self.db, &key) {
            Ok(bytes) => decode(&key, bytes)?,
            Err(lmdb::Error::NotFound) => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        let removed_types: Vec<_> = records
            .iter()
            .filter(|record| kind.is_none_or(|kind| record.record_type() == kind))
            .map(|record| record.record_type())
            .collect();
        let before = records.len();
        records.retain(|record| {
            kind.is_some_and(|kind| record.record_type() != kind)
                || data.is_some_and(|data| &record.data != data)
        });
        let deleted = before - records.len();
        if deleted == 0 {
            return Ok(0);
        }
        for kind in removed_types {
            if records.iter().any(|record| record.record_type() == kind) {
                continue;
            }
            match txn.del(self.meta, &mode_key(&key, kind), None) {
                Ok(()) | Err(lmdb::Error::NotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if records.is_empty() {
            txn.del(self.db, &key, None)?;
        } else {
            let mut message = Message::new(0, MessageType::Response, OpCode::Query);
            message.answers = records;
            let mut bytes = b"DNS1".to_vec();
            bytes.extend(message.to_vec()?);
            txn.put(self.db, &key, &bytes, WriteFlags::empty())?;
        }
        self.bump_revision(&mut txn)?;
        txn.commit()?;
        Ok(deleted)
    }

    /// Resolve exact names first, then whole-label wildcard patterns.
    fn source_in(&self, txn: &impl Transaction, key: &str) -> Result<Option<String>> {
        match txn.get(self.db, &key) {
            Ok(_) => return Ok(Some(key.into())),
            Err(lmdb::Error::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        let revision = self.revision_in(txn)?;
        let mut cached = self
            .wildcards
            .lock()
            .map_err(|_| anyhow::anyhow!("wildcard cache poisoned"))?;
        if cached
            .as_ref()
            .is_none_or(|(stored, _)| *stored != revision)
        {
            let mut index = Wildcards::default();
            let mut cursor = txn.open_ro_cursor(self.db)?;
            for (key, _) in cursor.iter() {
                let key = std::str::from_utf8(key)?;
                // Canonical names escape embedded dots; Hickory owns label parsing.
                if key.contains('*') {
                    let name = parse_name(key)?;
                    if has_wildcard(&name) {
                        index.insert(&name, key);
                    }
                }
            }
            *cached = Some((revision, index));
        }
        let name = parse_name(key)?;
        Ok(cached
            .as_ref()
            .expect("initialized wildcard index")
            .1
            .find(&name))
    }

    pub(crate) fn sources(&self, records: &[Record]) -> Result<BTreeMap<String, String>> {
        let txn = self.env.begin_ro_txn()?;
        let mut sources = BTreeMap::new();
        for record in records {
            let key = canonical(&record.name.to_ascii())?;
            if !sources.contains_key(&key)
                && let Some(source) = self.source_in(&txn, &key)?
            {
                sources.insert(key, source);
            }
        }
        Ok(sources)
    }

    /// A signed query gets concrete synthesized owners and the same LMDB snapshot.
    pub(crate) fn snapshot_for_query(
        &self,
        name: &str,
        kind: RecordType,
    ) -> Result<Option<(u64, Vec<Record>)>> {
        let txn = self.env.begin_ro_txn()?;
        let (_, synthesized) = self.lookup_in(&txn, name, kind)?;
        if synthesized.is_empty() {
            return Ok(None);
        }
        let (revision, mut records) = self.snapshot_in(&txn)?;
        records.retain(|record| !has_wildcard(&record.name));
        records.extend(synthesized);
        Ok(Some((revision, records)))
    }

    /// None means NXDOMAIN; an empty vector means NODATA. Follow local CNAMEs.
    pub fn lookup(&self, name: &str, kind: RecordType) -> Result<Option<Vec<Record>>> {
        Ok(self.lookup_in(&self.env.begin_ro_txn()?, name, kind)?.0)
    }

    fn lookup_in(
        &self,
        txn: &impl Transaction,
        name: &str,
        kind: RecordType,
    ) -> Result<(Option<Vec<Record>>, Vec<Record>)> {
        let mut key = canonical(name)?;
        let mut answers = Vec::new();
        let mut synthesized = Vec::new();
        for _ in 0..16 {
            let Some(source) = self.source_in(txn, &key)? else {
                return Ok((
                    if answers.is_empty() {
                        None
                    } else {
                        Some(answers)
                    },
                    synthesized,
                ));
            };
            let mut values = decode(&source, txn.get(self.db, &source)?)?;
            let owner = parse_name(&key)?;
            if source != key || has_wildcard(&owner) {
                for record in &mut values {
                    record.name = owner.clone();
                }
                // Include every type for correct signed NODATA proofs.
                synthesized.extend(values.iter().cloned());
            }
            let matching: Vec<_> = values
                .iter()
                .filter(|r| kind == RecordType::ANY || r.record_type() == kind)
                .cloned()
                .collect();
            if !matching.is_empty() {
                answers.extend(matching);
                return Ok((Some(answers), synthesized));
            }
            if let Some(cname) = values.iter().find(|r| r.record_type() == RecordType::CNAME)
                && let RData::CNAME(target) = &cname.data
            {
                key = canonical(&target.0.to_ascii())?;
                answers.push(cname.clone());
                continue;
            }
            return Ok((Some(answers), synthesized));
        }
        anyhow::bail!("CNAME loop or chain longer than 16 records")
    }
}

pub(crate) fn has_wildcard(name: &Name) -> bool {
    name.iter().any(|label| label == b"*" || label == b"**")
}

/// Reverse-label trie, rebuilt from LMDB keys only when its revision changes.
#[derive(Default)]
struct Wildcards {
    children: BTreeMap<Vec<u8>, Wildcards>,
    pattern: Option<WildcardPattern>,
}

struct WildcardPattern {
    key: String,
    rank: (usize, usize, Vec<u8>),
}

impl Wildcards {
    fn insert(&mut self, name: &Name, key: &str) {
        let rank: Vec<_> = name
            .iter()
            .rev()
            .map(|label| match label {
                b"**" => 0,
                b"*" => 1,
                _ => 2,
            })
            .collect();
        let fixed = rank.iter().filter(|&&v| v == 2).count();
        let single = rank.iter().filter(|&&v| v == 1).count();
        let mut node = self;
        for label in name.iter().rev() {
            node = node.children.entry(label.to_vec()).or_default();
        }
        node.pattern = Some(WildcardPattern {
            key: key.into(),
            rank: (fixed, single, rank),
        });
    }

    fn find(&self, name: &Name) -> Option<String> {
        let labels: Vec<_> = name.iter().rev().collect();
        let mut best = None;
        let mut visited = std::collections::HashSet::new();
        self.search(&labels, &mut visited, &mut best);
        best.map(|pattern| pattern.key.clone())
    }

    fn search<'a>(
        &'a self,
        labels: &[&[u8]],
        visited: &mut std::collections::HashSet<(usize, usize)>,
        best: &mut Option<&'a WildcardPattern>,
    ) {
        // Repeated ** must not revisit every possible partition of the labels.
        if !visited.insert((self as *const Self as usize, labels.len())) {
            return;
        }
        let Some((label, rest)) = labels.split_first() else {
            if let Some(pattern) = &self.pattern
                && best.is_none_or(|old| {
                    pattern.rank > old.rank || (pattern.rank == old.rank && pattern.key < old.key)
                })
            {
                *best = Some(pattern);
            }
            return;
        };
        if *label != b"*"
            && *label != b"**"
            && let Some(child) = self.children.get(*label)
        {
            child.search(rest, visited, best);
        }
        if let Some(child) = self.children.get(b"*".as_slice()) {
            child.search(rest, visited, best);
        }
        if let Some(child) = self.children.get(b"**".as_slice()) {
            // ** consumes at least one complete label, never zero labels.
            for consumed in 1..=labels.len() {
                child.search(&labels[consumed..], visited, best);
            }
        }
    }
}

fn decode(key: &str, bytes: &[u8]) -> Result<Vec<Record>> {
    if let Some(wire) = bytes.strip_prefix(b"DNS1") {
        return Ok(Message::from_vec(wire)?.answers);
    }
    // Read the original address-only storage format without losing existing data.
    std::str::from_utf8(bytes)?
        .lines()
        .map(|line| {
            let (ttl, ip) = line.split_once(' ').context("invalid LMDB record")?;
            let data = match ip.parse()? {
                IpAddr::V4(ip) => RData::A(A(ip)),
                IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
            };
            Ok(Record::from_rdata(parse_name(key)?, ttl.parse()?, data))
        })
        .collect()
}
