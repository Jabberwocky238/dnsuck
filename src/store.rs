use crate::records::{OrderMode, OrderModes, canonical, mode_key};
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
use std::{collections::BTreeMap, fs, net::IpAddr, path::Path};

pub struct Store {
    env: Environment,
    db: Database,
    meta: Database,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        fs::create_dir_all(path).context("creating LMDB directory")?;
        let env = Environment::new()
            // Tokio reuses many blocking workers; release reader slots with each transaction.
            .set_flags(EnvironmentFlags::NO_TLS)
            .set_max_dbs(2)
            .set_map_size(64 * 1024 * 1024)
            .open(path)
            .context("opening LMDB")?;
        let db = env.create_db(Some("records"), DatabaseFlags::empty())?;
        let meta = env.create_db(Some("metadata"), DatabaseFlags::empty())?;
        Ok(Self { env, db, meta })
    }

    /// Replace the address RRset of the same family, preserving other types.
    pub fn put(&self, name: &str, ip: IpAddr, ttl: u32) -> Result<()> {
        let data = match ip {
            IpAddr::V4(ip) => RData::A(A(ip)),
            IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
        };
        self.put_records(vec![Record::from_rdata(
            Name::from_ascii(&canonical(name)?)?,
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
            record.name = Name::from_ascii(&key)?;
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
        let revision = self.revision_in(&txn)?;
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

    /// None means NXDOMAIN; an empty vector means NODATA. Follow local CNAMEs.
    pub fn lookup(&self, name: &str, kind: RecordType) -> Result<Option<Vec<Record>>> {
        let mut key = canonical(name)?;
        let txn = self.env.begin_ro_txn()?;
        let mut answers = Vec::new();
        for _ in 0..16 {
            let values = match txn.get(self.db, &key) {
                Ok(bytes) => decode(&key, bytes)?,
                Err(lmdb::Error::NotFound) => {
                    return Ok(if answers.is_empty() {
                        None
                    } else {
                        Some(answers)
                    });
                }
                Err(error) => return Err(error.into()),
            };
            let matching: Vec<_> = values
                .iter()
                .filter(|r| kind == RecordType::ANY || r.record_type() == kind)
                .cloned()
                .collect();
            if !matching.is_empty() {
                answers.extend(matching);
                return Ok(Some(answers));
            }
            if let Some(cname) = values.iter().find(|r| r.record_type() == RecordType::CNAME)
                && let RData::CNAME(target) = &cname.data
            {
                key = canonical(&target.0.to_ascii())?;
                answers.push(cname.clone());
                continue;
            }
            return Ok(Some(answers));
        }
        anyhow::bail!("CNAME loop or chain longer than 16 records")
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
            Ok(Record::from_rdata(
                Name::from_ascii(key)?,
                ttl.parse()?,
                data,
            ))
        })
        .collect()
}
