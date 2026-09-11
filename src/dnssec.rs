use crate::{Store, records::canonical};
use anyhow::{Context, Result};
use hickory_server::{
    dnssec::NxProofKind,
    proto::{
        dnssec::{Algorithm, DnssecSigner, SigningKey, crypto::EcdsaSigningKey, rdata::DNSKEY},
        rr::{Name, RData, Record, RecordType},
    },
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{AxfrPolicy, Catalog, ZoneType},
};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct Snapshot {
    revision: u64,
    created: Instant,
    catalog: Arc<Catalog>,
}

pub struct SignedZone {
    pub origin: Name,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    cached: Mutex<Option<Snapshot>>,
}

impl SignedZone {
    pub fn load(origin: &str, path: &Path) -> Result<Self> {
        let pem = std::fs::read(path).context("reading DNSSEC PKCS#8 PEM key")?;
        let key = rustls_pemfile::private_key(&mut pem.as_slice())?
            .context("no DNSSEC private key in PEM")?;
        EcdsaSigningKey::from_key_der(&key, Algorithm::ECDSAP256SHA256)?;
        Ok(Self {
            origin: Name::from_ascii(&canonical(origin)?)?,
            key,
            cached: Mutex::new(None),
        })
    }

    pub fn catalog(&self, store: &Store) -> Result<Arc<Catalog>> {
        let mut cache = self
            .cached
            .lock()
            .map_err(|_| anyhow::anyhow!("DNSSEC cache lock poisoned"))?;
        let revision = store.revision()?;
        if let Some(snapshot) = cache.as_ref()
            && snapshot.revision == revision
            && snapshot.created.elapsed() < Duration::from_secs(3600)
        {
            return Ok(snapshot.catalog.clone());
        }
        let (revision, mut records) = store.snapshot()?;
        // Patterns are templates, not RFC 4592 wildcard owners in the signed zone.
        let templates = records.iter().any(|record| {
            self.origin.zone_of(&record.name) && crate::store::has_wildcard(&record.name)
        });
        records.retain(|record| !crate::store::has_wildcard(&record.name));
        let catalog = self.build(revision, records, templates)?;
        *cache = Some(Snapshot {
            revision,
            created: Instant::now(),
            catalog: catalog.clone(),
        });
        Ok(catalog)
    }

    pub fn catalog_for(&self, store: &Store, name: &str, kind: RecordType) -> Result<Arc<Catalog>> {
        match store.snapshot_for_query(name, kind)? {
            Some((revision, records)) => self.build(revision, records, true),
            None => self.catalog(store),
        }
    }

    fn build(&self, revision: u64, records: Vec<Record>, templates: bool) -> Result<Arc<Catalog>> {
        let has_apex = |kind| {
            records
                .iter()
                .any(|r| r.name == self.origin && r.record_type() == kind)
        };
        anyhow::ensure!(
            has_apex(RecordType::SOA) && has_apex(RecordType::NS),
            "DNSSEC zone requires apex SOA and NS records"
        );
        let mut zone =
            InMemoryZoneHandler::<hickory_server::net::runtime::TokioRuntimeProvider>::empty(
                self.origin.clone(),
                ZoneType::Primary,
                AxfrPolicy::Deny,
                Some(NxProofKind::Nsec),
            );
        for mut record in records {
            if !self.origin.zone_of(&record.name)
                || matches!(
                    record.record_type(),
                    RecordType::DNSKEY
                        | RecordType::RRSIG
                        | RecordType::NSEC
                        | RecordType::NSEC3
                        | RecordType::NSEC3PARAM
                )
            {
                continue;
            }
            if let RData::SOA(soa) = &mut record.data {
                soa.serial = soa.serial.wrapping_add(revision as u32);
                // The concrete namespace is synthesized per query. Do not let
                // cached NSEC intervals suppress other matching template names.
                if templates {
                    soa.minimum = 0;
                }
            }
            anyhow::ensure!(
                zone.upsert_mut(record, revision as u32),
                "record rejected while building signed zone"
            );
        }
        let key = EcdsaSigningKey::from_key_der(&self.key, Algorithm::ECDSAP256SHA256)?;
        let public_key = key.to_public_key()?;
        let signer = DnssecSigner::new(
            DNSKEY::from_key(&public_key),
            Box::new(key),
            self.origin.clone(),
            Duration::from_secs(7 * 86400),
        );
        zone.add_zone_signing_key_mut(signer)?;
        zone.secure_zone_mut()?;
        let mut catalog = Catalog::new();
        catalog.upsert(self.origin.clone().into(), vec![Arc::new(zone)]);
        let catalog = Arc::new(catalog);
        Ok(catalog)
    }
}
