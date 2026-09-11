use dnsuck::Store;
use hickory_server::proto::rr::{RData, RecordType};

#[test]
fn records_persist_and_address_families_are_independent() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    {
        let store = Store::open(dir.path())?;
        store.put("Example.TEST", "192.0.2.1".parse()?, 60)?;
        store.put("example.test.", "2001:db8::1".parse()?, 120)?;
        store.put("EXAMPLE.TEST", "192.0.2.2".parse()?, 90)?;
    }
    let store = Store::open(dir.path())?;
    let a = store.lookup("EXAMPLE.test.", RecordType::A)?.unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].ttl, 90);
    assert!(matches!(&a[0].data, RData::A(ip) if ip.to_string() == "192.0.2.2"));
    let aaaa = store.lookup("example.test", RecordType::AAAA)?.unwrap();
    assert_eq!(aaaa.len(), 1);
    assert_eq!(aaaa[0].ttl, 120);
    assert!(store.lookup("missing.test", RecordType::A)?.is_none());
    assert!(
        store
            .lookup("example.test", RecordType::TXT)?
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .put(
                &format!("{}.test", "x".repeat(64)),
                "192.0.2.1".parse()?,
                60
            )
            .is_err()
    );
    Ok(())
}

fn input(name: &str, kind: &str, data: &str) -> dnsuck::RecordInput {
    dnsuck::RecordInput {
        name: name.into(),
        record_type: kind.into(),
        ttl: 60,
        data: Some(data.into()),
        rdata_base64: None,
    }
}

#[test]
fn structured_inputs_and_atomic_rrset_updates() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = Store::open(dir.path())?;
    store.put_records(dnsuck::decode_inputs(vec![
        input("mail.test", "MX", "10 mail1.test."),
        input("mail.test", "MX", "20 mail2.test."),
        input("example.test", "A", "192.0.2.1"),
        input("example.test", "AAAA", "2001:db8::1"),
        input("alias.test", "CNAME", "example.test."),
    ])?)?;
    assert_eq!(store.lookup("mail.test", RecordType::MX)?.unwrap().len(), 2);
    assert_eq!(
        store
            .lookup("example.test", RecordType::ANY)?
            .unwrap()
            .len(),
        2
    );
    assert_eq!(store.lookup("alias.test", RecordType::A)?.unwrap().len(), 2);
    let invalid = dnsuck::decode_inputs(vec![
        input("valid.test", "A", "192.0.2.1"),
        input("alias.test", "A", "192.0.2.2"),
    ])?;
    let revision = store.revision()?;
    assert!(store.put_records(invalid).is_err());
    assert_eq!(store.revision()?, revision);
    assert!(store.lookup("valid.test", RecordType::A)?.is_none());
    assert!(input("bad.test", "A", "invalid").into_record().is_err());
    let mut raw = input("raw.test", "TYPE65280", "unused");
    raw.data = None;
    raw.rdata_base64 = Some("3q2+7w==".into());
    store.put_records(vec![raw.clone().into_record()?])?;
    assert_eq!(store.records("raw.test")?.len(), 1);
    raw.data = Some("both".into());
    assert!(raw.into_record().is_err());
    assert!(input("bad.test", "ANY", "invalid").into_record().is_err());
    Ok(())
}
