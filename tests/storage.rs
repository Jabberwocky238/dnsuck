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

#[test]
fn appends_are_atomic_distinct_and_do_not_lose_concurrent_writes() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = Store::open(dir.path())?;
    let records = || {
        dnsuck::decode_inputs(vec![
            input("append.test", "A", "192.0.2.1"),
            input("append.test", "A", "192.0.2.2"),
            input("APPEND.TEST.", "A", "192.0.2.1"),
        ])
    };
    assert_eq!(store.add_records(records()?)?, 2);
    let revision = store.revision()?;
    assert_eq!(store.add_records(records()?)?, 0);
    assert_eq!(store.revision()?, revision);
    let mut mismatched = input("append.test", "A", "192.0.2.1");
    mismatched.ttl = 90;
    assert!(
        store
            .add_records(dnsuck::decode_inputs(vec![
                input("a-valid.test", "TXT", "\"rollback\""),
                mismatched,
            ])?)
            .is_err()
    );
    assert!(store.records("a-valid.test")?.is_empty());
    assert_eq!(store.revision()?, revision);
    assert!(
        store
            .add_records(dnsuck::decode_inputs(vec![input(
                "append.test",
                "CNAME",
                "target.test."
            ),])?)
            .is_err()
    );
    std::thread::scope(|scope| {
        let workers: Vec<_> = (3..=14)
            .map(|last| {
                let store = &store;
                scope.spawn(move || {
                    store
                        .add_records(dnsuck::decode_inputs(vec![input(
                            "append.test",
                            "A",
                            &format!("192.0.2.{last}"),
                        )])?)
                        .map(|_| ())
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap()?;
        }
        anyhow::Ok(())
    })?;
    assert_eq!(
        store.lookup("append.test", RecordType::A)?.unwrap().len(),
        14
    );
    store.put_records(dnsuck::decode_inputs(vec![input(
        "append.test",
        "A",
        "192.0.2.99",
    )])?)?;
    assert_eq!(
        store.lookup("append.test", RecordType::A)?.unwrap().len(),
        1
    );
    Ok(())
}

#[test]
fn reader_slots_are_released_between_blocking_workers() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = Store::open(dir.path())?;
    store.put("readers.test", "192.0.2.1".parse()?, 300)?;
    // Keep more workers alive than LMDB's default reader limit, with only one
    // transaction active at a time. Idle threads must not retain reader slots.
    let barrier = std::sync::Barrier::new(161);
    let (send, receive) = std::sync::mpsc::channel();
    let results = std::thread::scope(|scope| {
        let mut results = Vec::new();
        for _ in 0..160 {
            let (store, barrier, send) = (&store, &barrier, send.clone());
            scope.spawn(move || {
                let result = store.lookup("readers.test", RecordType::A);
                send.send(result.map(|records| records.unwrap().len()))
                    .unwrap();
                barrier.wait();
            });
            results.push(receive.recv().unwrap());
        }
        barrier.wait();
        results
    });
    for result in results {
        assert_eq!(result?, 1);
    }
    Ok(())
}

#[test]
fn regex_templates_preserve_keys_and_exact_overrides() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = Store::open(dir.path())?;
    let pattern = r"([a-z]+).literal.([0-9]+).test";
    store.put(pattern, "192.0.2.1".parse()?, 60)?;
    let query = "abc.literal.123.test";
    let records = store.lookup(query, RecordType::A)?.unwrap();
    assert_eq!(records[0].name.to_ascii(), format!("{query}."));
    assert_eq!(store.records(pattern)?[0].key, format!("{pattern}."));
    assert!(store.records(query)?.is_empty());
    store.put(query, "2001:db8::1".parse()?, 60)?;
    assert!(store.lookup(query, RecordType::A)?.unwrap().is_empty());
    store.delete(query, None)?;
    assert_eq!(store.lookup(query, RecordType::A)?.unwrap().len(), 1);
    store.delete(pattern, None)?;
    assert!(store.lookup(query, RecordType::A)?.is_none());
    Ok(())
}

#[test]
fn star_is_single_layer_and_double_star_is_replaced_by_regex() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = Store::open(dir.path())?;
    store.put("*.deep.test", "192.0.2.8".parse()?, 60)?;
    let nested = format!("{}nested.test", "(.).".repeat(80));
    store.put(&nested, "192.0.2.7".parse()?, 60)?;
    assert_eq!(
        store
            .lookup(&format!("{}nested.test", "x.".repeat(80)), RecordType::A)?
            .unwrap()
            .len(),
        1
    );
    let query = format!("{}deep.test", "x.".repeat(80));
    assert!(store.lookup(&query, RecordType::A)?.is_none());
    assert_eq!(
        store.lookup("x.deep.test", RecordType::A)?.unwrap().len(),
        1
    );
    store.put("(.+).multi.test", "192.0.2.6".parse()?, 60)?;
    assert_eq!(
        store
            .lookup(&format!("{}multi.test", "x.".repeat(80)), RecordType::A)?
            .unwrap()
            .len(),
        1
    );
    assert!(store.lookup("deep.test", RecordType::A)?.is_none());
    assert!(store.put("**.deep.test", "192.0.2.9".parse()?, 60).is_err());
    assert_eq!(store.names("*.", "", 10)?, vec!["*.deep.test."]);
    Ok(())
}
