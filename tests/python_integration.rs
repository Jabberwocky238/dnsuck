#[test]
fn python_dns_end_to_end() {
    let status = std::process::Command::new(
        std::env::var("DNS_TEST_PYTHON").unwrap_or_else(|_| "python3".into()),
    )
    .args([
        "-m",
        "unittest",
        "discover",
        "-s",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests"),
        "-p",
        "test_*.py",
        "-v",
    ])
    .env("DNS_TEST_BINARY", env!("CARGO_BIN_EXE_dnsuck"))
    .status()
    .expect("Python 3 is required for the DNS integration tests");
    assert!(status.success(), "Python DNS integration tests failed");
}
