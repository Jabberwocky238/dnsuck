use std::{env, path::Path, process::Command};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    for name in ["DNSUCK_RELEASE_VERSION", "SOURCE_DATE_EPOCH"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    for path in ["src", "Cargo.toml", "build.rs"] {
        if Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if env::var("CARGO_PKG_NAME").as_deref() == Ok("dnsctl") {
        println!("cargo:rerun-if-changed=../build.rs");
    }
    for path in [
        Some("HEAD".to_string()),
        Some("packed-refs".to_string()),
        git(&["symbolic-ref", "-q", "HEAD"]),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(path) = git(&["rev-parse", "--git-path", &path])
            && Path::new(&path).exists()
        {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let version = env::var("DNSUCK_RELEASE_VERSION")
        .ok()
        .or_else(|| git(&["describe", "--tags", "--exact-match"]))
        .unwrap_or_else(|| env::var("CARGO_PKG_VERSION").expect("Cargo package version"));
    assert!(
        !version.is_empty()
            && version
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)),
        "invalid build version"
    );
    let now = match env::var("SOURCE_DATE_EPOCH") {
        Ok(epoch) => OffsetDateTime::from_unix_timestamp(
            epoch.parse().expect("SOURCE_DATE_EPOCH must be an integer"),
        )
        .expect("valid SOURCE_DATE_EPOCH"),
        Err(_) => OffsetDateTime::now_utc(),
    };
    println!("cargo:rustc-env=DNSUCK_BUILD_VERSION={version}");
    println!(
        "cargo:rustc-env=DNSUCK_BUILD_TIME={}",
        now.replace_nanosecond(0)
            .expect("zero nanoseconds")
            .format(&Rfc3339)
            .expect("format UTC build time")
    );
    println!(
        "cargo:rustc-env=DNSUCK_BUILD_COMMIT={}",
        git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into())
    );
}
