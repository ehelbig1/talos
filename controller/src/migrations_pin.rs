//! What the migrator embedded in THIS binary will compare against the
//! database's record of applied migrations.
//!
//! Two programs apply migrations to one `_sqlx_migrations` table: the `sqlx`
//! command-line tool in the controller image (the compose `migrate` service
//! and the chart's migration job) and the migrator this binary embeds and runs
//! at startup. Each refuses to start work when a recorded checksum differs
//! from the one it computes, so a library version that hashed a file
//! differently would stop every controller at boot against a database that is
//! fine.
//!
//! The record is SHA-384 of the file's bytes (measured 2026-10-07 on the
//! operator's database: 362 of 362 rows). This holds the embedded migrator to
//! that, file by file, and to the two settings that decide what it does about
//! a database it does not fully recognise.

use sha2::{Digest, Sha384};
use std::collections::BTreeMap;

fn files_by_version() -> BTreeMap<i64, std::path::PathBuf> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../migrations");
    std::fs::read_dir(dir)
        .expect("the migrations directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
        .map(|path| {
            let name = path.file_name().expect("a file name").to_string_lossy();
            let version = name
                .split('_')
                .next()
                .and_then(|prefix| prefix.parse::<i64>().ok())
                .unwrap_or_else(|| panic!("{name}: no numeric version prefix"));
            (version, path)
        })
        .collect()
}

#[test]
fn the_embedded_migrator_holds_every_file_under_the_checksum_of_its_bytes() {
    let migrator = sqlx::migrate!("../migrations");
    let files = files_by_version();
    assert!(
        files.len() > 300,
        "only {} migration files found",
        files.len()
    );
    assert_eq!(
        migrator.iter().count(),
        files.len(),
        "the embedded migrator and the directory disagree on how many migrations there are"
    );
    for migration in migrator.iter() {
        let path = files
            .get(&migration.version)
            .unwrap_or_else(|| panic!("version {} is embedded but has no file", migration.version));
        let bytes = std::fs::read(path).expect("read the migration");
        assert_eq!(
            hex::encode(&migration.checksum),
            hex::encode(Sha384::digest(&bytes)),
            "{}: the embedded checksum is not SHA-384 of the file",
            path.display()
        );
    }
}

#[test]
fn the_embedded_migrator_applies_in_version_order_under_the_lock_and_refuses_an_unknown_version() {
    let migrator = sqlx::migrate!("../migrations");
    let versions: Vec<i64> = migrator.iter().map(|m| m.version).collect();
    let mut sorted = versions.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        versions, sorted,
        "migrations are not in strictly increasing version order"
    );
    // Two controllers booting together must not both apply a migration.
    assert!(migrator.locking);
    // A database that records a migration this binary does not carry is a
    // database from a newer release: starting against it is not this binary's
    // call to make.
    assert!(!migrator.ignore_missing);
}
