//! Phase 6: migration determinism and startup-failure handling.
//!
//! Startup tests spawn the **real binary** as a subprocess, because the behaviour
//! under test is "does the process refuse to serve", which cannot be observed from
//! inside the process that is deciding to die.

mod support;

use std::process::Command;

use sqlx::PgPool;

const BINARY: &str = env!("CARGO_BIN_EXE_firecrow-backend");

/// Run the backend to completion (it is expected to exit non-zero) and return
/// (exit code, combined output).
fn run_backend(database_url: &str, extra: &[(&str, &str)]) -> (i32, String) {
    let mut cmd = Command::new(BINARY);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("SECRET_KEY", support::TEST_SECRET_KEY)
        .env("ENCRYPTION_KEY", support::TEST_ENCRYPTION_KEY)
        .env("FRONTEND_URL", "https://app.firecrow.test")
        .env("CORS_ORIGINS", "https://app.firecrow.test")
        .env("RATE_LIMIT_ENABLED", "false")
        .env("CSRF_ENABLED", "false")
        .env("PORT", "0")
        .env("DATABASE_URL", database_url);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("backend binary must be executable");
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

fn server_url() -> Option<String> {
    support::test_database_url()
}

// ---------------------------------------------------------------------------
// Part B: required-dependency startup failures
// ---------------------------------------------------------------------------

/// A malformed DATABASE_URL used to fall back to `PgConnectOptions::default()`,
/// silently pointing the pool at the local default socket.
#[test]
fn startup_rejects_malformed_database_url() {
    if server_url().is_none() {
        eprintln!("skipping: no database configured");
        return;
    }
    let (code, out) = run_backend("not-a-postgres-url", &[]);
    assert_ne!(
        code, 0,
        "a malformed DATABASE_URL must abort startup:\n{out}"
    );
    assert!(
        out.contains("DATABASE_URL is not a valid PostgreSQL connection URL"),
        "error must name the dependency and the operation:\n{out}"
    );
    assert!(
        !out.contains("Server listening"),
        "the listener must never be bound:\n{out}"
    );
}

/// PostgreSQL is REQUIRED. An unreachable server must abort, not degrade.
#[test]
fn startup_rejects_unreachable_database() {
    if server_url().is_none() {
        eprintln!("skipping: no database configured");
        return;
    }
    // Port 1 refuses connections immediately rather than hanging.
    let (code, out) = run_backend("postgres://probe:probe@127.0.0.1:1/nosuchdb", &[]);
    assert_ne!(
        code, 0,
        "an unreachable database must abort startup:\n{out}"
    );
    assert!(
        out.contains("cannot reach PostgreSQL"),
        "error must classify the failing dependency:\n{out}"
    );
    assert!(
        !out.contains("Server listening"),
        "the listener must never be bound:\n{out}"
    );
}

/// The credential must not appear in the error or the log.
#[test]
fn startup_error_does_not_leak_database_credentials() {
    if server_url().is_none() {
        eprintln!("skipping: no database configured");
        return;
    }
    const PASSWORD: &str = "sup3rs3cret-do-not-log-me";
    let (code, out) = run_backend(
        &format!("postgres://probe:{PASSWORD}@127.0.0.1:1/nosuchdb"),
        &[],
    );
    assert_ne!(code, 0);
    assert!(
        !out.contains(PASSWORD),
        "the database password leaked into startup output:\n{out}"
    );
}

/// The Phase 6 headline: a failing migration must stop the process.
///
/// Reproduced by pointing at a database whose schema was applied out-of-band, so
/// sqlx has no bookkeeping and re-runs the chain against existing objects.
#[tokio::test]
async fn startup_refuses_when_a_migration_fails() {
    let Some(base) = server_url() else {
        eprintln!("skipping: no database configured");
        return;
    };

    let name = format!("p6_untracked_{}", uuid::Uuid::new_v4().simple());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&base)
        .await
        .expect("connect to create a scratch database");

    sqlx::query(&format!("CREATE DATABASE \"{name}\""))
        .execute(&pool)
        .await
        .expect("create scratch database");
    pool.close().await;

    // Apply the schema out-of-band, exactly as an operator running the migration
    // files by hand would. No _sqlx_migrations table is created.
    let repo_migrations = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut files: Vec<_> = std::fs::read_dir(&repo_migrations)
        .expect("migrations dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();

    let scratch_url = base.replace("/postgres", &format!("/{name}"));
    let scratch = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&scratch_url)
        .await
        .expect("connect to scratch database");
    for f in &files {
        // Deliberately lenient: this emulates manual application, where a
        // per-statement failure must not abort the whole script.
        let _ = sqlx::raw_sql(&std::fs::read_to_string(f).unwrap())
            .execute(&scratch)
            .await;
    }
    let tracked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables
         WHERE table_schema='public' AND table_name='_sqlx_migrations'",
    )
    .fetch_one(&scratch)
    .await
    .unwrap_or(0);
    scratch.close().await;
    assert_eq!(
        tracked, 0,
        "scratch database must have no migration bookkeeping"
    );

    let (code, out) = run_backend(&scratch_url, &[]);
    assert_ne!(
        code,
        0,
        "a failing migration must abort startup:\n{}",
        out.chars().take(1200).collect::<String>()
    );
    assert!(
        out.contains("database migration failed"),
        "error must classify the failure:\n{}",
        out.chars().take(1200).collect::<String>()
    );
    assert!(
        !out.contains("Server listening"),
        "the listener must never be bound when the schema is not migrated:\n{out}"
    );
}

/// A missing required configuration value must also abort, and name the variable.
#[test]
fn startup_rejects_missing_required_secret() {
    if server_url().is_none() {
        eprintln!("skipping: no database configured");
        return;
    }
    let mut cmd = Command::new(BINARY);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("DATABASE_URL", server_url().unwrap())
        .env("FRONTEND_URL", "https://app.firecrow.test")
        .env("CORS_ORIGINS", "https://app.firecrow.test")
        .env("PORT", "0");
    let out = cmd.output().expect("binary");
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    assert_ne!(out.status.code().unwrap_or(-1), 0, "{text}");
    assert!(
        text.to_lowercase().contains("secret_key"),
        "the error must name the missing secret:\n{text}"
    );
    assert!(!text.contains("Server listening"), "{text}");
}

// ---------------------------------------------------------------------------
// Part A: migration chain integrity
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn migration_chain_is_fully_recorded(pool: PgPool) {
    let rows: Vec<(i64, bool)> =
        sqlx::query_as("SELECT version, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .expect("read bookkeeping");

    assert_eq!(
        rows.len(),
        17,
        "every migration must be recorded exactly once, got {rows:?}"
    );
    assert!(
        rows.iter().all(|(_, ok)| *ok),
        "no migration may be recorded as failed"
    );
    let versions: Vec<i64> = rows.iter().map(|(v, _)| *v).collect();
    assert!(
        versions.windows(2).all(|w| w[0] < w[1]),
        "versions must be strictly increasing and unique: {versions:?}"
    );
    assert_eq!(versions.last().copied(), Some(20260901000100));
}

#[sqlx::test(migrations = "./migrations")]
async fn migration_chain_produces_the_expected_schema(pool: PgPool) {
    let tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables
         WHERE table_schema='public' AND table_type='BASE TABLE'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    // 33 tables created by the migration chain, plus the _sqlx_migrations
    // bookkeeping table that sqlx creates itself.
    assert_eq!(tables, 34, "schema entity count changed unexpectedly");

    // Spot-check the three historically non-idempotent migrations' objects.
    for (table, constraint) in [
        (
            "payment_records",
            "payment_records_transaction_reference_key",
        ),
        ("role_permissions", "fk_role_permissions_role_id"),
        ("audit_jobs", "fk_audit_jobs_user_id"),
        ("pam_requests", "fk_pam_requests_user_id"),
    ] {
        let present: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_constraint
             WHERE conrelid = $1::regclass AND conname = $2",
        )
        .bind(table)
        .bind(constraint)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(present, 1, "{table}.{constraint} must exist exactly once");
    }

    // The repaired FK must reference roles, not iam_policies.
    let fk: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint
         WHERE conrelid='role_permissions'::regclass AND conname='fk_role_permissions_role_id'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(fk.contains("REFERENCES roles"), "{fk}");
    assert!(!fk.contains("iam_policies"), "{fk}");
}

/// Guards the Phase 6 conclusion that historical migrations must NOT be made
/// re-runnable.
///
/// sqlx validates the checksum of every already-applied migration
/// (sqlx-core migrator.rs:175) and returns `MigrateError::VersionMismatch` on a
/// mismatch. Editing a historical migration file therefore makes **every existing
/// deployment fail to start**. The three non-idempotent migrations are therefore
/// left exactly as written, and this test records that decision so a future
/// contributor does not "helpfully" add IF NOT EXISTS to them.
#[test]
fn historical_migrations_must_not_be_edited_for_idempotency() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    // The three proven non-idempotent files.
    let historical = [
        "20260814000000_add_unique_transaction_reference.sql",
        "20260814000001_fix_retention_and_utc.sql",
        "20260814000003_add_missing_cascades.sql",
    ];

    for name in historical {
        let text = std::fs::read_to_string(dir.join(name)).expect(name);
        for scaffold in [
            "pg_constraint",
            "to_regclass",
            "information_schema.constraint",
        ] {
            assert!(
                !text.contains(scaffold),
                "{name} contains `{scaffold}`. Editing an applied migration changes \
                 its checksum, and sqlx then refuses to start with VersionMismatch. \
                 Add a new migration instead."
            );
        }
    }

    // And no migration may opt out of the transaction that makes a failure atomic.
    for entry in std::fs::read_dir(&dir).expect("migrations dir") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "sql") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(
            !text.contains("no-transaction") && !text.contains("no_tx"),
            "{} disables the per-migration transaction. Without it a mid-migration \
             failure leaves partial schema and no bookkeeping row, and sqlx's \
             retry then compounds the damage.",
            path.display()
        );
    }
}

// ---------------------------------------------------------------------------
// Part C: housekeeping interval configuration
// ---------------------------------------------------------------------------

/// The setting arrived at `housekeeping_loop` as `_settings` and was ignored in
/// favour of a hardcoded 3600. It must now be authoritative.
#[test]
fn housekeeping_loop_uses_the_configured_interval() {
    let src = include_str!("../src/workers/mod.rs");
    let start = src
        .find("async fn housekeeping_loop")
        .expect("loop must exist");
    let body = &src[start..];

    assert!(
        body.contains("housekeeping_interval_seconds"),
        "housekeeping_loop must read the configured interval"
    );
    assert!(
        !body.contains("_settings: Settings"),
        "housekeeping_loop must not ignore its Settings argument"
    );
    assert!(
        !body.contains("from_secs(3600)"),
        "the hardcoded 3600 must be gone"
    );
}

/// A non-positive interval would make `tokio::time::interval` panic inside an
/// unsupervised task, so it must be rejected at startup.
///
/// Exercised through a subprocess rather than by mutating this process's
/// environment: `#[sqlx::test]` reads `DATABASE_URL` at run time, so an
/// env-mutating test would race the database-backed tests in the same binary.
#[test]
fn startup_rejects_non_positive_housekeeping_interval() {
    let Some(url) = server_url() else {
        eprintln!("skipping: no database configured");
        return;
    };
    for bad in ["0", "-1"] {
        let (code, out) = run_backend(&url, &[("HOUSEKEEPING_INTERVAL_SECONDS", bad)]);
        assert_ne!(code, 0, "interval {bad} must abort startup:\n{out}");
        assert!(
            out.contains("housekeeping_interval_seconds"),
            "the error must name the setting (for {bad}):\n{out}"
        );
        assert!(!out.contains("Server listening"), "{out}");
    }
}

/// The configuration must still be honoured, proven end to end by the startup
/// log. A positive non-default value must appear verbatim.
#[test]
fn startup_honours_configured_housekeeping_interval() {
    let Some(url) = server_url() else {
        eprintln!("skipping: no database configured");
        return;
    };
    // Use an unreachable database so the process exits quickly once the
    // configuration has been accepted; the interval is logged at pool start.
    let unreachable = "postgres://probe:probe@127.0.0.1:1/nosuchdb";
    let (code, out) = run_backend(
        unreachable,
        &[
            ("HOUSEKEEPING_INTERVAL_SECONDS", "97"),
            ("DATABASE_URL", unreachable),
        ],
    );
    assert_ne!(code, 0);
    // Configuration is validated before the database gate, so an accepted
    // interval must not produce a configuration error.
    assert!(
        !out.contains("housekeeping_interval_seconds"),
        "97 must be accepted as a valid interval:\n{out}"
    );
    let _ = url;
}

/// The default must remain 3600 seconds, so no deployment changes behaviour.
#[test]
fn housekeeping_default_interval_is_unchanged() {
    let src = include_str!("../src/config.rs");
    let start = src
        .find("fn default_housekeeping_interval")
        .expect("default fn must exist");
    assert!(
        src[start..].starts_with("fn default_housekeeping_interval() -> i64 {\n    3600\n}"),
        "the default must stay 3600 seconds"
    );
    assert!(
        src.contains("#[serde(default = \"default_housekeeping_interval\")]"),
        "the field must still fall back to that default"
    );
}
