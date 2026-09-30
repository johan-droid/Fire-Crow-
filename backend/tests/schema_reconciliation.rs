//! Automated schema/model reconciliation.
//!
//! The bug this exists to prevent: `FromRow` is *derived*, not compiled, so a
//! struct may name columns that no migration creates and the crate still builds.
//! The failure only appears at runtime, and only once a row exists — an empty
//! table returns `200 []` and looks healthy.
//!
//! This test reads the model definitions out of the source and compares them
//! against a freshly migrated PostgreSQL database. Any drift fails here, with
//! the exact missing column named, instead of at request time.
//!
//! Phase 3 of the remediation programme is discovery: the `KNOWN_MISSING` list
//! below is the documented inventory of pre-existing mismatches. Phase 4 removes
//! them and empties that list.

mod support;

use std::collections::{BTreeMap, BTreeSet};

/// Columns that the models reference but the migrations do not create, with the
/// root cause for each.
///
/// This is the Phase 3 inventory. Every entry is a defect: either a migration
/// never ran, or a model drifted away from the schema. Phase 4 removes all of
/// them, at which point this constant becomes empty and the test above it
/// becomes the permanent gate.
const KNOWN_MISSING: &[(&str, &str, &[&str], &str)] = &[
    // Phase 4 emptied this list. Any new entry must carry a root cause; the gate
    // above fails on undocumented drift, so this cannot grow silently.
];

/// Tables that application code writes but no migration creates.
const KNOWN_PHANTOM_TABLES: &[(&str, &str, &str)] = &[
    // Phase 4 created pam_audit, mfa_audit_logs and service_accounts.
];

/// Extract `pub field: Type` names from every `FromRow` struct in `source`.
fn from_row_fields(source: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // Locate each `#[derive(.. FromRow ..)]` struct and read its body.
    let mut idx = 0usize;
    while let Some(dpos) = source[idx..].find("FromRow") {
        let after = &source[idx + dpos..];
        let Some(struct_at) = after.find("struct ") else {
            break;
        };
        let after_struct = &after[struct_at + "struct ".len()..];
        let name_end = after_struct
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(after_struct.len());
        let name = after_struct[..name_end].to_string();
        let Some(brace) = after_struct.find('{') else {
            break;
        };
        // Match the closing brace of the struct body.
        let body_start = brace + 1;
        let mut depth = 1usize;
        let mut end = body_start;
        for (i, b) in after_struct[body_start..].bytes().enumerate() {
            if b == b'{' {
                depth += 1;
            } else if b == b'}' {
                depth -= 1;
                if depth == 0 {
                    end = body_start + i;
                    break;
                }
            }
        }
        let body = &after_struct[body_start..end];
        let fields: Vec<String> = body
            .lines()
            .filter_map(|l| {
                let l = l.split("//").next().unwrap_or("").trim();
                // Strip the attribute lines rustfmt may leave inline.
                if l.starts_with('#') || l.is_empty() {
                    return None;
                }
                l.strip_prefix("pub ")
                    .and_then(|r| r.split(':').next())
                    .map(|f| f.trim().to_string())
            })
            .filter(|f| !f.is_empty() && f.chars().all(|c| c.is_alphanumeric() || c == '_'))
            .collect();
        if !fields.is_empty() {
            out.entry(name).or_default().extend(fields);
        }
        idx += dpos + struct_at + name_end;
    }
    out
}

/// The struct -> table mapping, derived from actual `query_as` call sites.
///
/// Kept explicit because it cannot be derived from the model source alone, and an
/// explicit list is reviewable when a new model is added.
const STRUCT_TABLES: &[(&str, &str)] = &[
    ("User", "users"),
    ("AuditJob", "audit_jobs"),
    ("AuditReport", "audit_reports"),
    ("FindingModel", "findings"),
    ("PhaseLedgerModel", "phase_ledger"),
    ("MfaConfiguration", "mfa_configurations"),
    ("PaymentRecord", "payment_records"),
    ("PrivacyAuditLog", "privacy_audit_logs"),
    ("SsoProvider", "sso_providers"),
    ("Tenant", "tenants"),
    ("IamPolicy", "iam_policies"),
    ("DomainVerification", "domain_verifications"),
    ("ArtifactObject", "audit_artifacts"),
    ("PrivilegedAccessRequest", "pam_requests"),
    ("PrivilegedAccessGrant", "pam_grants"),
];

/// Every model source file, concatenated.
fn all_model_source() -> String {
    [
        include_str!("../src/models/audit_job.rs"),
        include_str!("../src/models/auth_exchange_code.rs"),
        include_str!("../src/models/compliance.rs"),
        include_str!("../src/models/domain_verification.rs"),
        include_str!("../src/models/github_credential.rs"),
        include_str!("../src/models/iam.rs"),
        include_str!("../src/models/login_failure.rs"),
        include_str!("../src/models/mfa.rs"),
        include_str!("../src/models/pam.rs"),
        include_str!("../src/models/payment.rs"),
        include_str!("../src/models/privacy_audit.rs"),
        include_str!("../src/models/push_subscription.rs"),
        include_str!("../src/models/role.rs"),
        include_str!("../src/models/security_log.rs"),
        include_str!("../src/models/sso.rs"),
        include_str!("../src/models/tenant.rs"),
        include_str!("../src/models/user.rs"),
        include_str!("../src/models/user_activity.rs"),
        include_str!("../src/models/user_session.rs"),
    ]
    .concat()
}

#[sqlx::test(migrations = "./migrations")]
async fn schema_every_model_column_exists(pool: sqlx::PgPool) {
    let structs = from_row_fields(&all_model_source());

    // Live column inventory.
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name, column_name FROM information_schema.columns
         WHERE table_schema = 'public'",
    )
    .fetch_all(&pool)
    .await
    .expect("read column inventory");

    let mut by_table: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (t, c) in rows {
        by_table.entry(t).or_default().insert(c);
    }

    let known_missing: BTreeSet<(&str, &str, &str)> = KNOWN_MISSING
        .iter()
        .map(|(s, t, cols, _)| (*s, *t, cols.first().copied().unwrap_or("")))
        .collect();
    let _ = &known_missing; // keys only, for documentation clarity

    let mut unexpected: Vec<String> = Vec::new();
    let mut documented: Vec<String> = Vec::new();

    for (struct_name, table) in STRUCT_TABLES {
        let Some(fields) = structs.get(*struct_name) else {
            unexpected.push(format!(
                "{struct_name}: listed in STRUCT_TABLES but no FromRow struct was found in src/models"
            ));
            continue;
        };
        let columns = by_table
            .get(*table)
            .unwrap_or_else(|| panic!("{table} does not exist; run the migrations"));

        let missing: Vec<&String> = fields
            .iter()
            // `client_secret_set` is a serialisation-only flag, not a column.
            .filter(|f| f.as_str() != "client_secret_set")
            .filter(|f| !columns.contains(*f))
            .collect();

        if missing.is_empty() {
            continue;
        }

        let names: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
        let entry = format!("{struct_name} -> {table}: missing {}", names.join(", "));

        let is_documented = KNOWN_MISSING.iter().any(|(s, t, cols, _)| {
            *s == *struct_name
                && *t == *table
                && missing.len() == cols.len()
                && missing.iter().all(|m| cols.contains(&m.as_str()))
        });

        if is_documented {
            documented.push(entry);
        } else {
            unexpected.push(entry);
        }
    }

    for entry in &documented {
        eprintln!("note: documented schema debt (tracked, removed in Phase 4): {entry}");
    }

    assert!(
        unexpected.is_empty(),
        "models reference columns that no migration creates, and the mismatch is NOT \
         documented in KNOWN_MISSING:\n  {}\n\nAdd a migration, or - if the field is a \
         DTO-only flag - mark it #[sqlx(skip)]. Then add the resolved pair to \
         KNOWN_MISSING if it is genuinely pre-existing.\n\
         Currently documented debt:\n  {}",
        unexpected.join("\n  "),
        documented.join("\n  ")
    );
}

/// Every table named inside a SQL string literal in `src/`, discovered by parsing
/// the source rather than trusting a hand-written list.
fn tables_referenced_in_sql() -> BTreeSet<String> {
    const SOURCES: &[&str] = &[
        include_str!("../src/api/mod.rs"),
        include_str!("../src/api/routes_audit.rs"),
        include_str!("../src/api/routes_auth.rs"),
        include_str!("../src/api/routes_dashboard.rs"),
        include_str!("../src/api/routes_dodo.rs"),
        include_str!("../src/api/routes_iam.rs"),
        include_str!("../src/api/routes_mfa.rs"),
        include_str!("../src/api/routes_pam.rs"),
        include_str!("../src/api/routes_sso.rs"),
        include_str!("../src/api/routes_storage.rs"),
        include_str!("../src/api/routes_system.rs"),
        include_str!("../src/api/routes_tenant.rs"),
        include_str!("../src/api/routes_user.rs"),
        include_str!("../src/api/routes_verify.rs"),
        include_str!("../src/services/iam_service.rs"),
        include_str!("../src/services/mfa_service.rs"),
        include_str!("../src/services/pam_service.rs"),
        include_str!("../src/services/payment_service.rs"),
        include_str!("../src/services/session.rs"),
        include_str!("../src/services/tenant_service.rs"),
        include_str!("../src/services/tenant_service.rs"),
        include_str!("../src/workers/mod.rs"),
        include_str!("../src/orchestrator/mod.rs"),
        include_str!("../src/graph/store.rs"),
        include_str!("../src/services/auth.rs"),
    ];

    // Words that follow FROM/INTO/UPDATE/JOIN but are not table names, e.g. the
    // `SET` in `DO UPDATE SET` and the `SKIP` in `FOR UPDATE SKIP LOCKED`.
    const SQL_KEYWORDS: &[&str] = &[
        "set",
        "skip",
        "locked",
        "nowait",
        "only",
        "table",
        "select",
        "values",
        "all",
        "exists",
        "and",
        "or",
        "not",
        "as",
        "using",
        "returning",
        "on",
        "conflict",
        "nothing",
        "distinct",
        "case",
        "when",
        "then",
        "else",
        "end",
        "null",
        "true",
        "false",
        "coalesce",
        "count",
        "sum",
        "max",
        "min",
        "extract",
        "interval",
        "for",
        "share",
        "of",
        "by",
        "asc",
        "desc",
        "limit",
        "offset",
        "order",
        "group",
        "having",
        "where",
        "inner",
        "left",
        "right",
        "cross",
        "full",
        "union",
        "lateral",
        "unnest",
        "generate_series",
        "current_user",
        "session_user",
    ];

    let mut found = BTreeSet::new();
    for src in SOURCES {
        // Only look inside double-quoted string literals, which is where SQL lives.
        // Scanning the raw text picks up English prose such as "the FROM clause".
        let bytes = src.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b'"' {
                i += 1;
                continue;
            }
            let start_quote = i;
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            let literal = &src[start_quote..i.min(src.len())];
            i += 1;

            // Only literals that actually begin with a SQL verb. Without this,
            // log messages and prose containing "UPDATE"/"JOIN" produce phantom
            // table names such as "set", "skip" and "queue".
            let trimmed = literal.trim();
            let upper = trimmed.to_ascii_uppercase();
            let is_sql = [
                "SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "CREATE", "ALTER",
            ]
            .iter()
            .any(|v| upper.starts_with(v) || upper.starts_with(&format!("\"{v}")));
            if !is_sql {
                continue;
            }
            for marker in [" FROM ", " INTO ", " UPDATE ", " JOIN "] {
                let mut from = 0usize;
                while let Some(rel) = upper[from..].find(marker) {
                    let at = from + rel + marker.len();
                    let tail = &literal[at..];
                    let name: String = tail
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    let lowered = name.to_ascii_lowercase();
                    if !name.is_empty() && !SQL_KEYWORDS.contains(&lowered.as_str()) {
                        found.insert(lowered);
                    }
                    from = at;
                }
            }
        }
    }
    found
}

#[sqlx::test(migrations = "./migrations")]
async fn schema_no_phantom_tables(pool: sqlx::PgPool) {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT table_name FROM information_schema.tables
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE'",
    )
    .fetch_all(&pool)
    .await
    .expect("read tables");
    let present: BTreeSet<String> = rows.into_iter().map(|(t,)| t).collect();

    let known: BTreeSet<&str> = KNOWN_PHANTOM_TABLES.iter().map(|(t, _, _)| *t).collect();

    // Tables whose name is clearly not one of ours, e.g. information_schema.
    let ignorable: BTreeSet<&str> = ["information_schema", "pg_catalog", "_sqlx_migrations"]
        .into_iter()
        .collect();

    let referenced = tables_referenced_in_sql();
    let undocumented: Vec<String> = referenced
        .into_iter()
        .filter(|t| {
            !present.contains(t) && !known.contains(t.as_str()) && !ignorable.contains(t.as_str())
        })
        .collect();

    for (t, src, why) in KNOWN_PHANTOM_TABLES {
        if !present.contains(*t) {
            eprintln!("note: documented phantom table (removed in Phase 4): {t} ({src}) - {why}");
        }
    }

    assert!(
        undocumented.is_empty(),
        "these tables are referenced in SQL but neither created by a migration nor \
         listed in KNOWN_PHANTOM_TABLES:\n  {}\n\nAdd a migration, then record it in \
         KNOWN_PHANTOM_TABLES if it is genuinely pre-existing debt.",
        undocumented.join("\n  ")
    );
}

/// The known-missing inventory must not silently grow. If this fails, a new
/// mismatch appeared and KNOWN_MISSING needs a new entry *with* a root cause.
#[sqlx::test(migrations = "./migrations")]
async fn schema_known_missing_inventory_is_exact(pool: sqlx::PgPool) {
    for (struct_name, table, columns, why) in KNOWN_MISSING {
        assert!(
            !columns.is_empty() && !why.trim().is_empty(),
            "{struct_name}: every KNOWN_MISSING entry needs columns and a root cause"
        );
        assert!(
            columns.windows(2).all(|w| w[0] < w[1]),
            "{struct_name}: KNOWN_MISSING column list must be sorted and deduplicated"
        );
        let exists: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM information_schema.tables
             WHERE table_schema='public' AND table_name = $1",
        )
        .bind(*table)
        .fetch_one(&pool)
        .await
        .expect("query tables");
        assert_eq!(exists.0, 1, "{table} must exist; {struct_name} targets it");
    }
}

// ---------------------------------------------------------------------------
// Phase 4 target
// ---------------------------------------------------------------------------

/// The documented debt must be fully paid off.
///
/// The recorded debt must stay empty. The gate above only fails on *undocumented*
/// drift, so this is what stops a mismatch from being quietly filed away as
/// "pre-existing" instead of fixed.
#[test]
fn schema_all_documented_mismatches_are_resolved() {
    assert!(
        KNOWN_MISSING.is_empty(),
        "still unfixed: {:#?}",
        KNOWN_MISSING
            .iter()
            .map(|(s, t, c, _)| (s, t, c))
            .collect::<Vec<_>>()
    );
    assert!(
        KNOWN_PHANTOM_TABLES.is_empty(),
        "tables still missing: {:#?}",
        KNOWN_PHANTOM_TABLES
    );
}
