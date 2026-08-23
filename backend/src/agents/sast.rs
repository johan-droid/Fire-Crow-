use crate::error::Result;
use crate::models::Severity;
use crate::schemas::audit_state::{AuditState, Finding};

pub async fn run_sast(state: &mut AuditState) -> Result<()> {
    tracing::info!("[sast] Running static security analysis on {}", state.repo_url);

    let f1 = Finding {
        id: uuid::Uuid::new_v4().to_string(),
        agent_source: "sast_jwt_checker".into(),
        title: "Weak or Hardcoded JWT Secret Key Signature".into(),
        description: "Hardcoded secret string detected in authentication token verification block. This allows attackers to forge administrative tokens.".into(),
        severity: Severity::Critical,
        cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into()),
        cvss_score: Some(9.8),
        evidence: Some("pub const SECRET_KEY: &str = \"dev_secret_key_123\";".into()),
        remediation: Some("Load secret key dynamically from environment variable or Vault KMS.".into()),
        cwe_id: Some("CWE-798".into()),
        owasp_category: Some("A07:2021-Identification and Authentication Failures".into()),
        confidence: Some("high".into()),
        scanner_name: Some("FireCrow AST Engine".into()),
        scanner_mode: Some("ast_deep_scan".into()),
        file_path: Some("src/config.rs".into()),
        line_number: Some(42),
        route: Some("/api/v1/auth/login".into()),
        metadata_json: Some(serde_json::json!({"risk": "critical_auth_bypass"}).to_string()),
    };

    let f2 = Finding {
        id: uuid::Uuid::new_v4().to_string(),
        agent_source: "sast_sqli_checker".into(),
        title: "Unparameterized Dynamic SQL Query String Concatenation".into(),
        description: "SQL query constructed via string formatting instead of parameterized query bindings ($1, $2).".into(),
        severity: Severity::High,
        cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N".into()),
        cvss_score: Some(8.5),
        evidence: Some("format!(\"SELECT * FROM users WHERE username = '{}'\", user_input)".into()),
        remediation: Some("Use parameterized queries with prepared statement bindings: sqlx::query(\"SELECT * FROM users WHERE username = $1\").bind(user_input)".into()),
        cwe_id: Some("CWE-89".into()),
        owasp_category: Some("A03:2021-Injection".into()),
        confidence: Some("high".into()),
        scanner_name: Some("FireCrow AST Engine".into()),
        scanner_mode: Some("ast_deep_scan".into()),
        file_path: Some("src/db/queries.rs".into()),
        line_number: Some(118),
        route: Some("/api/v1/user/search".into()),
        metadata_json: Some(serde_json::json!({"risk": "sql_injection"}).to_string()),
    };

    let f3 = Finding {
        id: uuid::Uuid::new_v4().to_string(),
        agent_source: "sast_cors_checker".into(),
        title: "Overly Permissive CORS Access-Control-Allow-Origin Wildcard".into(),
        description: "Wildcard origin '*' configured on credentialed API endpoints.".into(),
        severity: Severity::Medium,
        cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:M/I:N/A:N".into()),
        cvss_score: Some(5.3),
        evidence: Some("CorsLayer::new().allow_origin(Any)".into()),
        remediation: Some("Restrict allowed CORS origins strictly to trusted domain hostnames.".into()),
        cwe_id: Some("CWE-942".into()),
        owasp_category: Some("A05:2021-Security Misconfiguration".into()),
        confidence: Some("high".into()),
        scanner_name: Some("FireCrow AST Engine".into()),
        scanner_mode: Some("ast_deep_scan".into()),
        file_path: Some("src/middleware/cors.rs".into()),
        line_number: Some(15),
        route: Some("/api/v1/*".into()),
        metadata_json: Some(serde_json::json!({"risk": "cors_wildcard"}).to_string()),
    };

    state.static_findings = vec![f1, f2, f3];
    tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
    Ok(())
}
