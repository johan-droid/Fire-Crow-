pub fn build_audit_job_url(base_url: &str, job_id: &str) -> String {
    format!("{}/audit/{}", base_url.trim_end_matches('/'), job_id)
}
