use serde_json::Value;

pub fn build_scan_plan(repo_languages: &[String], has_container: bool) -> Value {
    let mut plan = serde_json::json!({
        "phases": [
            {"name": "recon", "agents": ["recon", "api_surface", "sbom_graph"], "always": true},
            {"name": "scanning", "agents": ["sast", "dependency_scan", "iac_scan", "secret_history"], "always": true},
            {"name": "analysis", "agents": ["ai_analyzer", "cross_validation"], "always": true},
            {"name": "reporting", "agents": ["reporter"], "always": true},
        ]
    });
    if has_container { plan["phases"][1]["agents"].as_array_mut().unwrap().push(Value::String("container_scan".into())); }
    if repo_languages.iter().any(|l| l == "python" || l == "javascript") {
        plan["phases"][1]["agents"].as_array_mut().unwrap().push(Value::String("sast_semgrep".into()));
    }
    plan
}
