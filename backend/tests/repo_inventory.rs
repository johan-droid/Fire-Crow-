//! Phase 4 inventory tests: understand what is actually being scanned.
//!
//! Covers: one repository per ecosystem (languages + manifests),
//! security-sensitive file detection by name/path, and proof that inventory
//! never carries secret contents. Offline: trees are built in temp dirs.

use firecrow_backend::agents::fetch::{is_security_sensitive_path, snapshot_repo};
use std::path::PathBuf;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "firecrow-inventory-test-{tag}-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Build a tree from `(relative path, contents)` pairs; returns the root.
fn build_tree(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let root = scratch_dir(tag);
    for (rel, content) in files {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, content).unwrap();
    }
    root
}

fn snapshot(
    tag: &str,
    files: &[(&str, &str)],
) -> (PathBuf, firecrow_backend::agents::fetch::RepoSnapshot) {
    let root = build_tree(tag, files);
    let snap = snapshot_repo(&root, SHA).expect("snapshot must succeed");
    (root, snap)
}

fn finish(root: &PathBuf) {
    let _ = std::fs::remove_dir_all(root);
}

// ---------------------------------------------------------------------------
// One repository per ecosystem
// ---------------------------------------------------------------------------

#[test]
fn rust_repo_is_inventoried() {
    let (root, snap) = snapshot(
        "rust",
        &[
            ("src/main.rs", "fn main() {}"),
            ("src/lib.rs", "pub fn f() {}"),
            ("Cargo.toml", "[package]"),
            ("Cargo.lock", "[[package]]"),
        ],
    );
    assert_eq!(snap.languages.get("Rust"), Some(&2));
    assert!(snap.manifests.contains(&"Cargo.toml".to_string()));
    assert!(snap.manifests.contains(&"Cargo.lock".to_string()));
    finish(&root);
}

#[test]
fn python_repo_is_inventoried() {
    let (root, snap) = snapshot(
        "python",
        &[
            ("app/main.py", "print('hi')"),
            ("app/util.pyi", "x: int"),
            ("requirements.txt", "requests==2.0"),
            ("pyproject.toml", "[project]"),
        ],
    );
    assert_eq!(snap.languages.get("Python"), Some(&2));
    assert!(snap.manifests.contains(&"requirements.txt".to_string()));
    assert!(snap.manifests.contains(&"pyproject.toml".to_string()));
    finish(&root);
}

#[test]
fn javascript_repo_is_inventoried() {
    let (root, snap) = snapshot(
        "js",
        &[
            ("src/index.js", "console.log(1)"),
            ("src/app.jsx", "export default {}"),
            ("package.json", "{}"),
            ("package-lock.json", "{}"),
            ("yarn.lock", ""),
        ],
    );
    assert_eq!(snap.languages.get("JavaScript"), Some(&2));
    for m in ["package.json", "package-lock.json", "yarn.lock"] {
        assert!(snap.manifests.contains(&m.to_string()), "missing {m}");
    }
    finish(&root);
}

#[test]
fn typescript_repo_is_inventoried() {
    let (root, snap) = snapshot(
        "ts",
        &[
            ("src/app.ts", "const x: number = 1;"),
            ("src/view.tsx", "export const v = 1;"),
            ("package.json", "{}"),
            ("pnpm-lock.yaml", ""),
        ],
    );
    assert_eq!(snap.languages.get("TypeScript"), Some(&2));
    assert!(snap.manifests.contains(&"package.json".to_string()));
    assert!(snap.manifests.contains(&"pnpm-lock.yaml".to_string()));
    finish(&root);
}

#[test]
fn go_repo_is_inventoried() {
    let (root, snap) = snapshot(
        "go",
        &[
            ("main.go", "package main"),
            ("go.mod", "module example"),
            ("go.sum", "h1:abc="),
        ],
    );
    assert_eq!(snap.languages.get("Go"), Some(&1));
    assert!(snap.manifests.contains(&"go.mod".to_string()));
    assert!(snap.manifests.contains(&"go.sum".to_string()));
    finish(&root);
}

#[test]
fn java_repo_is_inventoried() {
    let (root, snap) = snapshot(
        "java-maven",
        &[
            ("src/main/java/app/Main.java", "class Main {}"),
            ("pom.xml", "<project/>"),
        ],
    );
    assert_eq!(snap.languages.get("Java"), Some(&1));
    assert!(snap.manifests.contains(&"pom.xml".to_string()));
    finish(&root);

    let (root, snap) = snapshot(
        "java-gradle",
        &[
            ("src/main/java/app/Main.java", "class Main {}"),
            ("build.gradle", "plugins {}"),
            ("settings.gradle", ""),
        ],
    );
    assert_eq!(snap.languages.get("Java"), Some(&1));
    assert!(snap.manifests.contains(&"build.gradle".to_string()));
    finish(&root);
}

#[test]
fn c_and_cpp_repo_is_inventoried() {
    let (root, snap) = snapshot(
        "c",
        &[
            ("src/main.c", "int main() { return 0; }"),
            ("src/util.h", "#pragma once"),
            ("src/app.cpp", "int f() { return 1; }"),
        ],
    );
    assert_eq!(snap.languages.get("C"), Some(&2));
    assert_eq!(snap.languages.get("C++"), Some(&1));
    finish(&root);
}

#[test]
fn ruby_repo_is_inventoried() {
    let (root, snap) = snapshot(
        "ruby",
        &[
            ("app.rb", "puts 1"),
            ("Gemfile", "source rubygems"),
            ("Gemfile.lock", "GEM"),
        ],
    );
    assert_eq!(snap.languages.get("Ruby"), Some(&1));
    assert!(snap.manifests.contains(&"Gemfile".to_string()));
    assert!(snap.manifests.contains(&"Gemfile.lock".to_string()));
    finish(&root);
}

#[test]
fn php_repo_is_inventoried() {
    let (root, snap) = snapshot(
        "php",
        &[
            ("public/index.php", "<?php echo 1;"),
            ("composer.json", "{}"),
            ("composer.lock", "{}"),
        ],
    );
    assert_eq!(snap.languages.get("PHP"), Some(&1));
    assert!(snap.manifests.contains(&"composer.json".to_string()));
    assert!(snap.manifests.contains(&"composer.lock".to_string()));
    finish(&root);
}

// ---------------------------------------------------------------------------
// Security-sensitive files: detected by name/path, with a quiet baseline
// ---------------------------------------------------------------------------

#[test]
fn sensitive_paths_are_flagged() {
    for hit in [
        ".env",
        ".env.production",
        ".env.local",
        "config/credentials.json",
        "secrets/credentials.yaml",
        "my-credentials-backup.json",
        "config",
        "config.json",
        "config/settings.yaml",
        "terraform.tfvars",
        "infra/terraform.tfstate",
        "Dockerfile",
        "docker/Dockerfile.prod",
        "docker-compose.yml",
        "docker-compose.override.yaml",
        ".github/workflows/ci.yml",
        "infra/main.tf",
        "modules/vpc/network.tofu",
        "k8s/deployment.yaml",
        "kubernetes/service.yaml",
        "deploy/kustomization.yaml",
        "terraform/variables.tf",
    ] {
        assert!(
            is_security_sensitive_path(hit),
            "must flag sensitive path {hit:?}"
        );
    }
}

#[test]
fn ordinary_paths_are_not_flagged() {
    for ok in [
        "src/main.rs",
        "README.md",
        "package.json",
        "src/webpack.config.js",
        "src/app.config.ts",
        "docs/configuration.md",
        "src/myconfig.txt",
        "environments.ts",
        "src/env_helper.py",
        "Dockerfile.md",
        "terraforming/main.py",
        "src/kubernetes_client.py",
    ] {
        assert!(
            !is_security_sensitive_path(ok),
            "must not flag ordinary path {ok:?}"
        );
    }
}

#[test]
fn snapshot_lists_sensitive_files_by_path() {
    let (root, snap) = snapshot(
        "sensitive",
        &[
            ("src/main.rs", "fn main() {}"),
            (".env", "SECRET=1"),
            (".env.production", "SECRET=2"),
            ("config/credentials.json", "{}"),
            ("Dockerfile", "FROM scratch"),
            ("docker-compose.yml", "services: {}"),
            (".github/workflows/ci.yml", "on: push"),
            ("infra/main.tf", "resource {}"),
            ("k8s/deployment.yaml", "kind: Deployment"),
        ],
    );
    let expected = [
        ".env",
        ".env.production",
        ".github/workflows/ci.yml",
        "Dockerfile",
        "config/credentials.json",
        "docker-compose.yml",
        "infra/main.tf",
        "k8s/deployment.yaml",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect::<Vec<_>>();
    assert_eq!(snap.security_sensitive, expected);
    // Still inventoried as files — flagging never drops them from the scan.
    assert_eq!(snap.file_count, 9);
    finish(&root);
}

// ---------------------------------------------------------------------------
// Inventory must not carry secret contents
// ---------------------------------------------------------------------------

#[test]
fn inventory_never_carries_secret_contents() {
    let marker_a = "AKIAIOSFODNN7EXAMPLE-MARKER-A";
    let marker_b = "ghp_supersecretmarker00000000000001";
    let (root, snap) = snapshot(
        "nosecrets",
        &[
            ("src/main.rs", "fn main() {}"),
            (".env", &format!("AWS_KEY={marker_a}")),
            (".env.production", &format!("TOKEN={marker_b}")),
            (
                "config/credentials.json",
                &format!(r#"{{"key": "{marker_a}"}}"#),
            ),
            ("terraform.tfvars", &format!(r#"secret = "{marker_b}""#)),
        ],
    );
    assert_eq!(snap.security_sensitive.len(), 4);
    let json = serde_json::to_string(&snap).expect("snapshot serializes");
    assert!(
        !json.contains(marker_a) && !json.contains(marker_b),
        "snapshot must carry paths only, never secret contents"
    );
    // And the flagged files were not even opened for the binary sniff.
    assert_eq!(snap.binary_file_count, 0);
    finish(&root);
}
