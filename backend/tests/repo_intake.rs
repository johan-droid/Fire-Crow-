//! Phase 2 intake tests: safely accept a repository.
//!
//! Covers: valid public repo URLs, private-repo metadata, invalid URLs,
//! malformed owner/repo segments, path traversal, unsupported protocols,
//! inaccessible repositories (404), expired/invalid tokens (401), missing
//! tokens, branch resolution, commit-sha validation, and metadata capture.
//! All tests are offline: they exercise the pure intake logic (validation,
//! status mapping, metadata parsing), never the live GitHub API.

use firecrow_backend::agents::fetch::{
    auth_header_value, is_valid_commit_sha, map_repo_access_error, parse_github_owner_repo,
    parse_repository_metadata, resolve_branch, tarball_url, Visibility,
};
use firecrow_backend::api::routes_audit::validate_github_repo_url;
use firecrow_backend::error::AppError;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

// ---------------------------------------------------------------------------
// Valid public repository URLs
// ---------------------------------------------------------------------------

#[test]
fn valid_public_repo_urls_are_accepted_and_normalized() {
    for (input, owner, repo) in [
        ("https://github.com/acme/widget", "acme", "widget"),
        ("https://github.com/acme/widget/", "acme", "widget"),
        ("https://github.com/acme/widget.git", "acme", "widget"),
        ("https://github.com/acme/widget.git/", "acme", "widget"),
        ("  https://github.com/acme/widget  ", "acme", "widget"),
        (
            "https://github.com/Acme-Org/my.repo_2",
            "Acme-Org",
            "my.repo_2",
        ),
    ] {
        let canonical =
            validate_github_repo_url(input).unwrap_or_else(|_| panic!("must accept {input}"));
        assert_eq!(canonical, format!("https://github.com/{owner}/{repo}"));
        assert_eq!(
            parse_github_owner_repo(input),
            Some((owner.to_string(), repo.to_string())),
            "owner/repo must parse from {input}"
        );
    }
}

// ---------------------------------------------------------------------------
// Invalid URLs, unsupported protocols, non-GitHub hosts
// ---------------------------------------------------------------------------

#[test]
fn invalid_and_non_github_urls_are_rejected() {
    for bad in [
        "",
        "   ",
        "not-a-url",
        "github.com/acme/widget",
        "http://github.com/acme/widget",
        "ftp://github.com/acme/widget",
        "ssh://git@github.com/acme/widget.git",
        "git://github.com/acme/widget.git",
        "git@github.com:acme/widget.git",
        "file:///etc/passwd",
        "https://gitlab.com/acme/widget",
        "https://github.com.evil.com/acme/widget",
        "https://evilgithub.com/acme/widget",
        "https://api.github.com/repos/acme/widget",
        "https://github.com/acme",
        "https://github.com/acme/",
        "https://github.com/acme/widget/extra",
        "https://github.com/acme/widget/tree/main",
        "https://github.com//widget",
        "https://github.com/acme//",
        "https://github.com/acme/widget?tab=readme",
        "https://github.com/acme/widget#readme",
    ] {
        assert!(
            validate_github_repo_url(bad).is_err(),
            "must reject {bad:?}"
        );
        assert!(
            parse_github_owner_repo(bad).is_none(),
            "must not parse owner/repo from {bad:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Malformed owner / repository segments
// ---------------------------------------------------------------------------

#[test]
fn malformed_owner_segments_are_rejected() {
    for owner in [
        "..", ".", "", "ac me", "ac/me", "ac%2fme", "%2e%2e", "ac!me", "ac@me", "ac:me", "ac\\me",
        "école",
    ] {
        let url = format!("https://github.com/{owner}/widget");
        assert!(
            validate_github_repo_url(&url).is_err(),
            "must reject owner {owner:?}"
        );
        assert!(
            parse_github_owner_repo(&url).is_none(),
            "must not parse owner {owner:?}"
        );
    }
}

#[test]
fn malformed_repo_segments_are_rejected() {
    for repo in [
        "..",
        ".",
        "",
        "wid get",
        "wid/get",
        "wid%2fget",
        "%2e",
        "wid!get",
        "wid?get",
        "wid#get",
        "wid\\get",
    ] {
        let url = format!("https://github.com/acme/{repo}");
        assert!(
            validate_github_repo_url(&url).is_err(),
            "must reject repo {repo:?}"
        );
        assert!(
            parse_github_owner_repo(&url).is_none(),
            "must not parse repo {repo:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Path traversal
// ---------------------------------------------------------------------------

#[test]
fn path_traversal_is_rejected() {
    for bad in [
        "https://github.com/../etc",
        "https://github.com/acme/..",
        "https://github.com/acme/.",
        "https://github.com/./widget",
        "https://github.com/acme/widget/../../etc",
        "https://github.com/%2e%2e/widget",
        "https://github.com/acme/%2e%2e",
        "https://github.com/..%2f..%2fetc/passwd",
    ] {
        assert!(
            validate_github_repo_url(bad).is_err(),
            "must reject traversal {bad:?}"
        );
        assert!(
            parse_github_owner_repo(bad).is_none(),
            "must not parse traversal {bad:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Token handling: missing token never sends a credential
// ---------------------------------------------------------------------------

#[test]
fn missing_token_sends_no_credential() {
    assert_eq!(auth_header_value(""), None);
    assert_eq!(auth_header_value("   "), None);
    assert_eq!(auth_header_value("\t\n "), None);
    assert_eq!(
        auth_header_value("ghp_secret"),
        Some("Bearer ghp_secret".to_string())
    );
    // Surrounding whitespace is trimmed, never sent to GitHub.
    assert_eq!(
        auth_header_value("  ghp_secret  "),
        Some("Bearer ghp_secret".to_string())
    );
}

// ---------------------------------------------------------------------------
// Access-status mapping: expired/invalid token, inaccessible repo, rate limit
// ---------------------------------------------------------------------------

#[test]
fn expired_or_invalid_token_maps_to_unauthorized() {
    // GitHub answers 401 Bad credentials for invalid, expired, and revoked
    // tokens alike; intake reports them together rather than guessing.
    for token_present in [true, false] {
        let err = map_repo_access_error(401, token_present, None, "acme", "widget");
        assert!(
            matches!(err, AppError::Unauthorized(_)),
            "401 must be Unauthorized, got {err:?}"
        );
        assert!(
            err.to_string().contains("expired"),
            "401 message must name expiry as a possible cause: {err}"
        );
    }
}

#[test]
fn inaccessible_repository_maps_to_not_found_without_leaking_existence() {
    // 404 covers missing, private, and no-access alike; the message must say
    // so together instead of revealing which one it is.
    for token_present in [true, false] {
        let err = map_repo_access_error(404, token_present, None, "acme", "widget");
        assert!(
            matches!(err, AppError::NotFound(_)),
            "404 must be NotFound, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("not found"),
            "404 message must say not found: {msg}"
        );
        assert!(
            msg.contains("private"),
            "404 message must admit privacy: {msg}"
        );
    }
    // Without a token the message must point at the missing credential.
    let err = map_repo_access_error(404, false, None, "acme", "widget");
    assert!(
        err.to_string().contains("no GitHub token was supplied"),
        "missing-token 404 must say a token is needed: {err}"
    );
}

#[test]
fn forbidden_and_rate_limits_map_honestly() {
    let err = map_repo_access_error(403, true, None, "acme", "widget");
    assert!(
        matches!(err, AppError::Forbidden(_)),
        "403 with budget left must be Forbidden, got {err:?}"
    );
    let err = map_repo_access_error(403, true, Some("5"), "acme", "widget");
    assert!(matches!(err, AppError::Forbidden(_)));

    for (status, remaining) in [(403, Some("0")), (429, None), (429, Some("0"))] {
        let err = map_repo_access_error(status, true, remaining, "acme", "widget");
        assert!(
            matches!(err, AppError::RateLimited),
            "{status} with remaining={remaining:?} must be RateLimited, got {err:?}"
        );
    }

    let err = map_repo_access_error(500, true, None, "acme", "widget");
    assert!(
        matches!(err, AppError::HttpClientError(_)),
        "unexpected statuses must stay generic HttpClientError, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Repository metadata capture
// ---------------------------------------------------------------------------

fn public_repo_body() -> serde_json::Value {
    serde_json::json!({
        "full_name": "acme/widget",
        "private": false,
        "default_branch": "main",
    })
}

fn private_repo_body() -> serde_json::Value {
    serde_json::json!({
        "full_name": "acme/secret",
        "private": true,
        "visibility": "private",
        "default_branch": "develop",
    })
}

#[test]
fn valid_public_repo_metadata_is_captured() {
    let meta = parse_repository_metadata(
        "acme",
        "widget",
        "https://github.com/acme/widget",
        &public_repo_body(),
    )
    .expect("public metadata must parse");
    assert_eq!(meta.owner, "acme");
    assert_eq!(meta.repo, "widget");
    assert_eq!(meta.repository_url, "https://github.com/acme/widget");
    assert_eq!(meta.default_branch, "main");
    assert_eq!(meta.visibility, Visibility::Public);
    assert_eq!(meta.commit_sha, None, "sha is resolved later, not parsed");
}

#[test]
fn private_repo_metadata_is_captured_as_private() {
    let meta = parse_repository_metadata(
        "acme",
        "secret",
        "https://github.com/acme/secret",
        &private_repo_body(),
    )
    .expect("private metadata must parse");
    assert_eq!(meta.visibility, Visibility::Private);
    assert_eq!(meta.default_branch, "develop");
    assert_eq!(meta.visibility.as_str(), "private");
}

#[test]
fn non_public_visibility_counts_as_private() {
    // `internal` (GitHub Enterprise) is not world-readable.
    let body = serde_json::json!({
        "private": false,
        "visibility": "internal",
        "default_branch": "main",
    });
    let meta = parse_repository_metadata("acme", "w", "https://github.com/acme/w", &body).unwrap();
    assert_eq!(meta.visibility, Visibility::Private);

    // An explicit "public" visibility string wins over a missing flag.
    let body = serde_json::json!({
        "visibility": "public",
        "default_branch": "main",
    });
    let meta = parse_repository_metadata("acme", "w", "https://github.com/acme/w", &body).unwrap();
    assert_eq!(meta.visibility, Visibility::Public);
}

#[test]
fn metadata_without_a_default_branch_is_rejected() {
    for body in [
        serde_json::json!({"private": false}),
        serde_json::json!({"private": false, "default_branch": ""}),
        serde_json::json!({"private": false, "default_branch": "   "}),
        serde_json::json!({"private": false, "default_branch": 42}),
    ] {
        assert!(
            parse_repository_metadata("acme", "w", "https://github.com/acme/w", &body).is_err(),
            "metadata without default_branch must fail: {body}"
        );
    }
}

// ---------------------------------------------------------------------------
// Branch resolution and commit-sha validation
// ---------------------------------------------------------------------------

#[test]
fn blank_branch_falls_back_to_the_default_branch() {
    assert_eq!(resolve_branch("", "main"), "main");
    assert_eq!(resolve_branch("   ", "develop"), "develop");
    assert_eq!(resolve_branch("feature/x", "main"), "feature/x");
    assert_eq!(resolve_branch("  main  ", "develop"), "main");
}

#[test]
fn only_well_formed_commit_shas_are_accepted() {
    assert!(is_valid_commit_sha(SHA));
    assert!(is_valid_commit_sha(&"a".repeat(40)));
    for bad in [
        "",
        "abc",
        &"a".repeat(39),
        &"a".repeat(41),
        "0123456789ABCDEF0123456789ABCDEF01234567",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        "0123456789abcdef0123456789abcdef0123456 ",
        " 0123456789abcdef0123456789abcdef01234567",
    ] {
        assert!(!is_valid_commit_sha(bad), "must reject sha {bad:?}");
    }
}

#[test]
fn tarball_download_is_pinned_to_the_resolved_sha() {
    let url = tarball_url("acme", "widget", SHA);
    assert_eq!(
        url,
        format!("https://api.github.com/repos/acme/widget/tarball/{SHA}")
    );
    assert!(
        !url.contains("main"),
        "the download URL must carry the sha, not a moving branch ref"
    );
}
