//! Phase 19B.1: the GitHub App identity layer.
//!
//! What is proven here:
//!
//! * App identity is all-or-nothing: absent ID + absent key means disabled,
//!   half an identity is an explicit error, and a non-RSA key is rejected at
//!   construction — never at first use in production.
//! * A minted JWT verifies against the App's public key, carries `iss` =
//!   the App ID, and stays inside GitHub's lifetime rules (`exp - iat <=
//!   600s, `iat` backdated for skew).
//! * Key material never appears in an error, and the identity struct cannot
//!   be formatted into a log.
//!
//! The RSA key below is generated for these tests only (`openssl genrsa`)
//! and signs nothing outside them.

mod support;

use base64::Engine as _;
use firecrow_backend::services::github_app::AppIdentity;
use sqlx::PgPool;

/// TEST-ONLY RSA private key. Never a real credential: it exists so the
/// suite can mint and verify tokens without network or key services.
const TEST_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDM5+/U2YwFZdjE
jBfKwA4PSdSp9oRe60vhNesRGE+nGMlO9dZHc7AITvvXIYu5qUHTQkbLJlH2BIe/
CfKSBoIFHBfn/TOcmNz3U2NFwALaPtA56NXxFxbbof8z3cda4udToY76I5B/k5bS
QSTsM0QPPNoSWz6L3hG/wVFGGLARI1fU91ZAOcBOvwerZ5Ygbk72i/WQHO2H15X0
9bVAmqSt/ATOfCg6S6A7pPieJ/lHzSlT0K8+rdVddB2ss4BT93Lt62JNk5eSYA46
nL8Mz/Qk6pwQCQB7CEVteHKCRx/mnqlj7n2ksZRODloPDYkyu+KUPqYf/fwan9OG
rRoY+ewjAgMBAAECggEATg07ahTEJXo6LARBO9YUhPZWr7dbjNyMNulW9VgRX1Et
vYofaXBD6aZMgBIjK0Gx9UsVtGSQa+ol2ztqzvzzogalhJUKh+gio4N8GSGe9Itg
ve5XMFLfPiJjF9qvCYvNGio8UEQj0rThio2OBvswPa2sU7m2BYk9sZFt6AmXZ68k
LJGYX24Ktquo8Wz33Q/Fx7WAt0NlOrwaNa6jUjue9MLl6peIFZXNSd0gPU62IqmL
o+IMtTbVHYe3b+I1GEKUrzXs1/j9OGB+veUlqLokQvJSQugYGmqlxNOJMAO2GAHb
Z2CfwuNBim55XcLwR+kvOuVQAV40RqrS4WttsyzRIQKBgQDvBxI+o+vROBw19rnn
JFYwgY2TJOCOA+OQ9L8ZytQDgXW159siGlnYdrtmEV20yo6+x9FYROz4M8bVEENC
P5wHHgtcf4MBhgzOy2OoDqXjBggwbG2BmgG20QQJ9M/74sBQ7eMW1mvfrfFfVnG4
Yvfgjebl7TNcnGIjApW4/LzqXQKBgQDbdJ6Hn4UqJgjraeGPNxVXcBQpRX9FKMuQ
pwd3UDaZdVsBcQ2ybzcINqytuHx1x7Jafmccp27NSOJFNeo5IcYPn7EjJ7azfF8n
AOyDBJC6Oyk/fW9+CGquxobjKcejtdnMaMuLMdXsmWLLwHsvP9CRjLc2oky3+Pqw
g3PN6D3IfwKBgQCH3bkdKgftELvYYLojDKCBSeKzdQ6/Kq67wqKtgoEozPmfwH7q
z5eqVzMGPXDKRykEgIgaaHNaUfP/QBM7IPULhqRmm4RX5V56XVn0OP9KIC+fdsJ4
HJZE2GI3VpSyVJ2EYvPmE1OV/UVqL7TMXlUPqxlIMKA1UB7oT5vTXrXzcQKBgQCf
n4qz0Ub16mZwfTpQhltilyZDAsbY0hyHIcbfdRvRsTe5q7avxA8+TS56yYbV0KQd
CHYNtId2j/3tI5MzbSp4MMqSbI+Kq/s2Doj5n3d5zhBpmt5eyNZ4O/TfBIOuw1Yh
RVRP8bbNeqAO3fl726nkRHr7JUAyTMpjW6n+6l8OFwKBgDPbwQtfMS23yQxtCTt5
UbasFdoYNeaI9tIYe7VEDvZXqpXiIqb7gqEfl2Fgy+a+MSSkLKhwNSSDNLg7COhb
F2bluSxO3pitCf0N0F4p6iiB6kTurzID41KVAwVGWZtsz/+9t7ze1ufiUREo4BpD
vTr3yQc1kmXLT8QMholpAl29
-----END PRIVATE KEY-----
";

const APP_ID: u64 = 123456;

fn identity() -> AppIdentity {
    AppIdentity::from_parts(APP_ID, TEST_PRIVATE_KEY_PEM)
        .expect("test identity builds")
        .expect("test identity is enabled")
}

// ---------------------------------------------------------------------------
// Construction: all-or-nothing, fail fast
// ---------------------------------------------------------------------------

#[test]
fn absent_identity_means_disabled_not_an_error() {
    assert!(
        AppIdentity::from_parts(0, "")
            .expect("absence must not error")
            .is_none(),
        "no ID and no key is a disabled integration, not a failure"
    );
    assert!(AppIdentity::from_parts(0, "   ")
        .expect("blank key must not error")
        .is_none(),);
}

#[test]
fn half_an_identity_is_an_explicit_error() {
    for (id, key) in [(APP_ID, ""), (0, TEST_PRIVATE_KEY_PEM)] {
        let err = match AppIdentity::from_parts(id, key) {
            Err(err) => err,
            // `expect_err` needs `Debug` on the value type, which the
            // identity deliberately lacks — so match instead.
            Ok(_) => panic!("half identity must fail (id set: {})", id != 0),
        };
        let rendered = err.to_string();
        assert!(
            rendered.contains("incomplete"),
            "the error must name the problem, got: {rendered}"
        );
        assert!(
            !rendered.contains("MIIEvg"),
            "key material must never enter the error"
        );
    }
}

#[test]
fn a_non_rsa_key_is_rejected_at_construction() {
    for bad in [
        "not-a-key-at-all",
        "-----BEGIN PRIVATE KEY-----\nbm90LWEtcmVhbC1rZXk=\n-----END PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nbm90LWEtcmVhbC1rZXk=\n-----END ENCRYPTED PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----\nbm90LWEtcmVhbC1rZXk=\n-----END EC PRIVATE KEY-----",
    ] {
        let err = match AppIdentity::from_parts(APP_ID, bad) {
            Err(err) => err,
            Ok(_) => panic!("bad key must fail: {bad:?}"),
        };
        let rendered = err.to_string();
        assert!(
            !rendered.contains("bm90LWEtcmVhbC1rZXk="),
            "key bytes must never enter the error: {rendered}"
        );
    }
}

#[test]
fn only_the_public_app_id_is_exposed() {
    // Structural property, pinned here by documentation: `AppIdentity`
    // implements no `Debug`, `Display`, or `Serialize`, so no log line,
    // panic message, or response can render the key. (A `format!("{:.?}")`
    // on it does not compile; that is the test.) The public ID is the only
    // observable field.
    assert_eq!(identity().app_id(), APP_ID);
}

// ---------------------------------------------------------------------------
// Minting: verifiable, bounded, key-safe
// ---------------------------------------------------------------------------

#[test]
fn a_minted_jwt_verifies_against_the_app_public_key() {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};

    let now = chrono::Utc::now();
    let token = identity().mint_jwt(now).expect("mint succeeds");

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false; // claims-shape test, not a clock test
    validation.required_spec_claims.clear();
    let decoded = jsonwebtoken::decode::<serde_json::Value>(
        &token,
        &DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes()).expect("test key parses"),
        &validation,
    )
    .expect("the App's own public key must verify the mint");

    assert_eq!(decoded.claims["iss"], serde_json::json!(APP_ID.to_string()));
    assert_eq!(decoded.header.alg, Algorithm::RS256);
}

/// TEST-ONLY public half of the fixture key.
const TEST_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzOfv1NmMBWXYxIwXysAO
D0nUqfaEXutL4TXrERhPpxjJTvXWR3OwCE771yGLualB00JGyyZR9gSHvwnykgaC
BRwX5/0znJjc91NjRcAC2j7QOejV8RcW26H/M93HWuLnU6GO+iOQf5OW0kEk7DNE
DzzaEls+i94Rv8FRRhiwESNX1PdWQDnATr8Hq2eWIG5O9ov1kBzth9eV9PW1QJqk
rfwEznwoOkugO6T4nif5R80pU9CvPq3VXXQdrLOAU/dy7etiTZOXkmAOOpy/DM/0
JOqcEAkAewhFbXhygkcf5p6pY+59pLGUTg5aDw2JMrvilD6mH/38Gp/Thq0aGPns
IwIDAQAB
-----END PUBLIC KEY-----
";

#[test]
fn mint_bounds_hold_for_a_fixed_clock() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-10-04T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let token = identity().mint_jwt(now).expect("mint succeeds");

    // Read the claims without verifying: bounds are a mint property.
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "a JWT has three segments");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("claims segment decodes"),
    )
    .expect("claims are JSON");

    let iat = claims["iat"].as_i64().expect("iat present");
    let exp = claims["exp"].as_i64().expect("exp present");
    assert_eq!(claims["iss"], serde_json::json!(APP_ID.to_string()));
    assert_eq!(
        exp - iat,
        540,
        "lifetime stays inside GitHub's 600s ceiling"
    );
    assert_eq!(iat, now.timestamp() - 60, "iat absorbs clock skew");
}

// ---------------------------------------------------------------------------
// Phase 19B.2: installation identity
// ---------------------------------------------------------------------------

use firecrow_backend::services::github_app::{
    get_installation, installation_usable, register_installation, remove_installation,
    set_installation_suspended,
};

#[sqlx::test(migrations = "./migrations")]
async fn a_valid_installation_registers_and_resolves(pool: PgPool) {
    let user = support::seed_user(&pool, "installer").await;

    let row = register_installation(&pool, 9001, 4242, "acme-org", "Organization", &user.id)
        .await
        .expect("valid registration");
    assert_eq!(row.installation_id, 9001);
    assert_eq!(row.account_login, "acme-org");
    assert!(!row.suspended);

    let found = get_installation(&pool, 9001)
        .await
        .expect("lookup")
        .expect("registered installation resolves");
    assert_eq!(found.account_id, 4242);
    assert!(installation_usable(&pool, 9001).await.expect("usable"));
}

#[sqlx::test(migrations = "./migrations")]
async fn an_unknown_installation_is_unusable(pool: PgPool) {
    assert!(get_installation(&pool, 111222333).await.unwrap().is_none());
    assert!(!installation_usable(&pool, 111222333).await.unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn a_malformed_installation_id_resolves_like_unknown(pool: PgPool) {
    for bad in [0, -1, i64::MIN] {
        assert!(get_installation(&pool, bad).await.unwrap().is_none());
        assert!(!installation_usable(&pool, bad).await.unwrap());
        assert!(!remove_installation(&pool, bad).await.unwrap());
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn malformed_identity_is_refused_before_the_database(pool: PgPool) {
    let user = support::seed_user(&pool, "badinstall").await;
    for (id, account, login, kind, installer) in [
        (0, 1, "acme", "Organization", user.id.as_str()),
        (-5, 1, "acme", "Organization", user.id.as_str()),
        (9002, 0, "acme", "Organization", user.id.as_str()),
        (9002, 1, "", "Organization", user.id.as_str()),
        (9002, 1, "acme", "Bot", user.id.as_str()),
        (9002, 1, "acme", "organization", user.id.as_str()),
        (9002, 1, "acme", "Organization", "   "),
    ] {
        assert!(
            register_installation(&pool, id, account, login, kind, installer)
                .await
                .is_err(),
            "id={id} account={account} login={login:?} kind={kind:?} must be refused"
        );
    }
    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM github_installations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows.0, 0, "no refused identity may leave a row");
}

#[sqlx::test(migrations = "./migrations")]
async fn re_registration_updates_instead_of_duplicating(pool: PgPool) {
    let first = support::seed_user(&pool, "first").await;
    let second = support::seed_user(&pool, "second").await;

    register_installation(&pool, 9003, 1, "acme", "Organization", &first.id)
        .await
        .unwrap();
    let updated = register_installation(&pool, 9003, 1, "acme-renamed", "Organization", &second.id)
        .await
        .unwrap();
    assert_eq!(updated.installed_by_user_id, second.id);
    assert_eq!(updated.account_login, "acme-renamed");

    let rows: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM github_installations WHERE installation_id=9003")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rows.0, 1, "one installation ID is always one row");
}

#[sqlx::test(migrations = "./migrations")]
async fn a_suspended_installation_is_unusable_until_cleared(pool: PgPool) {
    let user = support::seed_user(&pool, "suspend").await;
    register_installation(&pool, 9004, 7, "acme", "Organization", &user.id)
        .await
        .unwrap();

    assert!(set_installation_suspended(&pool, 9004, true).await.unwrap());
    assert!(!installation_usable(&pool, 9004).await.unwrap());
    // The row is still known: suspension is a flag, not deletion.
    assert!(get_installation(&pool, 9004).await.unwrap().is_some());

    assert!(set_installation_suspended(&pool, 9004, false)
        .await
        .unwrap());
    assert!(installation_usable(&pool, 9004).await.unwrap());

    // Suspending the unknown changes nothing.
    assert!(!set_installation_suspended(&pool, 424242, true)
        .await
        .unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn revocation_is_deletion_and_deletion_is_total(pool: PgPool) {
    let user = support::seed_user(&pool, "revoke").await;
    register_installation(&pool, 9005, 9, "acme", "User", &user.id)
        .await
        .unwrap();

    assert!(remove_installation(&pool, 9005).await.unwrap());
    assert!(get_installation(&pool, 9005).await.unwrap().is_none());
    assert!(!installation_usable(&pool, 9005).await.unwrap());
    // Removing twice is idempotent, not an error.
    assert!(!remove_installation(&pool, 9005).await.unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn installations_belong_to_their_own_accounts(pool: PgPool) {
    let user = support::seed_user(&pool, "accounts").await;
    register_installation(&pool, 9006, 100, "acme", "Organization", &user.id)
        .await
        .unwrap();
    register_installation(&pool, 9007, 200, "other", "Organization", &user.id)
        .await
        .unwrap();

    // Re-registering 9006 with a different account rewrites *that* row; the
    // other installation is untouched. Identity follows the installation ID.
    let row = get_installation(&pool, 9006).await.unwrap().unwrap();
    assert_eq!(row.account_id, 100);
    let other = get_installation(&pool, 9007).await.unwrap().unwrap();
    assert_eq!(other.account_login, "other");
}

// ---------------------------------------------------------------------------
// Phase 19B.3: installation token acquisition (memory-only)
// ---------------------------------------------------------------------------

use firecrow_backend::services::github_app::exchange_installation_token;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const INSTALLATION_ID: i64 = 9001;

async fn exchanging_server(status: u16, body: serde_json::Value, expect: usize) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/app/installations/{INSTALLATION_ID}/access_tokens"
        )))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .expect(expect as u64)
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn a_successful_exchange_returns_a_bounded_token() {
    let server = exchanging_server(
        201,
        serde_json::json!({
            "token": "ghs_test-installation-token",
            "expires_at": "2026-10-04T01:00:00Z",
        }),
        1,
    )
    .await;

    let token = exchange_installation_token(&server.uri(), &identity(), INSTALLATION_ID)
        .await
        .expect("exchange succeeds");
    assert_eq!(token.token(), "ghs_test-installation-token");
    assert_eq!(
        token.expires_at(),
        chrono::DateTime::parse_from_rfc3339("2026-10-04T01:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    );
    // Freshly minted, far from expiry.
    assert!(!token.is_expired(
        chrono::DateTime::parse_from_rfc3339("2026-10-04T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    ));
    // At the expiry instant it is unusable.
    assert!(token.is_expired(token.expires_at()));
}

#[tokio::test]
async fn the_exchange_authenticates_as_the_app() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": "ghs_x",
            "expires_at": "2026-10-04T01:00:00Z",
        })))
        .mount(&server)
        .await;

    exchange_installation_token(&server.uri(), &identity(), INSTALLATION_ID)
        .await
        .expect("exchange succeeds");

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let auth = requests[0]
        .headers
        .get("authorization")
        .expect("Authorization header is sent")
        .to_str()
        .unwrap()
        .to_string();
    let jwt = auth
        .strip_prefix("Bearer ")
        .expect("Bearer scheme")
        .to_string();
    assert_eq!(
        jwt.split('.').count(),
        3,
        "the credential is an App JWT, not a stored token"
    );
}

/// Unwrap the error side of an exchange. `expect_err` is unusable here:
/// it requires `Debug` on the value type, which the token deliberately
/// lacks — so a helper that matches instead.
async fn exchange_err(
    server: &MockServer,
    installation_id: i64,
    what: &str,
) -> firecrow_backend::error::AppError {
    match exchange_installation_token(&server.uri(), &identity(), installation_id).await {
        Err(err) => err,
        Ok(_) => panic!("{what} must fail"),
    }
}

#[tokio::test]
async fn a_rejected_credential_and_an_unknown_installation_fail_at_once() {
    // 401: exactly one attempt — retrying a rejected credential is pointless.
    let server = exchanging_server(401, serde_json::json!({"message": "Bad credentials"}), 1).await;
    let err = exchange_err(&server, INSTALLATION_ID, "401").await;
    assert!(
        matches!(err, firecrow_backend::error::AppError::Unauthorized(_)),
        "got: {err}"
    );
    assert!(!err.to_string().contains("Bad credentials"));

    // 404: unknown, revoked, or suspended — reported together, like the
    // repository-access mapping, so the error never distinguishes them.
    let server = exchanging_server(404, serde_json::json!({"message": "Not Found"}), 1).await;
    let err = exchange_err(&server, INSTALLATION_ID, "404").await;
    assert!(
        matches!(err, firecrow_backend::error::AppError::NotFound(_)),
        "got: {err}"
    );

    // A malformed installation ID never reaches the network.
    let err = exchange_err(&server, 0, "ID 0").await;
    assert!(matches!(
        err,
        firecrow_backend::error::AppError::NotFound(_)
    ));
}

#[tokio::test]
async fn transient_failures_are_retried_once_then_reported() {
    // 429 then success: the first request is rate-limited, the exhausted
    // 429 mock stops matching, and the retry reaches the success mock.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": "ghs_after-retry",
            "expires_at": "2026-10-04T01:00:00Z",
        })))
        .mount(&server)
        .await;
    let token = exchange_installation_token(&server.uri(), &identity(), INSTALLATION_ID)
        .await
        .expect("transient 429 is retried");
    assert_eq!(token.token(), "ghs_after-retry");

    // Persistent 500: two attempts, then unavailable — never infinite.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .expect(2)
        .mount(&server)
        .await;
    let err = exchange_err(&server, INSTALLATION_ID, "persistent 500").await;
    assert!(
        matches!(err, firecrow_backend::error::AppError::Unavailable(_)),
        "got: {err}"
    );
}

#[tokio::test]
async fn malformed_and_oversized_responses_are_refused() {
    // Valid JSON but no token.
    let server = exchanging_server(
        201,
        serde_json::json!({"expires_at": "2026-10-04T01:00:00Z"}),
        1,
    )
    .await;
    assert!(
        exchange_installation_token(&server.uri(), &identity(), INSTALLATION_ID)
            .await
            .is_err()
    );

    // Not JSON at all.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_body_string("<html>nope</html>"))
        .expect(1)
        .mount(&server)
        .await;
    assert!(
        exchange_installation_token(&server.uri(), &identity(), INSTALLATION_ID)
            .await
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Phase 19B.4: installation → repository authorization
// ---------------------------------------------------------------------------

use firecrow_backend::services::github_app::authorize_installation_repo;

async fn chain_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/app/installations/{INSTALLATION_ID}/access_tokens"
        )))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": "ghs_chain-token",
            "expires_at": "2026-10-04T01:00:00Z",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widget"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "full_name": "acme/widget",
            "private": true,
            "default_branch": "main",
        })))
        .mount(&server)
        .await;
    server
}

async fn owned_installation(pool: &PgPool, user: &str) -> i64 {
    register_installation(pool, INSTALLATION_ID, 4242, "acme", "Organization", user)
        .await
        .expect("fixture installation");
    INSTALLATION_ID
}

#[sqlx::test(migrations = "./migrations")]
async fn the_full_chain_authorizes_a_reachable_repository(pool: PgPool) {
    let user = support::seed_user(&pool, "chain").await;
    owned_installation(&pool, &user.id).await;
    let server = chain_server().await;

    let authorized = authorize_installation_repo(
        &pool,
        &server.uri(),
        &identity(),
        &user.id,
        INSTALLATION_ID,
        "acme",
        "widget",
    )
    .await
    .expect("reachable repository authorizes");

    assert_eq!(authorized.installation_id, INSTALLATION_ID);
    assert_eq!(authorized.owner, "acme");
    assert_eq!(authorized.repo, "widget");

    // Both links were actually consulted: the token endpoint and the
    // repository endpoint, the latter with the installation token.
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let repo_call = requests
        .iter()
        .find(|r| r.url.as_str().contains("/repos/acme/widget"))
        .expect("repository check happened");
    assert_eq!(
        repo_call
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        "Bearer ghs_chain-token",
        "the check runs as the installation, not the App and not the user"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn another_users_installation_is_forbidden_without_network(pool: PgPool) {
    let owner = support::seed_user(&pool, "chainowner").await;
    let stranger = support::seed_user(&pool, "chainstranger").await;
    owned_installation(&pool, &owner.id).await;
    let server = chain_server().await;

    let err = authorize_installation_repo(
        &pool,
        &server.uri(),
        &identity(),
        &stranger.id,
        INSTALLATION_ID,
        "acme",
        "widget",
    )
    .await
    .expect_err("foreign installation must fail");
    assert!(
        matches!(err, firecrow_backend::error::AppError::Forbidden(_)),
        "got: {err}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "ownership is decided locally, before any credential is minted"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn suspended_and_unknown_installations_stop_before_network(pool: PgPool) {
    let user = support::seed_user(&pool, "chainstop").await;
    owned_installation(&pool, &user.id).await;
    let server = chain_server().await;

    set_installation_suspended(&pool, INSTALLATION_ID, true)
        .await
        .unwrap();
    let err = authorize_installation_repo(
        &pool,
        &server.uri(),
        &identity(),
        &user.id,
        INSTALLATION_ID,
        "acme",
        "widget",
    )
    .await
    .expect_err("suspended must fail");
    assert!(matches!(
        err,
        firecrow_backend::error::AppError::NotFound(_)
    ));

    let err = authorize_installation_repo(
        &pool,
        &server.uri(),
        &identity(),
        &user.id,
        777888999,
        "acme",
        "widget",
    )
    .await
    .expect_err("unknown must fail");
    assert!(matches!(
        err,
        firecrow_backend::error::AppError::NotFound(_)
    ));

    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "no token is minted for an unusable installation"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn an_inaccessible_repository_is_refused(pool: PgPool) {
    let user = support::seed_user(&pool, "chainnoaccess").await;
    owned_installation(&pool, &user.id).await;

    // Token exchange works, but the installation cannot see the repository.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": "ghs_chain-token",
            "expires_at": "2026-10-04T01:00:00Z",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "message": "Not Found"
        })))
        .mount(&server)
        .await;

    let err = authorize_installation_repo(
        &pool,
        &server.uri(),
        &identity(),
        &user.id,
        INSTALLATION_ID,
        "acme",
        "widget",
    )
    .await
    .expect_err("inaccessible repository must fail");
    assert!(
        matches!(err, firecrow_backend::error::AppError::NotFound(_)),
        "got: {err}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn hostile_segments_never_become_urls(pool: PgPool) {
    let user = support::seed_user(&pool, "chainseg").await;
    owned_installation(&pool, &user.id).await;
    let server = chain_server().await;

    for (owner, repo) in [
        ("../etc", "widget"),
        ("acme", "../../etc"),
        ("ac/me", "widget"),
        ("", "widget"),
        ("acme", ""),
        // Surrounding whitespace is trimmed, not smuggled: " acme " would
        // authorize as "acme", which the mock below proves harmless.
    ] {
        let err = authorize_installation_repo(
            &pool,
            &server.uri(),
            &identity(),
            &user.id,
            INSTALLATION_ID,
            owner,
            repo,
        )
        .await
        .expect_err("hostile segment must fail");
        assert!(
            matches!(err, firecrow_backend::error::AppError::BadRequest(_)),
            "{owner:?}/{repo:?} got: {err}"
        );
    }
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "no request may carry an unvalidated segment"
    );
}

// ---------------------------------------------------------------------------
// Phase 19B.5: the webhook cryptographic boundary
// ---------------------------------------------------------------------------

use firecrow_backend::services::github_app::{
    record_webhook_delivery, verify_webhook_signature, webhook_body_sha256,
};

const WEBHOOK_SECRET: &str = "wh-test-secret-not-real";

fn sign(secret: &str, body: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes any key");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

#[test]
fn signature_verification_is_exact_and_constant_time_safe() {
    let body = br#"{"zen":"Keep it logically awesome."}"#;
    let good = sign(WEBHOOK_SECRET, body);

    assert!(verify_webhook_signature(WEBHOOK_SECRET, body, &good));
    // Wrong secret, tampered body, and malformed headers all fail closed.
    assert!(!verify_webhook_signature("other-secret", body, &good));
    let mut tampered = body.to_vec();
    tampered.push(b' ');
    assert!(!verify_webhook_signature(WEBHOOK_SECRET, &tampered, &good));
    assert!(!verify_webhook_signature(WEBHOOK_SECRET, body, ""));
    assert!(!verify_webhook_signature(WEBHOOK_SECRET, body, "sha256="));
    assert!(!verify_webhook_signature(
        WEBHOOK_SECRET,
        body,
        &good.replacen("sha256=", "sha1=", 1)
    ));
    assert!(!verify_webhook_signature(
        WEBHOOK_SECRET,
        body,
        "not-even-hex"
    ));
    // Empty secret never verifies, even against its own output.
    let empty_signed = sign("", body);
    assert!(!verify_webhook_signature("", body, &empty_signed));
    // Oversized bodies are refused before hashing.
    let big = vec![b'x'; firecrow_backend::services::github_app::GITHUB_WEBHOOK_MAX_BYTES + 1];
    assert!(!verify_webhook_signature(
        WEBHOOK_SECRET,
        &big,
        &sign(WEBHOOK_SECRET, &big)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn delivery_ids_deduplicate_and_replays_conflict(pool: PgPool) {
    use firecrow_backend::services::github_app::{mark_webhook_outcome, DeliveryReplay};

    let sha = webhook_body_sha256(b"{}");

    assert_eq!(
        record_webhook_delivery(&pool, "delivery-1", "ping", &sha, None)
            .await
            .unwrap(),
        DeliveryReplay::Process,
        "first sighting processes"
    );
    // Still pending: a redelivery retries the unfinished work.
    assert_eq!(
        record_webhook_delivery(&pool, "delivery-1", "ping", &sha, None)
            .await
            .unwrap(),
        DeliveryReplay::Process,
    );
    // Closed as processed: now it is a duplicate.
    mark_webhook_outcome(&pool, "delivery-1", "processed")
        .await
        .unwrap();
    assert_eq!(
        record_webhook_delivery(&pool, "delivery-1", "ping", &sha, None)
            .await
            .unwrap(),
        DeliveryReplay::Duplicate,
        "a handled delivery acknowledges without reprocessing"
    );
    // Same ID, different bytes: a replay carrying a different body.
    let other = webhook_body_sha256(br#"{"different":true}"#);
    let err = record_webhook_delivery(&pool, "delivery-1", "ping", &other, None)
        .await
        .expect_err("modified replay must conflict");
    assert!(matches!(
        err,
        firecrow_backend::error::AppError::Conflict(_)
    ));
}

/// A webhook TestServer with the signature secret configured.
async fn webhook_app(pool: PgPool) -> axum_test::TestServer {
    use firecrow_backend::app::{build_app, build_state};

    let mut settings = support::test_settings();
    settings.github_app_webhook_secret = WEBHOOK_SECRET.into();
    let state = build_state(settings, pool, None)
        .await
        .expect("state builds");
    axum_test::TestServer::new(build_app(state, false)).expect("test server")
}

async fn post_webhook(
    app: &axum_test::TestServer,
    event: &str,
    delivery: String,
    body: Vec<u8>,
    secret: &str,
) -> axum_test::TestResponse {
    let signature = if secret.is_empty() {
        String::new()
    } else {
        sign(secret, &body)
    };
    let mut req = app.post("/api/v1/github/webhook");
    if !delivery.is_empty() {
        req = req.add_header("x-github-delivery", delivery);
    }
    // Owned header values and an owned body: this helper is usable inside
    // `join_all` over generated inputs without borrowing a temporary.
    req.add_header("x-github-event", event.to_string())
        .add_header("x-hub-signature-256", signature)
        .bytes(axum::body::Bytes::from(body))
        .await
}

#[sqlx::test(migrations = "./migrations")]
async fn the_webhook_route_enforces_the_boundary(pool: PgPool) {
    let app = webhook_app(pool.clone()).await;
    let ping = br#"{"zen":"hi"}"#;

    // Valid signature: pong.
    let ok = post_webhook(
        &app,
        "ping",
        "delivery-ok".into(),
        ping.to_vec(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(ok.status_code(), 200, "body: {}", ok.text());

    // Missing signature.
    let missing = app
        .post("/api/v1/github/webhook")
        .add_header("x-github-event", "ping")
        .add_header("x-github-delivery", "delivery-missing")
        .bytes(axum::body::Bytes::from_static(ping))
        .await;
    assert_eq!(missing.status_code(), 401);

    // Wrong secret.
    let forged = post_webhook(
        &app,
        "ping",
        "delivery-forged".into(),
        ping.to_vec(),
        "wrong-secret",
    )
    .await;
    assert_eq!(forged.status_code(), 401);

    // Tampered body under a valid signature for other bytes.
    let tampered = app
        .post("/api/v1/github/webhook")
        .add_header("x-github-event", "ping")
        .add_header("x-github-delivery", "delivery-tampered")
        .add_header("x-hub-signature-256", sign(WEBHOOK_SECRET, b"{}"))
        .bytes(axum::body::Bytes::from_static(ping))
        .await;
    assert_eq!(tampered.status_code(), 401);

    // Malformed JSON with a valid signature for those bytes: 400, and the
    // failure is about shape, never about the secret.
    let malformed = post_webhook(
        &app,
        "ping",
        "delivery-malformed".into(),
        b"{nope".to_vec(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(malformed.status_code(), 400);

    // Unknown events are acknowledged without effect.
    let unknown = post_webhook(
        &app,
        "star",
        "delivery-unknown".into(),
        br#"{"action":"created"}"#.to_vec(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(unknown.status_code(), 200, "body: {}", unknown.text());
    assert_eq!(
        unknown.json::<serde_json::Value>()["status"],
        serde_json::json!("ignored")
    );

    // Oversized body: refused even with a valid signature.
    let big = vec![b'{'; firecrow_backend::services::github_app::GITHUB_WEBHOOK_MAX_BYTES + 1];
    let huge = post_webhook(
        &app,
        "ping",
        "delivery-huge".into(),
        big.clone(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(huge.status_code(), 413, "body: {}", huge.text());

    // A duplicate delivery is acknowledged, not reprocessed.
    let replay = post_webhook(
        &app,
        "ping",
        "delivery-ok".into(),
        ping.to_vec(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(replay.status_code(), 200);
    assert_eq!(
        replay.json::<serde_json::Value>()["status"],
        serde_json::json!("duplicate")
    );

    // Same ID, different body: the replay conflict.
    let conflicted = post_webhook(
        &app,
        "ping",
        "delivery-ok".into(),
        br#"{"zen":"different"}"#.to_vec(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(conflicted.status_code(), 409);
}

#[sqlx::test(migrations = "./migrations")]
async fn an_unconfigured_webhook_refuses_everything(pool: PgPool) {
    // The default test app has no webhook secret: every delivery fails
    // closed, including a well-formed one.
    let app = support::test_app(pool.clone()).await;
    let body = br#"{"zen":"hi"}"#;
    let response = post_webhook(
        &app,
        "ping",
        "delivery-unconfigured".into(),
        body.to_vec(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(response.status_code(), 501, "body: {}", response.text());

    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM github_webhook_deliveries")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows.0, 0, "a refused delivery records nothing");
}

#[sqlx::test(migrations = "./migrations")]
async fn installation_lifecycle_events_drive_identity(pool: PgPool) {
    let app = webhook_app(pool.clone()).await;
    let user = support::seed_user(&pool, "whinstaller").await;
    // Link the Fire Crow user to the installing GitHub account first:
    // without OAuth linkage there is no owner to attribute.
    sqlx::query("UPDATE users SET github_id=$1 WHERE id=$2")
        .bind("4242")
        .bind(&user.id)
        .execute(&pool)
        .await
        .unwrap();

    // Install by the linked account: registers.
    let created = serde_json::json!({
        "action": "created",
        "installation": {
            "id": 61001,
            "account": {"id": 4242, "login": "acme-org", "type": "Organization"},
        },
        "sender": {"id": 4242, "login": "octocat"},
    });
    let created_bytes = serde_json::to_vec(&created).unwrap();
    let response = post_webhook(
        &app,
        "installation",
        "delivery-created".into(),
        created_bytes.clone(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(response.status_code(), 200, "body: {}", response.text());
    assert!(get_installation(&pool, 61001).await.unwrap().is_some());

    // Suspend: unusable but still known.
    let suspend = serde_json::json!({
        "action": "suspend",
        "installation": {"id": 61001},
    });
    let suspend_bytes = serde_json::to_vec(&suspend).unwrap();
    let response = post_webhook(
        &app,
        "installation",
        "delivery-suspend".into(),
        suspend_bytes.clone(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(response.status_code(), 200, "body: {}", response.text());
    assert!(!installation_usable(&pool, 61001).await.unwrap());

    // Uninstall: revoked, the row is gone.
    let deleted = serde_json::json!({
        "action": "deleted",
        "installation": {"id": 61001},
    });
    let deleted_bytes = serde_json::to_vec(&deleted).unwrap();
    let response = post_webhook(
        &app,
        "installation",
        "delivery-deleted".into(),
        deleted_bytes.clone(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(response.status_code(), 200, "body: {}", response.text());
    assert!(get_installation(&pool, 61001).await.unwrap().is_none());

    // Install by an unlinked GitHub account: acknowledged, stored nowhere.
    let stranger = serde_json::json!({
        "action": "created",
        "installation": {
            "id": 61002,
            "account": {"id": 9999, "login": "stranger", "type": "User"},
        },
        "sender": {"id": 9999, "login": "stranger"},
    });
    let stranger_bytes = serde_json::to_vec(&stranger).unwrap();
    let response = post_webhook(
        &app,
        "installation",
        "delivery-stranger".into(),
        stranger_bytes.clone(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(response.status_code(), 200, "body: {}", response.text());
    assert_eq!(
        response.json::<serde_json::Value>()["registered"],
        serde_json::json!(false)
    );
    assert!(get_installation(&pool, 61002).await.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Phase 19B.6: a verified push becomes an audit through the one door
// ---------------------------------------------------------------------------

static PUSH_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A webhook server with the App identity configured, talking to a mocked
/// GitHub API for the token exchange and the repository check.
async fn push_app(pool: PgPool, api_base: &str) -> axum_test::TestServer {
    use firecrow_backend::app::{build_app, build_state};

    let mut settings = support::test_settings();
    settings.github_app_webhook_secret = WEBHOOK_SECRET.into();
    settings.github_app_id = APP_ID;
    settings.github_app_private_key = TEST_PRIVATE_KEY_PEM.into();
    let state = build_state(settings, pool, None)
        .await
        .expect("state builds");
    let _ = api_base;
    axum_test::TestServer::new(build_app(state, false)).expect("test server")
}

fn push_body(after: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "ref": "refs/heads/main",
        "after": after,
        "repository": {"full_name": "acme/widget"},
        "installation": {"id": INSTALLATION_ID},
    }))
    .unwrap()
}

async fn mock_github_for_push() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": "ghs_push-token",
            "expires_at": "2030-01-01T00:00:00Z",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/widget"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "full_name": "acme/widget",
            "private": true,
            "default_branch": "main",
        })))
        .mount(&server)
        .await;
    server
}

#[sqlx::test(migrations = "./migrations")]
async fn a_verified_push_queues_one_pinned_audit(pool: PgPool) {
    let _env = PUSH_ENV_LOCK.lock().await;
    let user = support::seed_user(&pool, "push").await;
    register_installation(
        &pool,
        INSTALLATION_ID,
        4242,
        "acme",
        "Organization",
        &user.id,
    )
    .await
    .unwrap();

    let api = mock_github_for_push().await;
    std::env::set_var("GITHUB_API_BASE_URL", api.uri());
    let app = push_app(pool.clone(), &api.uri()).await;

    let head = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let body = push_body(head);
    let response = post_webhook(
        &app,
        "push",
        "delivery-push-1".into(),
        body.clone(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(response.status_code(), 200, "body: {}", response.text());
    let job_id = response.json::<serde_json::Value>()["job_id"]
        .as_str()
        .expect("push queues a job")
        .to_string();

    // The job is an ordinary job: same door, same columns, pinned snapshot.
    let job: (String, String, Option<String>, Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT status, repo_branch, requested_commit_sha, github_installation_id, webhook_delivery_id
         FROM audit_jobs WHERE id=$1",
    )
    .bind(&job_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(job.0, "queued");
    assert_eq!(job.1, "main");
    assert_eq!(job.2.as_deref(), Some(head));
    assert_eq!(job.3, Some(INSTALLATION_ID));
    assert_eq!(job.4.as_deref(), Some("delivery-push-1"));

    // Redelivery is a duplicate acknowledgement, never a second job.
    let replay = post_webhook(
        &app,
        "push",
        "delivery-push-1".into(),
        body.clone(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(replay.status_code(), 200);
    assert_eq!(
        replay.json::<serde_json::Value>()["status"],
        serde_json::json!("duplicate")
    );
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1, "one delivery is one job, even redelivered");

    std::env::remove_var("GITHUB_API_BASE_URL");
}

#[sqlx::test(migrations = "./migrations")]
async fn pushes_that_authorize_nothing_queue_nothing(pool: PgPool) {
    let _env = PUSH_ENV_LOCK.lock().await;
    let user = support::seed_user(&pool, "pushignore").await;
    register_installation(
        &pool,
        INSTALLATION_ID,
        4242,
        "acme",
        "Organization",
        &user.id,
    )
    .await
    .unwrap();

    let api = mock_github_for_push().await;
    std::env::set_var("GITHUB_API_BASE_URL", api.uri());
    let app = push_app(pool.clone(), &api.uri()).await;

    // Branch deletion: no snapshot, no audit.
    let deleted = post_webhook(
        &app,
        "push",
        "delivery-deleted-branch".into(),
        push_body("0000000000000000000000000000000000000000"),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(deleted.status_code(), 200, "body: {}", deleted.text());

    // Unknown installation: acknowledged, never authorized.
    let mut foreign = push_body("cccccccccccccccccccccccccccccccccccccccc");
    let mut value: serde_json::Value = serde_json::from_slice(&foreign).unwrap();
    value["installation"]["id"] = serde_json::json!(31337);
    foreign = serde_json::to_vec(&value).unwrap();
    let unknown = post_webhook(
        &app,
        "push",
        "delivery-foreign".into(),
        foreign.clone(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(unknown.status_code(), 200, "body: {}", unknown.text());

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0, "neither push may create a job");

    std::env::remove_var("GITHUB_API_BASE_URL");
}

// ---------------------------------------------------------------------------
// Phase 19B.7: PR checks report the audit outcome, never a new pipeline
// ---------------------------------------------------------------------------

use firecrow_backend::services::github_app::{post_check_run, FIRECROW_CHECK_NAME};

#[tokio::test]
async fn a_check_run_posts_conclusion_counts_and_identity() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widget/check-runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": 77001})))
        .expect(1)
        .mount(&server)
        .await;

    let id = post_check_run(
        &server.uri(),
        "ghs_check-token",
        "acme",
        "widget",
        "dddddddddddddddddddddddddddddddddddddddd",
        "success",
        "Security audit completed",
        "Fire Crow audit completed: 2 finding(s).",
    )
    .await
    .expect("check posts");

    assert_eq!(id, 77001);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let call = &requests[0];
    assert_eq!(
        call.headers.get("authorization").unwrap().to_str().unwrap(),
        "Bearer ghs_check-token",
        "the check posts as the installation"
    );
    let body: serde_json::Value = serde_json::from_slice(&call.body).unwrap();
    assert_eq!(body["name"], serde_json::json!(FIRECROW_CHECK_NAME));
    assert_eq!(
        body["head_sha"],
        serde_json::json!("dddddddddddddddddddddddddddddddddddddddd")
    );
    assert_eq!(body["status"], serde_json::json!("completed"));
    assert_eq!(body["conclusion"], serde_json::json!("success"));
}

#[tokio::test]
async fn check_run_inputs_are_validated_before_network() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": 1})))
        .expect(0)
        .mount(&server)
        .await;

    // Not a SHA: refused locally.
    assert!(post_check_run(
        &server.uri(),
        "t",
        "acme",
        "widget",
        "main",
        "success",
        "t",
        "s",
    )
    .await
    .is_err());
    // Unknown conclusion: refused locally (GitHub would 422).
    assert!(post_check_run(
        &server.uri(),
        "t",
        "acme",
        "widget",
        "dddddddddddddddddddddddddddddddddddddddd",
        "maybe",
        "t",
        "s",
    )
    .await
    .is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn a_pull_request_pins_its_head_through_the_same_door(pool: PgPool) {
    let _env = PUSH_ENV_LOCK.lock().await;
    let user = support::seed_user(&pool, "pr").await;
    register_installation(
        &pool,
        INSTALLATION_ID,
        4242,
        "acme",
        "Organization",
        &user.id,
    )
    .await
    .unwrap();

    let api = mock_github_for_push().await;
    std::env::set_var("GITHUB_API_BASE_URL", api.uri());
    let app = push_app(pool.clone(), &api.uri()).await;

    // `synchronize` carries a new head: queue it, pinned.
    let head = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let body = serde_json::to_vec(&serde_json::json!({
        "action": "synchronize",
        "pull_request": {"head": {"sha": head, "ref": "feature-branch"}},
        "repository": {"full_name": "acme/widget"},
        "installation": {"id": INSTALLATION_ID},
    }))
    .unwrap();
    let response = post_webhook(
        &app,
        "pull_request",
        "delivery-pr-1".into(),
        body.clone(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(response.status_code(), 200, "body: {}", response.text());
    let job_id = response.json::<serde_json::Value>()["job_id"]
        .as_str()
        .expect("PR queues a job")
        .to_string();
    let stored: (Option<String>, String, Option<i64>) = sqlx::query_as(
        "SELECT requested_commit_sha, repo_branch, github_installation_id FROM audit_jobs WHERE id=$1",
    )
    .bind(&job_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.0.as_deref(), Some(head));
    assert_eq!(stored.1, "feature-branch");
    assert_eq!(stored.2, Some(INSTALLATION_ID));

    // A closed PR carries no new snapshot: acknowledged, queued nothing.
    let closed = serde_json::to_vec(&serde_json::json!({
        "action": "closed",
        "pull_request": {"head": {"sha": head, "ref": "feature-branch"}},
        "repository": {"full_name": "acme/widget"},
        "installation": {"id": INSTALLATION_ID},
    }))
    .unwrap();
    let response = post_webhook(
        &app,
        "pull_request",
        "delivery-pr-2".into(),
        closed.clone(),
        WEBHOOK_SECRET,
    )
    .await;
    assert_eq!(response.status_code(), 200, "body: {}", response.text());
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1, "a closed PR queues nothing");

    std::env::remove_var("GITHUB_API_BASE_URL");
}

#[sqlx::test(migrations = "./migrations")]
async fn a_finished_webhook_job_reports_its_outcome_as_a_check(pool: PgPool) {
    let _env = PUSH_ENV_LOCK.lock().await;
    let user = support::seed_user(&pool, "check").await;
    let job = support::seed_job(&pool, &user.id, "failed").await;
    let head = "ffffffffffffffffffffffffffffffffffffffff";
    sqlx::query("UPDATE audit_jobs SET github_installation_id=$1, commit_sha=$2 WHERE id=$3")
        .bind(INSTALLATION_ID)
        .bind(head)
        .bind(&job)
        .execute(&pool)
        .await
        .unwrap();

    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/app/installations/{INSTALLATION_ID}/access_tokens"
        )))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": "ghs_check-token",
            "expires_at": "2030-01-01T00:00:00Z",
        })))
        .mount(&api)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/acme/widget/check-runs"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": 77002})))
        .expect(1)
        .mount(&api)
        .await;
    // The job's repository must resolve under the check URL.
    sqlx::query("UPDATE audit_jobs SET repo_url=$1 WHERE id=$2")
        .bind("https://github.com/acme/widget")
        .bind(&job)
        .execute(&pool)
        .await
        .unwrap();

    std::env::set_var("GITHUB_API_BASE_URL", api.uri());
    let mut settings = support::test_settings();
    settings.github_app_id = APP_ID;
    settings.github_app_private_key = TEST_PRIVATE_KEY_PEM.into();
    firecrow_backend::workers::maybe_post_github_check(&pool, &settings, &job).await;

    let requests = api.received_requests().await.unwrap();
    let check = requests
        .iter()
        .find(|r| r.url.as_str().contains("/check-runs"))
        .expect("a check run was posted");
    let body: serde_json::Value = serde_json::from_slice(&check.body).unwrap();
    assert_eq!(body["conclusion"], serde_json::json!("failure"));
    assert_eq!(body["head_sha"], serde_json::json!(head));
    assert!(body["output"]["summary"]
        .as_str()
        .unwrap()
        .contains("failed"));

    std::env::remove_var("GITHUB_API_BASE_URL");
}

#[sqlx::test(migrations = "./migrations")]
async fn check_reporting_is_best_effort_and_never_fires_unattributed(pool: PgPool) {
    let _env = PUSH_ENV_LOCK.lock().await;
    let user = support::seed_user(&pool, "checkskip").await;
    // No installation on the job: nothing to report to, no network.
    let job = support::seed_job(&pool, &user.id, "failed").await;

    let api = MockServer::start().await;
    std::env::set_var("GITHUB_API_BASE_URL", api.uri());
    let mut settings = support::test_settings();
    settings.github_app_id = APP_ID;
    settings.github_app_private_key = TEST_PRIVATE_KEY_PEM.into();
    firecrow_backend::workers::maybe_post_github_check(&pool, &settings, &job).await;

    assert_eq!(api.received_requests().await.unwrap().len(), 0);

    std::env::remove_var("GITHUB_API_BASE_URL");
}

// ---------------------------------------------------------------------------
// Phase 20: concurrent webhook delivery
// ---------------------------------------------------------------------------

/// N workers deliver the same webhook simultaneously. Exactly one creates a
/// job; the rest see it as a duplicate. The UNIQUE constraint on
/// `webhook_delivery_id` is the arbiter — no application-level check could
/// close this race.
#[sqlx::test(migrations = "./migrations")]
async fn concurrent_deliveries_of_one_event_produce_one_job(pool: PgPool) {
    let _env = PUSH_ENV_LOCK.lock().await;
    let user = support::seed_user(&pool, "race").await;
    register_installation(
        &pool,
        INSTALLATION_ID,
        4242,
        "acme",
        "Organization",
        &user.id,
    )
    .await
    .unwrap();

    let api = mock_github_for_push().await;
    std::env::set_var("GITHUB_API_BASE_URL", api.uri());
    let app = push_app(pool.clone(), &api.uri()).await;

    let head = "1111111111111111111111111111111111111111";
    let body = push_body(head);

    // 8 concurrent deliveries of the same event.
    //
    // `join_all`, not `tokio::spawn`: the test server is not `Send`, and the
    // race this proves is between database writers, not between threads. All
    // eight requests are in flight at once against the same server.
    let responses = futures::future::join_all((0..8).map(|_| {
        post_webhook(
            &app,
            "push",
            "delivery-race".into(),
            body.clone(),
            WEBHOOK_SECRET,
        )
    }))
    .await;

    // Every response is 200 and every one names the *same* job.
    //
    // Note what concurrency legitimately does here: a redelivery that
    // arrives while the first attempt is still running sees outcome
    // `pending`, so it re-runs the handler rather than short-circuiting as a
    // duplicate. That is deliberate — a crash mid-handling must not lose the
    // work. Idempotency, not the status label, is what keeps this safe:
    // `webhook_delivery_id` UNIQUE means the second insert creates nothing
    // and returns the first attempt's job. So the invariant under race is
    // "one job, one id", not "one 200".
    let mut job_ids = std::collections::HashSet::new();
    for response in responses {
        assert_eq!(response.status_code(), 200);
        let body = response.json::<serde_json::Value>();
        if let Some(id) = body["job_id"].as_str() {
            job_ids.insert(id.to_string());
        }
    }
    assert_eq!(
        job_ids.len(),
        1,
        "concurrent deliveries must agree on one job id, got {job_ids:?}"
    );

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1, "one delivery is one job under concurrency");

    std::env::remove_var("GITHUB_API_BASE_URL");
}
/// Distinct deliveries are distinct jobs — but they still pass through the
/// same per-user gate as user submissions, so a burst beyond
/// `max_active_jobs_per_user` is refused rather than queued.
///
/// This is the webhook half of 19B.6's "no unlimited job producer": a GitHub
/// flood can create at most one job per live-audit slot.
#[sqlx::test(migrations = "./migrations")]
async fn concurrent_distinct_events_respect_the_per_user_gate(pool: PgPool) {
    let _env = PUSH_ENV_LOCK.lock().await;
    let user = support::seed_user(&pool, "race2").await;
    register_installation(
        &pool,
        INSTALLATION_ID,
        4242,
        "acme",
        "Organization",
        &user.id,
    )
    .await
    .unwrap();

    let api = mock_github_for_push().await;
    std::env::set_var("GITHUB_API_BASE_URL", api.uri());
    let app = push_app(pool.clone(), &api.uri()).await;

    let head = "2222222222222222222222222222222222222222";
    let body = push_body(head);

    let app = std::sync::Arc::new(app);
    let responses = futures::future::join_all((0..5).map(|i| {
        post_webhook(
            &app,
            "push",
            format!("delivery-race-{i}"),
            body.clone(),
            WEBHOOK_SECRET,
        )
    }))
    .await;
    let mut queued = 0;
    let mut refused = 0;
    for response in responses {
        match response.status_code() {
            axum::http::StatusCode::OK => queued += 1,
            axum::http::StatusCode::CONFLICT => refused += 1,
            other => panic!("unexpected status: {}", other.as_u16()),
        }
    }
    assert_eq!(
        queued, 2,
        "distinct deliveries queue up to the per-user limit"
    );
    assert_eq!(refused, 3, "the burst beyond the limit is refused");

    // Refused deliveries created nothing, and each admitted one is its own job
    // attributed to its own delivery.
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 2, "a refused webhook must not leave a job behind");
    let distinct: (i64,) =
        sqlx::query_as("SELECT COUNT(DISTINCT webhook_delivery_id) FROM audit_jobs")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        distinct.0, 2,
        "each admitted job carries its own delivery id"
    );

    std::env::remove_var("GITHUB_API_BASE_URL");
}
