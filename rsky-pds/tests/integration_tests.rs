use crate::common::{create_account, get_admin_token};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jwt_simple::algorithms::ECDSAP256kKeyPairLike;
use jwt_simple::prelude::{Claims, Duration as JwtDuration, ES256kKeyPair};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use rand::RngCore;
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use rsky_lexicon::com::atproto::server::CreateInviteCodeOutput;
use rsky_pds::account_manager::helpers::account::activate_account;
use rsky_pds::config::ServerConfig;
use rsky_pds::db::DbConn;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};
use serial_test::serial;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

mod common;

const TEST_IMPORTED_ACCOUNT_DID: &str = "did:plc:khvyd3oiw46vif5gm7hijslk";
const TEST_EXTERNAL_AUTH_ISSUER: &str = "https://login.divine.video";
const TEST_EXTERNAL_AUTH_JWT_PRIVATE_KEY_HEX: &str =
    "7f2a55949068468ad5d670dfd0c0a33d5b9e7e1a2c0d2059f0f8f8779d4d055d";
const TEST_DPOP_PROOF_PRIVATE_KEY_HEX: &str =
    "9e2a55949068468ad5d670dfd0c0a33d5b9e7e1a2c0d2059f0f8f8779d4d0111";
const TEST_DPOP_PROOF_PRIVATE_KEY_HEX_ALT: &str =
    "6b2a55949068468ad5d670dfd0c0a33d5b9e7e1a2c0d2059f0f8f8779d4d0222";
const TEST_DPOP_PROOF_P256_PRIVATE_KEY_HEX: &str =
    "8a3d69f14f9b4f74abf5cf1e8bc2dc2f561f2320f3166d4c12a6c612f4d31123";

#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct ExternalAccessCnf {
    jkt: String,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct ExternalAuthClaims {
    #[serde(default)]
    scope: String,
    #[serde(default)]
    lxm: Option<String>,
    #[serde(default)]
    cnf: Option<ExternalAccessCnf>,
}

fn external_auth_public_key_hex() -> String {
    let key_bytes = hex::decode(TEST_EXTERNAL_AUTH_JWT_PRIVATE_KEY_HEX).unwrap();
    let key_pair = ES256kKeyPair::from_bytes(&key_bytes).unwrap();
    hex::encode(key_pair.public_key().to_bytes())
}

fn create_external_access_token(
    issuer: &str,
    audience: &str,
    did: &str,
    cnf_jkt: Option<&str>,
) -> String {
    let key_bytes = hex::decode(TEST_EXTERNAL_AUTH_JWT_PRIVATE_KEY_HEX).unwrap();
    let key_pair = ES256kKeyPair::from_bytes(&key_bytes).unwrap();
    let claims = Claims::with_custom_claims(
        ExternalAuthClaims {
            scope: "com.atproto.access".to_string(),
            lxm: None,
            cnf: cnf_jkt.map(|jkt| ExternalAccessCnf {
                jkt: jkt.to_string(),
            }),
        },
        JwtDuration::from_mins(15),
    )
    .with_subject(did)
    .with_audience(audience)
    .with_issuer(issuer);

    key_pair.sign(claims).unwrap()
}

fn dpop_public_jwk(secret_hex: &str) -> Value {
    let sk = SecretKey::from_slice(&hex::decode(secret_hex).unwrap()).unwrap();
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    let uncompressed = pk.serialize_uncompressed();
    let x = URL_SAFE_NO_PAD.encode(&uncompressed[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&uncompressed[33..65]);

    json!({
        "kty": "EC",
        "crv": "secp256k1",
        "x": x,
        "y": y,
    })
}

fn dpop_public_jwk_p256(secret_hex: &str) -> Value {
    let key_bytes: [u8; 32] = hex::decode(secret_hex).unwrap().try_into().unwrap();
    let signing_key = P256SigningKey::from_bytes((&key_bytes).into()).unwrap();
    let point = signing_key.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());

    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
    })
}

fn dpop_jwk_thumbprint(jwk: &Value) -> String {
    let canonical = format!(
        "{{\"crv\":\"{}\",\"kty\":\"{}\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk["crv"].as_str().unwrap(),
        jwk["kty"].as_str().unwrap(),
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap(),
    );
    let digest = Sha256::digest(canonical.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn create_dpop_proof(
    access_token: &str,
    method: &str,
    htu: &str,
    secret_hex: &str,
    nonce: Option<&str>,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut random = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut random);
    let jwk = dpop_public_jwk(secret_hex);
    let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256K",
        "jwk": jwk,
    });
    let payload = json!({
        "jti": format!("dpop-jti-{now}-{}", hex::encode(random)),
        "htm": method,
        "htu": htu,
        "iat": now,
        "ath": ath,
        "nonce": nonce,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let sk = SecretKey::from_slice(&hex::decode(secret_hex).unwrap()).unwrap();
    let hash = Sha256::digest(signing_input.as_bytes());
    let message = Message::from_digest_slice(hash.as_ref()).unwrap();
    let mut sig = sk.sign_ecdsa(message);
    sig.normalize_s();
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.serialize_compact());

    format!("{signing_input}.{sig_b64}")
}

fn create_dpop_proof_p256(
    access_token: &str,
    method: &str,
    htu: &str,
    secret_hex: &str,
    nonce: Option<&str>,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut random = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut random);
    let jwk = dpop_public_jwk_p256(secret_hex);
    let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": jwk,
    });
    let payload = json!({
        "jti": format!("dpop-p256-jti-{now}-{}", hex::encode(random)),
        "htm": method,
        "htu": htu,
        "iat": now,
        "ath": ath,
        "nonce": nonce,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let key_bytes: [u8; 32] = hex::decode(secret_hex).unwrap().try_into().unwrap();
    let signing_key = P256SigningKey::from_bytes((&key_bytes).into()).unwrap();
    let digest = Sha256::digest(signing_input.as_bytes());
    let signature: P256Signature = signing_key.sign_prehash(digest.as_slice()).unwrap();
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    format!("{signing_input}.{sig_b64}")
}

async fn issue_dpop_nonce(client: &Client, token: &str, dpop_proof: &str) -> String {
    let response = client
        .get("/xrpc/com.atproto.server.getSession")
        .header(Header::new("Authorization", format!("DPoP {token}")))
        .header(Header::new("DPoP", dpop_proof.to_string()))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
    let nonce = response
        .headers()
        .get_one("DPoP-Nonce")
        .unwrap_or("")
        .to_string();
    assert!(!nonce.is_empty());
    nonce
}

fn configure_external_auth_server() {
    unsafe {
        std::env::set_var("PDS_ENTRYWAY_URL", TEST_EXTERNAL_AUTH_ISSUER);
        std::env::set_var(
            "PDS_ENTRYWAY_JWT_PUBLIC_KEY_HEX",
            external_auth_public_key_hex(),
        );
    }
}

async fn create_active_account(client: &Client) -> String {
    create_account(client).await;

    let db = DbConn::get_one(client.rocket()).await.unwrap();
    activate_account(TEST_IMPORTED_ACCOUNT_DID, &db)
        .await
        .unwrap();

    TEST_IMPORTED_ACCOUNT_DID.to_string()
}

#[tokio::test]
async fn test_index() {
    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;
    let response = client.get("/").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
}

#[tokio::test]
async fn test_robots_txt() {
    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;
    let response = client.get("/robots.txt").dispatch().await;
    let response_status = response.status();
    let response_body = response.into_string().await.unwrap();
    assert_eq!(response_status, Status::Ok);
    assert_eq!(
        response_body,
        "# Hello!\n\n# Crawling the public API is allowed\nUser-agent: *\nAllow: /"
    );
}

#[tokio::test]
#[serial]
async fn test_oauth_protected_resource_metadata() {
    configure_external_auth_server();

    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;

    let response = client
        .get("/.well-known/oauth-protected-resource")
        .dispatch()
        .await;
    let response_status = response.status();
    let content_type = response
        .headers()
        .get_one("Content-Type")
        .unwrap_or("")
        .to_string();
    let response_body = response.into_json::<Value>().await.unwrap();

    assert_eq!(response_status, Status::Ok);
    assert!(content_type.starts_with("application/json"));
    assert_eq!(
        response_body["authorization_servers"],
        json!(["https://login.divine.video"])
    );
}

#[tokio::test]
#[serial]
async fn test_external_auth_server_access_token_is_accepted_for_existing_account() {
    configure_external_auth_server();

    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;

    let did = create_active_account(&client).await;
    let dpop_jwk = dpop_public_jwk_p256(TEST_DPOP_PROOF_P256_PRIVATE_KEY_HEX);
    let cnf_jkt = dpop_jwk_thumbprint(&dpop_jwk);

    let token = create_external_access_token(
        TEST_EXTERNAL_AUTH_ISSUER,
        "did:web:localhost",
        &did,
        Some(&cnf_jkt),
    );
    let initial_dpop = create_dpop_proof_p256(
        &token,
        "GET",
        "https://localhost/xrpc/com.atproto.server.getSession",
        TEST_DPOP_PROOF_P256_PRIVATE_KEY_HEX,
        None,
    );
    let nonce = issue_dpop_nonce(&client, &token, &initial_dpop).await;
    let dpop = create_dpop_proof_p256(
        &token,
        "GET",
        "https://localhost/xrpc/com.atproto.server.getSession",
        TEST_DPOP_PROOF_P256_PRIVATE_KEY_HEX,
        Some(&nonce),
    );

    let response = client
        .get("/xrpc/com.atproto.server.getSession")
        .header(Header::new("Authorization", format!("DPoP {token}")))
        .header(Header::new("DPoP", dpop))
        .dispatch()
        .await;
    let response_status = response.status();
    let response_nonce = response.headers().get_one("DPoP-Nonce").map(str::to_string);
    let response_body = response.into_json::<Value>().await.unwrap();

    assert_eq!(response_status, Status::Ok);
    assert_eq!(response_body["did"], json!(did));
    assert!(response_nonce.is_some());
}

#[tokio::test]
#[serial]
async fn test_external_auth_server_access_token_rejects_wrong_issuer() {
    configure_external_auth_server();

    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;

    let did = create_active_account(&client).await;

    let token =
        create_external_access_token("https://evil.example", "did:web:localhost", &did, None);

    let response = client
        .get("/xrpc/com.atproto.server.getSession")
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;
    let response_status = response.status();
    let response_body = response.into_json::<Value>().await.unwrap();

    assert_eq!(response_status, Status::BadRequest);
    assert!(response_body["message"]
        .as_str()
        .unwrap_or("")
        .contains("issuer"));
}

#[tokio::test]
#[serial]
async fn test_external_auth_server_access_token_rejects_wrong_audience() {
    configure_external_auth_server();

    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;

    let did = create_active_account(&client).await;

    let token =
        create_external_access_token(TEST_EXTERNAL_AUTH_ISSUER, "did:web:not-the-pds", &did, None);

    let response = client
        .get("/xrpc/com.atproto.server.getSession")
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .dispatch()
        .await;
    let response_status = response.status();
    let response_body = response.into_json::<Value>().await.unwrap();

    assert_eq!(response_status, Status::BadRequest);
    assert!(response_body["message"]
        .as_str()
        .unwrap_or("")
        .contains("aud"));
}

#[tokio::test]
#[serial]
async fn test_external_auth_server_access_token_rejects_unknown_account() {
    configure_external_auth_server();

    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;

    let dpop_jwk = dpop_public_jwk(TEST_DPOP_PROOF_PRIVATE_KEY_HEX);
    let cnf_jkt = dpop_jwk_thumbprint(&dpop_jwk);
    let token = create_external_access_token(
        TEST_EXTERNAL_AUTH_ISSUER,
        "did:web:localhost",
        "did:plc:missing-account",
        Some(&cnf_jkt),
    );
    let initial_dpop = create_dpop_proof(
        &token,
        "GET",
        "https://localhost/xrpc/com.atproto.server.getSession",
        TEST_DPOP_PROOF_PRIVATE_KEY_HEX,
        None,
    );
    let nonce = issue_dpop_nonce(&client, &token, &initial_dpop).await;
    let dpop = create_dpop_proof(
        &token,
        "GET",
        "https://localhost/xrpc/com.atproto.server.getSession",
        TEST_DPOP_PROOF_PRIVATE_KEY_HEX,
        Some(&nonce),
    );

    let response = client
        .get("/xrpc/com.atproto.server.getSession")
        .header(Header::new("Authorization", format!("DPoP {token}")))
        .header(Header::new("DPoP", dpop))
        .dispatch()
        .await;
    let response_status = response.status();
    let response_body = response.into_json::<Value>().await.unwrap();

    assert_eq!(response_status, Status::BadRequest);
    assert_eq!(response_body["error"], json!("AccountNotFound"));
}

#[tokio::test]
#[serial]
async fn test_external_auth_server_access_token_rejects_missing_dpop_proof() {
    configure_external_auth_server();

    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;
    let did = create_active_account(&client).await;

    let dpop_jwk = dpop_public_jwk(TEST_DPOP_PROOF_PRIVATE_KEY_HEX);
    let cnf_jkt = dpop_jwk_thumbprint(&dpop_jwk);
    let token = create_external_access_token(
        TEST_EXTERNAL_AUTH_ISSUER,
        "did:web:localhost",
        &did,
        Some(&cnf_jkt),
    );

    let response = client
        .get("/xrpc/com.atproto.server.getSession")
        .header(Header::new("Authorization", format!("DPoP {token}")))
        .dispatch()
        .await;
    let response_status = response.status();
    let response_nonce = response.headers().get_one("DPoP-Nonce").map(str::to_string);
    let response_body = response.into_json::<Value>().await.unwrap();

    assert_eq!(response_status, Status::BadRequest);
    assert!(response_body["message"]
        .as_str()
        .unwrap_or("")
        .contains("use_dpop_nonce"));
    assert!(response_nonce.is_some());
}

#[tokio::test]
#[serial]
async fn test_external_auth_server_access_token_rejects_wrong_dpop_key_binding() {
    configure_external_auth_server();

    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;
    let did = create_active_account(&client).await;

    let dpop_jwk = dpop_public_jwk(TEST_DPOP_PROOF_PRIVATE_KEY_HEX);
    let cnf_jkt = dpop_jwk_thumbprint(&dpop_jwk);
    let token = create_external_access_token(
        TEST_EXTERNAL_AUTH_ISSUER,
        "did:web:localhost",
        &did,
        Some(&cnf_jkt),
    );
    let initial_dpop = create_dpop_proof(
        &token,
        "GET",
        "https://localhost/xrpc/com.atproto.server.getSession",
        TEST_DPOP_PROOF_PRIVATE_KEY_HEX,
        None,
    );
    let nonce = issue_dpop_nonce(&client, &token, &initial_dpop).await;
    let dpop = create_dpop_proof(
        &token,
        "GET",
        "https://localhost/xrpc/com.atproto.server.getSession",
        TEST_DPOP_PROOF_PRIVATE_KEY_HEX_ALT,
        Some(&nonce),
    );

    let response = client
        .get("/xrpc/com.atproto.server.getSession")
        .header(Header::new("Authorization", format!("DPoP {token}")))
        .header(Header::new("DPoP", dpop))
        .dispatch()
        .await;
    let response_status = response.status();
    let response_body = response.into_json::<Value>().await.unwrap();

    assert_eq!(response_status, Status::BadRequest);
    assert!(response_body["message"]
        .as_str()
        .unwrap_or("")
        .contains("cnf.jkt"));
}

#[tokio::test]
#[serial]
async fn test_external_auth_server_access_token_rejects_dpop_ath_mismatch() {
    configure_external_auth_server();

    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;
    let did = create_active_account(&client).await;

    let dpop_jwk = dpop_public_jwk(TEST_DPOP_PROOF_PRIVATE_KEY_HEX);
    let cnf_jkt = dpop_jwk_thumbprint(&dpop_jwk);
    let token = create_external_access_token(
        TEST_EXTERNAL_AUTH_ISSUER,
        "did:web:localhost",
        &did,
        Some(&cnf_jkt),
    );
    let initial_dpop = create_dpop_proof(
        &token,
        "GET",
        "https://localhost/xrpc/com.atproto.server.getSession",
        TEST_DPOP_PROOF_PRIVATE_KEY_HEX,
        None,
    );
    let nonce = issue_dpop_nonce(&client, &token, &initial_dpop).await;
    let dpop = create_dpop_proof(
        "different-access-token",
        "GET",
        "https://localhost/xrpc/com.atproto.server.getSession",
        TEST_DPOP_PROOF_PRIVATE_KEY_HEX,
        Some(&nonce),
    );

    let response = client
        .get("/xrpc/com.atproto.server.getSession")
        .header(Header::new("Authorization", format!("DPoP {token}")))
        .header(Header::new("DPoP", dpop))
        .dispatch()
        .await;
    let response_status = response.status();
    let response_body = response.into_json::<Value>().await.unwrap();

    assert_eq!(response_status, Status::BadRequest);
    assert!(response_body["message"]
        .as_str()
        .unwrap_or("")
        .contains("ath"));
}

#[tokio::test]
#[serial]
async fn test_external_auth_server_access_token_rejects_dpop_htm_mismatch() {
    configure_external_auth_server();

    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;
    let did = create_active_account(&client).await;

    let dpop_jwk = dpop_public_jwk(TEST_DPOP_PROOF_PRIVATE_KEY_HEX);
    let cnf_jkt = dpop_jwk_thumbprint(&dpop_jwk);
    let token = create_external_access_token(
        TEST_EXTERNAL_AUTH_ISSUER,
        "did:web:localhost",
        &did,
        Some(&cnf_jkt),
    );
    let initial_dpop = create_dpop_proof(
        &token,
        "GET",
        "https://localhost/xrpc/com.atproto.server.getSession",
        TEST_DPOP_PROOF_PRIVATE_KEY_HEX,
        None,
    );
    let nonce = issue_dpop_nonce(&client, &token, &initial_dpop).await;
    let dpop = create_dpop_proof(
        &token,
        "POST",
        "https://localhost/xrpc/com.atproto.server.getSession",
        TEST_DPOP_PROOF_PRIVATE_KEY_HEX,
        Some(&nonce),
    );

    let response = client
        .get("/xrpc/com.atproto.server.getSession")
        .header(Header::new("Authorization", format!("DPoP {token}")))
        .header(Header::new("DPoP", dpop))
        .dispatch()
        .await;
    let response_status = response.status();
    let response_body = response.into_json::<Value>().await.unwrap();

    assert_eq!(response_status, Status::BadRequest);
    assert!(response_body["message"]
        .as_str()
        .unwrap_or("")
        .contains("htm"));
}

#[tokio::test]
async fn test_create_invite_code() {
    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;
    let input = json!({
        "useCount": 1
    });

    let response = client
        .post("/xrpc/com.atproto.server.createInviteCode")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", get_admin_token()))
        .body(input.to_string())
        .dispatch()
        .await;
    let response_status = response.status();

    assert_eq!(response_status, Status::Ok);
    response
        .into_json::<CreateInviteCodeOutput>()
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_invite_code_and_account() {
    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;
    let domain = client
        .rocket()
        .state::<ServerConfig>()
        .unwrap()
        .identity
        .service_handle_domains
        .first()
        .unwrap();

    let input = json!({
        "useCount": 1
    });

    let response = client
        .post("/xrpc/com.atproto.server.createInviteCode")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", get_admin_token()))
        .body(input.to_string())
        .dispatch()
        .await;
    let invite_code = response
        .into_json::<CreateInviteCodeOutput>()
        .await
        .unwrap()
        .code;

    let account_input = json!({
        "did": "did:plc:khvyd3oiw46vif5gm7hijslk",
        "email": "foo@example.com",
        "handle": format!("foo{domain}"),
        "password": "password",
        "inviteCode": invite_code
    });

    let response = client
        .post("/xrpc/com.atproto.server.createAccount")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", get_admin_token()))
        .body(account_input.to_string())
        .dispatch()
        .await;
    let response_status = response.status();
    assert_eq!(response_status, Status::Ok);
}

#[tokio::test]
async fn test_create_session() {
    let postgres = common::get_postgres().await;
    let client = common::get_client(&postgres).await;

    let (username, password) = create_account(&client).await;

    // Valid Login
    let session_input = json!({
        "identifier": username,
        "password": password,
    });

    let response = client
        .post("/xrpc/com.atproto.server.createSession")
        .header(ContentType::JSON)
        .body(session_input.to_string())
        .dispatch()
        .await;
    let response_status = response.status();
    assert_eq!(response_status, Status::Ok);

    // Invalid Login
    let session_input = json!({
        "identifier": username,
        "password": password + "1",
    });

    let response = client
        .post("/xrpc/com.atproto.server.createSession")
        .header(ContentType::JSON)
        .body(session_input.to_string())
        .dispatch()
        .await;
    let response_status = response.status();
    assert_eq!(response_status, Status::BadRequest);
}
