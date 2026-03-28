use crate::account_manager::helpers::account::{ActorAccount, AvailabilityFlags};
use crate::account_manager::helpers::auth::CustomClaimObj;
use crate::account_manager::AccountManager;
use crate::apis::ApiError;
use crate::config::ServerConfig;
use crate::xrpc_server::auth::{verify_jwt as verify_service_jwt_server, ServiceJwtPayload};
use crate::SharedIdResolver;
use anyhow::{bail, Result};
use base64::{
    engine::general_purpose::{STANDARD as base64pad, URL_SAFE_NO_PAD},
    Engine as _,
};
use jwt_simple::claims::Audiences;
use jwt_simple::prelude::*;
use lazy_static::lazy_static;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p256::EncodedPoint;
use rand::RngCore;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::State;
use rsky_common::env::env_str;
use rsky_common::get_verification_material;
use rsky_identity::did::atproto_data::get_did_key_from_multibase;
use rsky_identity::types::DidDocument;
use secp256k1::{ecdsa::Signature, Keypair, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::str;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;

const INFINITY: u64 = u64::MAX;
const DPOP_REPLAY_WINDOW_SECONDS: i64 = 300;
const DPOP_MAX_CLOCK_SKEW_SECONDS: i64 = 60;
const DPOP_NONCE_TTL_SECONDS: i64 = 300;

lazy_static! {
    static ref DPOP_REPLAY_CACHE: Mutex<HashMap<String, i64>> = Mutex::new(HashMap::new());
    static ref DPOP_NONCE_CACHE: Mutex<HashMap<String, (String, i64)>> = Mutex::new(HashMap::new());
}

#[derive(PartialEq, Clone, Debug)]
pub enum AuthScope {
    Access,
    Refresh,
    AppPass,
    AppPassPrivileged,
    SignupQueued,
}

impl AuthScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthScope::Access => "com.atproto.access",
            AuthScope::Refresh => "com.atproto.refresh",
            AuthScope::AppPass => "com.atproto.appPass",
            AuthScope::AppPassPrivileged => "com.atproto.appPassPrivileged",
            AuthScope::SignupQueued => "com.atproto.signupQueued",
        }
    }

    pub fn from_str(scope: &str) -> Result<Self> {
        match scope {
            "com.atproto.access" => Ok(AuthScope::Access),
            "com.atproto.refresh" => Ok(AuthScope::Refresh),
            "com.atproto.appPass" => Ok(AuthScope::AppPass),
            "com.atproto.appPassPrivileged" => Ok(AuthScope::AppPassPrivileged),
            "com.atproto.signupQueued" => Ok(AuthScope::SignupQueued),
            _ => bail!("Invalid AuthScope: `{scope:?}` is not a valid auth scope"),
        }
    }
}

pub enum RoleStatus {
    Valid,
    Invalid,
    Missing,
}

#[derive(Clone)]
pub struct Credentials {
    pub r#type: String,
    pub did: Option<String>,
    pub scope: Option<AuthScope>,
    pub audience: Option<String>,
    pub token_id: Option<String>,
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub is_privileged: Option<bool>,
}

#[derive(Clone)]
pub struct AccessOutput {
    pub credentials: Option<Credentials>,
    pub artifacts: Option<String>,
}

pub struct ValidatedBearer {
    pub did: String,
    pub scope: AuthScope,
    pub token: String,
    pub payload: JwtPayload,
    pub audience: Option<String>,
}

pub struct AuthVerifierDids {
    pub pds: String,
    pub entryway: Option<String>,
    pub mod_service: Option<String>,
}

pub struct ServiceJwtOpts {
    pub aud: Option<String>,
    pub iss: Option<Vec<String>>,
}

pub struct ValidateAccessTokenOpts {
    pub check_takedown: Option<bool>,
    pub check_deactivated: Option<bool>,
}

pub struct VerifiedServiceJwt {
    pub aud: String,
    pub iss: String,
}

pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Clone)]
pub struct JwtPayload {
    pub scope: AuthScope,
    pub sub: Option<String>,
    pub iss: Option<String>,
    pub aud: Option<Audiences>,
    pub exp: Option<Duration>,
    pub iat: Option<Duration>,
    pub jti: Option<String>,
    pub cnf_jkt: Option<String>,
    pub external_issuer: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthorizationScheme {
    Bearer,
    Dpop,
}

enum DpopProofKey {
    Secp256k1(secp256k1::PublicKey),
    P256(P256VerifyingKey),
}

#[derive(Debug, Deserialize, Serialize)]
struct AccessTokenConfirmationClaim {
    #[serde(default)]
    jkt: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExternalAccessTokenClaims {
    #[serde(default)]
    scope: String,
    #[serde(default)]
    lxm: Option<String>,
    #[serde(default)]
    cnf: Option<AccessTokenConfirmationClaim>,
}

#[derive(Debug, Deserialize)]
struct DpopJwkHeader {
    #[serde(default)]
    typ: Option<String>,
    alg: String,
    jwk: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct DpopProofClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    #[serde(default)]
    ath: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("BadJwt: `{0}`")]
    BadJwt(String),
    #[error("BadJwtAudience: `{0}`")]
    BadJwtAudience(String),
    #[error("UntrustedIss: `{0}`")]
    UntrustedIss(String),
    #[error("AuthRequired: `{0}`")]
    AuthRequired(String),
    #[error("AccountNotFound: `{0}`")]
    AccountNotFound(String),
    #[error("AccountTakedown: `{0}`")]
    AccountTakedown(String),
    #[error("AccountDeactivated: `{0}`")]
    AccountDeactivated(String),
    #[error("InternalServerError: `{0}`")]
    InternalServerError(String),
}

// verifier guards

pub struct Refresh {
    pub access: AccessOutput,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Refresh {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let mut options = VerificationOptions::default();
        options.allowed_audiences = Some(HashSet::from_strings(&[
            env::var("PDS_SERVICE_DID").unwrap()
        ]));
        let ValidatedBearer {
            did,
            scope,
            token,
            payload,
            audience,
        } = match validate_bearer_token(req, vec![AuthScope::Refresh], Some(options)).await {
            Ok(result) => {
                let payload = result.payload.clone();
                match payload.jti {
                    Some(_) => result,
                    None => {
                        let error =
                            AuthError::BadJwt("Unexpected missing refresh token id".to_owned());
                        req.local_cache(|| Some(ApiError::InvalidRequest(error.to_string())));
                        return Outcome::Error((Status::BadRequest, error));
                    }
                }
            }
            Err(error) => {
                let error = AuthError::BadJwt(error.to_string());
                req.local_cache(|| Some(ApiError::InvalidRequest(error.to_string())));
                return Outcome::Error((Status::BadRequest, error));
            }
        };
        Outcome::Success(Refresh {
            access: AccessOutput {
                credentials: Some(Credentials {
                    r#type: "refresh".to_string(),
                    did: Some(did),
                    scope: Some(scope),
                    audience,
                    token_id: payload.jti,
                    aud: None,
                    iss: None,
                    is_privileged: None,
                }),
                artifacts: Some(token),
            },
        })
    }
}

pub async fn access_check<'r>(
    req: &'r Request<'_>,
    scopes: Vec<AuthScope>,
    opts: Option<ValidateAccessTokenOpts>,
) -> Outcome<AccessOutput, AuthError> {
    match validate_access_token(req, scopes, opts).await {
        Ok(access) => Outcome::Success(access),
        Err(error) => match error.downcast_ref() {
            Some(AuthError::AccountDeactivated(error)) => Outcome::Error((
                Status::BadRequest,
                AuthError::AccountDeactivated(error.to_string()),
            )),
            Some(AuthError::AccountNotFound(error)) => Outcome::Error((
                Status::BadRequest,
                AuthError::AccountNotFound(error.to_string()),
            )),
            Some(AuthError::AccountTakedown(error)) => Outcome::Error((
                Status::BadRequest,
                AuthError::AccountTakedown(error.to_string()),
            )),
            _ => Outcome::Error((Status::BadRequest, AuthError::BadJwt(error.to_string()))),
        },
    }
}

pub struct AccessFullImport {
    pub access: AccessOutput,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AccessFullImport {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let opts = ValidateAccessTokenOpts {
            check_takedown: Some(true),
            check_deactivated: Some(false),
        };
        match access_check(req, vec![AuthScope::Access], Some(opts)).await {
            Outcome::Success(access) => Outcome::Success(AccessFullImport { access }),
            Outcome::Error(error) => Outcome::Error(error),
            Outcome::Forward(_) => panic!("Outcome::Forward returned"),
        }
    }
}

pub struct AccessFull {
    pub access: AccessOutput,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AccessFull {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match access_check(req, vec![AuthScope::Access], None).await {
            Outcome::Success(access) => Outcome::Success(AccessFull { access }),
            Outcome::Error(error) => {
                req.local_cache(|| Some(ApiError::InvalidRequest(error.1.to_string())));
                Outcome::Error(error)
            }
            Outcome::Forward(_) => panic!("Outcome::Forward returned"),
        }
    }
}

pub struct AccessPrivileged {
    pub access: AccessOutput,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AccessPrivileged {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match access_check(
            req,
            vec![AuthScope::Access, AuthScope::AppPassPrivileged],
            None,
        )
        .await
        {
            Outcome::Success(access) => Outcome::Success(Self { access }),
            Outcome::Error(error) => {
                req.local_cache(|| Some(ApiError::InvalidRequest(error.1.to_string())));
                Outcome::Error(error)
            }
            Outcome::Forward(_) => panic!("Outcome::Forward returned"),
        }
    }
}

pub struct AccessStandard {
    pub access: AccessOutput,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AccessStandard {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match access_check(
            req,
            vec![
                AuthScope::Access,
                AuthScope::AppPass,
                AuthScope::AppPassPrivileged,
            ],
            None,
        )
        .await
        {
            Outcome::Success(access) => Outcome::Success(AccessStandard { access }),
            Outcome::Error(error) => {
                req.local_cache(|| Some(ApiError::InvalidRequest(error.1.to_string())));
                Outcome::Error(error)
            }
            Outcome::Forward(_) => panic!("Outcome::Forward returned"),
        }
    }
}

#[derive(Clone)]
pub struct AccessStandardIncludeChecks {
    pub access: AccessOutput,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AccessStandardIncludeChecks {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match access_check(
            req,
            vec![
                AuthScope::Access,
                AuthScope::AppPass,
                AuthScope::AppPassPrivileged,
            ],
            Some(ValidateAccessTokenOpts {
                check_deactivated: Some(true),
                check_takedown: Some(true),
            }),
        )
        .await
        {
            Outcome::Success(access) => Outcome::Success(AccessStandardIncludeChecks { access }),
            Outcome::Error(error) => {
                req.local_cache(|| Some(ApiError::InvalidRequest(error.1.to_string())));
                Outcome::Error(error)
            }
            Outcome::Forward(_) => panic!("Outcome::Forward returned"),
        }
    }
}

#[derive(Clone)]
pub struct AccessStandardCheckTakedown {
    pub access: AccessOutput,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AccessStandardCheckTakedown {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match access_check(
            req,
            vec![
                AuthScope::Access,
                AuthScope::AppPass,
                AuthScope::AppPassPrivileged,
            ],
            Some(ValidateAccessTokenOpts {
                check_deactivated: None,
                check_takedown: Some(true),
            }),
        )
        .await
        {
            Outcome::Success(access) => Outcome::Success(AccessStandardCheckTakedown { access }),
            Outcome::Error(error) => {
                req.local_cache(|| Some(ApiError::InvalidRequest(error.1.to_string())));
                Outcome::Error(error)
            }
            Outcome::Forward(_) => panic!("Outcome::Forward returned"),
        }
    }
}

pub struct AccessStandardSignupQueued {
    pub access: AccessOutput,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AccessStandardSignupQueued {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match access_check(
            req,
            vec![
                AuthScope::Access,
                AuthScope::AppPass,
                AuthScope::AppPassPrivileged,
                AuthScope::SignupQueued,
            ],
            None,
        )
        .await
        {
            Outcome::Success(access) => Outcome::Success(AccessStandardSignupQueued { access }),
            Outcome::Error(error) => {
                req.local_cache(|| Some(ApiError::InvalidRequest(error.1.to_string())));
                Outcome::Error(error)
            }
            Outcome::Forward(_) => panic!("Outcome::Forward returned"),
        }
    }
}

pub struct RevokeRefreshToken {
    pub id: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RevokeRefreshToken {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let mut options = VerificationOptions::default();
        options.max_validity = Some(Duration::from_secs(INFINITY));
        match validate_bearer_token(req, vec![AuthScope::Refresh], Some(options)).await {
            Ok(result) => match result.payload.jti {
                Some(jti) => Outcome::Success(RevokeRefreshToken { id: jti }),
                None => {
                    let error = AuthError::BadJwt("Unexpected missing refresh token id".to_owned());
                    req.local_cache(|| Some(ApiError::InvalidRequest(error.to_string())));
                    Outcome::Error((Status::BadRequest, error))
                }
            },
            Err(error) => {
                req.local_cache(|| Some(ApiError::InvalidRequest(error.to_string())));
                Outcome::Error((Status::BadRequest, AuthError::BadJwt(error.to_string())))
            }
        }
    }
}

pub struct UserDidAuth {
    pub access: AccessOutput,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for UserDidAuth {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let id_resolver = req.guard::<&State<SharedIdResolver>>().await.unwrap();
        match verify_service_jwt(
            req,
            id_resolver,
            ServiceJwtOpts {
                aud: Some(env::var("PDS_SERVICE_DID").unwrap()),
                iss: None,
            },
        )
        .await
        {
            Ok(payload) => Outcome::Success(UserDidAuth {
                access: AccessOutput {
                    credentials: Some(Credentials {
                        r#type: "user_did".to_string(),
                        did: None,
                        scope: None,
                        audience: None,
                        token_id: None,
                        aud: Some(payload.aud),
                        iss: Some(payload.iss),
                        is_privileged: None,
                    }),
                    artifacts: None,
                },
            }),
            Err(error) => {
                req.local_cache(|| {
                    Some(ApiError::InvalidRequest(
                        AuthError::BadJwt(error.to_string()).to_string(),
                    ))
                });
                Outcome::Error((Status::BadRequest, AuthError::BadJwt(error.to_string())))
            }
        }
    }
}

pub struct UserDidAuthOptional {
    pub access: Option<AccessOutput>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for UserDidAuthOptional {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if is_bearer_token(req) {
            match UserDidAuth::from_request(req).await {
                Outcome::Success(output) => Outcome::Success(UserDidAuthOptional {
                    access: Some(output.access),
                }),
                Outcome::Error(err) => {
                    req.local_cache(|| Some(ApiError::InvalidRequest(err.1.to_string())));
                    Outcome::Error(err)
                }
                _ => panic!("Unexpected outcome during UserDidAuthOptional"),
            }
        } else {
            Outcome::Success(UserDidAuthOptional { access: None })
        }
    }
}

pub struct ModService {
    pub access: AccessOutput,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ModService {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Some(mod_service_did) = env_str("PDS_MOD_SERVICE_DID") {
            let id_resolver = req.guard::<&State<SharedIdResolver>>().await.unwrap();
            match verify_service_jwt(
                req,
                id_resolver,
                ServiceJwtOpts {
                    aud: None,
                    iss: Some(vec![
                        mod_service_did.clone(),
                        format!("{mod_service_did}#atproto_labeler"),
                    ]),
                },
            )
            .await
            {
                Ok(payload)
                    if Some(payload.aud.clone()) != env_str("PDS_SERVICE_DID")
                        && (env_str("PDS_ENTRYWAY_DID").is_none()
                            || Some(payload.aud.clone()) != env_str("PDS_ENTRYWAY_DID")) =>
                {
                    let error = AuthError::BadJwtAudience(
                        "jwt audience does not match service did".to_string(),
                    );
                    req.local_cache(|| Some(ApiError::InvalidRequest(error.to_string())));
                    Outcome::Error((Status::BadRequest, error))
                }
                Ok(payload) => Outcome::Success(ModService {
                    access: AccessOutput {
                        credentials: Some(Credentials {
                            r#type: "mod_service".to_string(),
                            did: None,
                            scope: None,
                            audience: None,
                            token_id: None,
                            aud: Some(payload.aud),
                            iss: Some(payload.iss),
                            is_privileged: None,
                        }),
                        artifacts: None,
                    },
                }),
                Err(error) => {
                    let error = AuthError::BadJwt(error.to_string());
                    req.local_cache(|| Some(ApiError::InvalidRequest(error.to_string())));
                    Outcome::Error((Status::BadRequest, AuthError::BadJwt(error.to_string())))
                }
            }
        } else {
            let error = AuthError::UntrustedIss("Untrusted issuer".to_string());
            req.local_cache(|| Some(ApiError::InvalidRequest(error.to_string())));
            Outcome::Error((Status::BadRequest, error))
        }
    }
}

pub struct Moderator {
    pub access: AccessOutput,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Moderator {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if is_bearer_token(req) {
            match ModService::from_request(req).await {
                Outcome::Success(output) => Outcome::Success(Moderator {
                    access: output.access,
                }),
                Outcome::Error(err) => {
                    req.local_cache(|| Some(ApiError::InvalidRequest(err.1.to_string())));
                    Outcome::Error(err)
                }
                _ => panic!("Unexpected outcome during Moderator"),
            }
        } else {
            match AdminToken::from_request(req).await {
                Outcome::Success(output) => Outcome::Success(Moderator {
                    access: output.access,
                }),
                Outcome::Error(err) => {
                    req.local_cache(|| Some(ApiError::InvalidRequest(err.1.to_string())));
                    Outcome::Error(err)
                }
                _ => panic!("Unexpected outcome during Moderator"),
            }
        }
    }
}

pub struct AdminToken {
    pub access: AccessOutput,
}

fn admin_password_from_env() -> Option<String> {
    env::var("PDS_ADMIN_PASSWORD")
        .ok()
        .or_else(|| env::var("PDS_ADMIN_PASS").ok())
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminToken {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth_header: &str = req.headers().get_one("Authorization").unwrap_or("");
        match parse_basic_auth(auth_header) {
            None => Outcome::Error((
                Status::BadRequest,
                AuthError::AuthRequired("AuthMissing".to_string()),
            )),
            Some(parsed) => {
                let BasicAuth { username, password } = parsed;
                let expected_password = match admin_password_from_env() {
                    Some(password) => password,
                    None => {
                        let error = AuthError::AuthRequired("BadAuth".to_string());
                        req.local_cache(|| Some(ApiError::InvalidRequest(error.to_string())));
                        return Outcome::Error((Status::BadRequest, error));
                    }
                };

                if username != "admin" || password != expected_password {
                    let error = AuthError::AuthRequired("BadAuth".to_string());
                    req.local_cache(|| Some(ApiError::InvalidRequest(error.to_string())));
                    Outcome::Error((Status::BadRequest, error))
                } else {
                    Outcome::Success(AdminToken {
                        access: AccessOutput {
                            credentials: Some(Credentials {
                                r#type: "admin_token".to_string(),
                                did: None,
                                scope: None,
                                audience: None,
                                token_id: None,
                                aud: None,
                                iss: None,
                                is_privileged: None,
                            }),
                            artifacts: None,
                        },
                    })
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct OptionalAccessOrAdminToken {
    pub access: Option<AccessOutput>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OptionalAccessOrAdminToken {
    type Error = AuthError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if is_bearer_token(req) {
            match AccessFull::from_request(req).await {
                Outcome::Success(output) => Outcome::Success(OptionalAccessOrAdminToken {
                    access: Some(output.access),
                }),
                Outcome::Error(err) => {
                    req.local_cache(|| Some(ApiError::InvalidRequest(err.1.to_string())));
                    Outcome::Error(err)
                }
                _ => panic!("Unexpected outcome during OptionalAccessOrAdminToken"),
            }
        } else if is_basic_token(req) {
            match AdminToken::from_request(req).await {
                Outcome::Success(output) => Outcome::Success(OptionalAccessOrAdminToken {
                    access: Some(output.access),
                }),
                Outcome::Error(err) => {
                    req.local_cache(|| Some(ApiError::InvalidRequest(err.1.to_string())));
                    Outcome::Error(err)
                }
                _ => panic!("Unexpected outcome during OptionalAccessOrAdminToken"),
            }
        } else {
            Outcome::Success(OptionalAccessOrAdminToken { access: None })
        }
    }
}

pub async fn validate_bearer_access_token<'r>(
    request: &'r Request<'_>,
    scopes: Vec<AuthScope>,
) -> Result<AccessOutput> {
    let mut options = VerificationOptions::default();
    options.allowed_audiences = Some(HashSet::from_strings(&[
        env::var("PDS_SERVICE_DID").unwrap()
    ]));
    let ValidatedBearer {
        did,
        scope,
        token,
        audience,
        ..
    } = validate_bearer_token(request, scopes, Some(options)).await?;
    let is_privileged = vec![AuthScope::Access, AuthScope::AppPassPrivileged].contains(&scope);
    Ok(AccessOutput {
        credentials: Some(Credentials {
            r#type: "access".to_string(),
            did: Some(did),
            scope: Some(scope),
            audience,
            token_id: None,
            aud: None,
            iss: None,
            is_privileged: Some(is_privileged),
        }),
        artifacts: Some(token),
    })
}

pub async fn validate_bearer_token<'r>(
    request: &'r Request<'_>,
    scopes: Vec<AuthScope>,
    verify_options: Option<VerificationOptions>,
) -> Result<ValidatedBearer> {
    let token = bearer_token_from_req(request)?.ok_or_else(|| anyhow::anyhow!("AuthMissing"))?;
    validate_token_string(request, token, scopes, verify_options).await
}

pub async fn validate_access_token<'r>(
    request: &'r Request<'_>,
    scopes: Vec<AuthScope>,
    opts: Option<ValidateAccessTokenOpts>,
) -> Result<AccessOutput> {
    let (auth_scheme, token) =
        authorization_token_from_req(request)?.ok_or_else(|| anyhow::anyhow!("AuthMissing"))?;

    let mut options = VerificationOptions::default();
    options.allowed_audiences = Some(HashSet::from_strings(&[
        env::var("PDS_SERVICE_DID").unwrap()
    ]));
    let ValidatedBearer {
        did,
        scope,
        token: validated_token,
        audience,
        payload,
    } = validate_token_string(request, token, scopes, Some(options)).await?;

    if payload.external_issuer {
        if auth_scheme != AuthorizationScheme::Dpop {
            bail!("AuthRequired: external access tokens require Authorization: DPoP");
        }
        let expected_jkt = payload
            .cnf_jkt
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("BadJwt: externally issued token missing cnf.jkt"))?;
        let dpop_proof = match request.headers().get_one("DPoP") {
            Some(proof) => proof,
            None => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| anyhow::anyhow!("InternalServerError: invalid system clock"))?
                    .as_secs() as i64;
                let nonce_key = dpop_nonce_cache_key(&validated_token);
                issue_dpop_nonce(request, &nonce_key, now)?;
                bail!("AuthRequired: use_dpop_nonce");
            }
        };
        verify_dpop_proof(request, dpop_proof, &validated_token, expected_jkt)?;
    }

    let ValidateAccessTokenOpts {
        check_takedown,
        check_deactivated,
    } = opts.unwrap_or_else(|| ValidateAccessTokenOpts {
        check_takedown: Some(false),
        check_deactivated: Some(false),
    });
    let check_takedown = check_takedown.unwrap_or(false);
    let check_deactivated = check_deactivated.unwrap_or(false);

    let account_manager = match request
        .guard::<AccountManager>()
        .await
        .map(|account_manager| account_manager)
    {
        Outcome::Success(account_manager) => account_manager,
        Outcome::Error(_) => {
            return Err(anyhow::Error::new(AuthError::InternalServerError(
                "Unexpected Error Occurred".to_string(),
            )))
        }
        Outcome::Forward(_) => {
            return Err(anyhow::Error::new(AuthError::InternalServerError(
                "Unexpected Error Occurred".to_string(),
            )))
        }
    };
    if check_takedown || check_deactivated {
        let found: ActorAccount = match account_manager
            .get_account(
                &did,
                Some(AvailabilityFlags {
                    include_deactivated: Some(true),
                    include_taken_down: Some(true),
                }),
            )
            .await
        {
            Ok(Some(found)) => found,
            _ => {
                return Err(anyhow::Error::new(AuthError::AccountNotFound(
                    "Account not found".to_string(),
                )))
            }
        };
        if check_takedown && found.takedown_ref.is_some() {
            return Err(anyhow::Error::new(AuthError::AccountTakedown(
                "Account has been taken down".to_string(),
            )));
        }
        if check_deactivated && found.deactivated_at.is_some() {
            return Err(anyhow::Error::new(AuthError::AccountDeactivated(
                "Account is deactivated".to_string(),
            )));
        }
    }
    Ok(AccessOutput {
        credentials: Some(Credentials {
            r#type: "access".to_string(),
            did: Some(did),
            scope: Some(scope),
            audience,
            token_id: None,
            aud: None,
            iss: None,
            is_privileged: None,
        }),
        artifacts: Some(validated_token),
    })
}

async fn validate_token_string<'r>(
    request: &'r Request<'_>,
    token: String,
    scopes: Vec<AuthScope>,
    verify_options: Option<VerificationOptions>,
) -> Result<ValidatedBearer> {
    let secp = Secp256k1::new();
    // Try JWT key first (for session tokens)
    let jwt_private_key = env::var("PDS_JWT_KEY_K256_PRIVATE_KEY_HEX").unwrap();
    let jwt_secret_key =
        SecretKey::from_slice(&hex::decode(jwt_private_key.as_bytes()).unwrap()).unwrap();
    let jwt_key = Keypair::from_secret_key(&secp, &jwt_secret_key);
    let cfg = request.guard::<&State<ServerConfig>>().await.unwrap();
    let payload = match verify_jwt(token.clone(), jwt_key, verify_options.clone()).await {
        Ok(payload) => payload,
        Err(jwt_err) => {
            // Fall back to repo signing key (for service auth tokens
            // that come back from external services like video.bsky.app)
            let repo_key_hex =
                env::var("PDS_REPO_SIGNING_KEY_K256_PRIVATE_KEY_HEX").unwrap_or_default();
            let repo_result = if repo_key_hex.is_empty() {
                Err(jwt_err)
            } else {
                let repo_secret_key =
                    SecretKey::from_slice(&hex::decode(repo_key_hex.as_bytes()).unwrap()).unwrap();
                let repo_key = Keypair::from_secret_key(&secp, &repo_secret_key);
                verify_jwt(token.clone(), repo_key, verify_options.clone()).await
            };

            match repo_result {
                Ok(payload) => payload,
                Err(repo_err) => {
                    match verify_external_entryway_jwt(token.clone(), cfg, verify_options.clone())
                        .await
                    {
                        Ok(payload) => payload,
                        Err(entryway_err)
                            if entryway_err
                                .to_string()
                                .contains("Signature tag didn't verify") =>
                        {
                            return Err(repo_err);
                        }
                        Err(entryway_err) => return Err(entryway_err),
                    }
                }
            }
        }
    };
    let JwtPayload {
        sub, aud, scope, ..
    } = payload.clone();
    // Service auth tokens use 'iss' (mapped to 'sub' by jwt_simple) but may also
    // have it only in the issuer field. Fall back to empty if not present.
    let sub = match sub {
        Some(s) => s,
        None => bail!("BadJwt: missing sub/iss in token"),
    };
    let aud = match aud {
        Some(a) => a,
        None => bail!("BadJwt: missing aud in token"),
    };
    if !sub.starts_with("did:") {
        bail!("Malformed token")
    }
    if let Audiences::AsString(aud) = aud {
        if !aud.starts_with("did:") {
            bail!("Malformed token")
        }
        if !scopes.is_empty() && !scopes.contains(&scope) {
            bail!("Bad token scope")
        }
        Ok(ValidatedBearer {
            did: sub,
            scope,
            audience: Some(aud),
            token,
            payload,
        })
    } else {
        bail!("Malformed token")
    }
}

fn verify_dpop_proof(
    request: &Request<'_>,
    dpop_proof: &str,
    access_token: &str,
    expected_jkt: &str,
) -> Result<()> {
    let parts: Vec<&str> = dpop_proof.split('.').collect();
    if parts.len() != 3 {
        bail!("BadJwt: malformed DPoP proof");
    }

    let header: DpopJwkHeader = decode_base64url_json(parts[0])?;
    let alg = header.alg.to_ascii_uppercase();
    if alg != "ES256" && alg != "ES256K" {
        bail!("BadJwt: unsupported DPoP alg");
    }
    if let Some(typ) = header.typ.as_deref() {
        if typ.to_ascii_lowercase() != "dpop+jwt" {
            bail!("BadJwt: invalid DPoP typ");
        }
    }

    let (proof_key, computed_jkt) = parse_jwk_and_thumbprint(&header.jwk)?;
    if computed_jkt != expected_jkt {
        bail!("BadJwt: DPoP key does not match access token cnf.jkt");
    }

    verify_compact_jws(parts[0], parts[1], parts[2], &alg, &proof_key)?;

    let claims: DpopProofClaims = decode_base64url_json(parts[1])?;
    if claims.htm.to_uppercase() != request.method().as_str().to_uppercase() {
        bail!("BadJwt: DPoP htm mismatch");
    }
    validate_htu(request, &claims.htu)?;

    let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
    let actual_ath = claims
        .ath
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("BadJwt: missing DPoP ath"))?;
    if actual_ath != expected_ath {
        bail!("BadJwt: DPoP ath mismatch");
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("InternalServerError: invalid system clock"))?
        .as_secs() as i64;
    if claims.iat > now + DPOP_MAX_CLOCK_SKEW_SECONDS {
        bail!("BadJwt: DPoP iat is in the future");
    }
    if now - claims.iat > DPOP_REPLAY_WINDOW_SECONDS {
        bail!("BadJwt: DPoP iat is outside replay window");
    }

    let nonce_cache_key = dpop_nonce_cache_key(access_token);
    let expected_nonce = current_dpop_nonce(&nonce_cache_key, now)?;
    if expected_nonce.is_none() {
        issue_dpop_nonce(request, &nonce_cache_key, now)?;
        bail!("AuthRequired: use_dpop_nonce");
    }
    let expected_nonce = expected_nonce.unwrap();
    let proof_nonce = claims
        .nonce
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("AuthRequired: use_dpop_nonce"))?;
    if proof_nonce != expected_nonce {
        issue_dpop_nonce(request, &nonce_cache_key, now)?;
        bail!("AuthRequired: use_dpop_nonce");
    }

    let mut replay_cache = DPOP_REPLAY_CACHE
        .lock()
        .map_err(|_| anyhow::anyhow!("InternalServerError: DPoP replay cache lock poisoned"))?;
    replay_cache.retain(|_, ts| now - *ts <= DPOP_REPLAY_WINDOW_SECONDS);
    if replay_cache.contains_key(&claims.jti) {
        bail!("BadJwt: replayed DPoP proof");
    }
    replay_cache.insert(claims.jti, now);

    // Rotate nonce for next request and return it in response headers.
    issue_dpop_nonce(request, &nonce_cache_key, now)?;

    Ok(())
}

fn decode_base64url_json<T: for<'de> Deserialize<'de>>(value: &str) -> Result<T> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| anyhow::anyhow!("BadJwt: malformed base64url segment"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn parse_jwk_and_thumbprint(jwk: &serde_json::Value) -> Result<(DpopProofKey, String)> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("BadJwt: DPoP jwk missing kty"))?;
    let crv = jwk
        .get("crv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("BadJwt: DPoP jwk missing crv"))?;
    let x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("BadJwt: DPoP jwk missing x"))?;
    let y = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("BadJwt: DPoP jwk missing y"))?;

    if kty != "EC" {
        bail!("BadJwt: unsupported DPoP jwk kty");
    }

    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| anyhow::anyhow!("BadJwt: invalid DPoP jwk x"))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|_| anyhow::anyhow!("BadJwt: invalid DPoP jwk y"))?;
    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        bail!("BadJwt: invalid DPoP jwk coordinate length");
    }

    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x_bytes);
    uncompressed.extend_from_slice(&y_bytes);

    // RFC 7638 key thumbprint canonical order.
    let canonical = format!("{{\"crv\":\"{crv}\",\"kty\":\"{kty}\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
    let digest = Sha256::digest(canonical.as_bytes());
    let jkt = URL_SAFE_NO_PAD.encode(digest);

    let proof_key = match crv {
        "secp256k1" => DpopProofKey::Secp256k1(
            secp256k1::PublicKey::from_slice(&uncompressed)
                .map_err(|_| anyhow::anyhow!("BadJwt: invalid secp256k1 DPoP key"))?,
        ),
        "P-256" => {
            let point = EncodedPoint::from_affine_coordinates(
                p256::FieldBytes::from_slice(&x_bytes),
                p256::FieldBytes::from_slice(&y_bytes),
                false,
            );
            let verifying_key = P256VerifyingKey::from_encoded_point(&point)
                .map_err(|_| anyhow::anyhow!("BadJwt: invalid P-256 DPoP key"))?;
            DpopProofKey::P256(verifying_key)
        }
        _ => bail!("BadJwt: unsupported DPoP jwk curve"),
    };

    Ok((proof_key, jkt))
}

fn verify_compact_jws(
    header_b64: &str,
    payload_b64: &str,
    signature_b64: &str,
    alg: &str,
    proof_key: &DpopProofKey,
) -> Result<()> {
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| anyhow::anyhow!("BadJwt: malformed DPoP signature"))?;
    if signature_bytes.len() != 64 {
        bail!("BadJwt: invalid DPoP signature length");
    }
    let signing_input = format!("{header_b64}.{payload_b64}");
    let digest = Sha256::digest(signing_input.as_bytes());

    match (alg.to_ascii_uppercase().as_str(), proof_key) {
        ("ES256K", DpopProofKey::Secp256k1(public_key)) => {
            let signature = Signature::from_compact(&signature_bytes)
                .map_err(|_| anyhow::anyhow!("BadJwt: invalid DPoP signature format"))?;
            let message = Message::from_digest_slice(digest.as_ref())
                .map_err(|_| anyhow::anyhow!("BadJwt: invalid DPoP signing input"))?;
            Secp256k1::verification_only()
                .verify_ecdsa(&message, &signature, public_key)
                .map_err(|_| anyhow::anyhow!("BadJwt: DPoP signature verification failed"))?;
        }
        ("ES256", DpopProofKey::P256(public_key)) => {
            let signature = P256Signature::from_slice(&signature_bytes)
                .map_err(|_| anyhow::anyhow!("BadJwt: invalid DPoP ES256 signature format"))?;
            public_key
                .verify_prehash(digest.as_slice(), &signature)
                .map_err(|_| anyhow::anyhow!("BadJwt: DPoP signature verification failed"))?;
        }
        ("ES256", _) => bail!("BadJwt: ES256 requires P-256 DPoP key"),
        ("ES256K", _) => bail!("BadJwt: ES256K requires secp256k1 DPoP key"),
        _ => bail!("BadJwt: unsupported DPoP alg"),
    }

    Ok(())
}

fn request_relative_uri(request: &Request<'_>) -> String {
    let mut uri = request.uri().path().to_string();
    if let Some(query) = request.uri().query() {
        uri.push('?');
        uri.push_str(query.as_str());
    }
    uri
}

fn validate_htu(request: &Request<'_>, htu: &str) -> Result<()> {
    let parsed = Url::parse(htu).map_err(|_| anyhow::anyhow!("BadJwt: invalid DPoP htu"))?;

    let expected_scheme = request
        .headers()
        .get_one("X-Forwarded-Proto")
        .unwrap_or("https");
    if parsed.scheme() != expected_scheme {
        bail!("BadJwt: DPoP htu scheme mismatch");
    }

    if let Some(host) = request.headers().get_one("Host") {
        let parsed_host = match parsed.port() {
            Some(port) => format!("{}:{port}", parsed.host_str().unwrap_or_default()),
            None => parsed.host_str().unwrap_or_default().to_string(),
        };
        if !same_host(&parsed_host, host, parsed.scheme()) {
            bail!("BadJwt: DPoP htu host mismatch");
        }
    }

    let mut parsed_relative = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        parsed_relative.push('?');
        parsed_relative.push_str(query);
    }
    if parsed_relative != request_relative_uri(request) {
        bail!("BadJwt: DPoP htu path mismatch");
    }
    Ok(())
}

fn same_host(provided: &str, expected: &str, scheme: &str) -> bool {
    let normalize = |host: &str| {
        if (scheme == "https" && host.ends_with(":443"))
            || (scheme == "http" && host.ends_with(":80"))
        {
            host.rsplit_once(':')
                .map(|(h, _)| h.to_string())
                .unwrap_or_else(|| host.to_string())
        } else {
            host.to_string()
        }
    };
    normalize(provided).eq_ignore_ascii_case(&normalize(expected))
}

fn dpop_nonce_cache_key(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

fn issue_dpop_nonce(request: &Request<'_>, nonce_key: &str, now: i64) -> Result<String> {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let nonce = URL_SAFE_NO_PAD.encode(bytes);
    let mut nonce_cache = DPOP_NONCE_CACHE
        .lock()
        .map_err(|_| anyhow::anyhow!("InternalServerError: DPoP nonce cache lock poisoned"))?;
    nonce_cache.retain(|_, (_, ts)| now - *ts <= DPOP_NONCE_TTL_SECONDS);
    nonce_cache.insert(nonce_key.to_string(), (nonce.clone(), now));
    set_dpop_nonce_for_response(request, nonce.clone());
    Ok(nonce)
}

fn current_dpop_nonce(nonce_key: &str, now: i64) -> Result<Option<String>> {
    let mut nonce_cache = DPOP_NONCE_CACHE
        .lock()
        .map_err(|_| anyhow::anyhow!("InternalServerError: DPoP nonce cache lock poisoned"))?;
    nonce_cache.retain(|_, (_, ts)| now - *ts <= DPOP_NONCE_TTL_SECONDS);
    Ok(nonce_cache.get(nonce_key).map(|(nonce, _)| nonce.clone()))
}

fn set_dpop_nonce_for_response(request: &Request<'_>, nonce: String) {
    let cache = request.local_cache(|| Mutex::new(None::<String>));
    if let Ok(mut guard) = cache.lock() {
        *guard = Some(nonce);
    }
}

pub fn response_dpop_nonce(request: &Request<'_>) -> Option<String> {
    let cache = request.local_cache(|| Mutex::new(None::<String>));
    cache.lock().ok().and_then(|guard| (*guard).clone())
}

pub async fn verify_service_jwt<'r>(
    request: &'r Request<'_>,
    id_resolver: &State<SharedIdResolver>,
    opts: ServiceJwtOpts,
) -> Result<VerifiedServiceJwt> {
    let get_signing_key = |iss: String, force_refresh: bool| -> Result<String> {
        match &opts.iss {
            Some(opts_iss) if opts_iss.contains(&iss) => bail!("UntrustedIss: Untrusted issuer"),
            _ => (),
        }
        let parts = iss.split("#").collect::<Vec<&str>>();
        if let (Some(did), Some(service_id)) = (parts.get(0), parts.get(1)) {
            let (did, service_id) = (did.to_string(), *service_id);
            let key_id = if service_id == "atproto_labeler" {
                "atproto_label"
            } else {
                "atproto"
            };
            let mut lock = futures::executor::block_on(id_resolver.id_resolver.write());
            let did_doc: Result<DidDocument> =
                futures::executor::block_on(lock.did.ensure_resolve(&did, Some(force_refresh)));
            let did_doc: DidDocument = match did_doc {
                Err(err) => bail!("could not resolve iss did: `{err}`"),
                Ok(res) => res,
            };
            match get_verification_material(&did_doc, &key_id.to_string()) {
                None => bail!("missing or bad key in did doc"),
                Some(parsed_key) => match get_did_key_from_multibase(parsed_key)? {
                    None => bail!("missing or bad key in did doc"),
                    Some(did_key) => Ok(did_key),
                },
            }
        } else {
            bail!("could not resolve iss did")
        }
    };

    match bearer_token_from_req(request)? {
        None => bail!("MissingJwt: missing jwt"),
        Some(jwt_str) => {
            let payload: ServiceJwtPayload =
                verify_service_jwt_server(jwt_str, opts.aud, get_signing_key).await?;
            Ok(VerifiedServiceJwt {
                iss: payload.iss,
                aud: payload.aud,
            })
        }
    }
}

pub fn is_user_or_admin(auth: AccessOutput, did: &String) -> bool {
    match auth.credentials {
        Some(credentials) if credentials.did == Some("admin_token".to_string()) => true,
        Some(credentials) => credentials.did == Some(did.to_string()),
        None => false,
    }
}

// HELPERS
// ---------

const BEARER: &str = "Bearer ";
const DPOP: &str = "DPoP ";
const BASIC: &str = "Basic ";

fn authorization_token_from_req(
    request: &Request,
) -> Result<Option<(AuthorizationScheme, String)>> {
    match request.headers().get_one("authorization") {
        Some(header) if header.starts_with(DPOP) => {
            let slice = &header[DPOP.len()..];
            Ok(Some((AuthorizationScheme::Dpop, slice.to_string())))
        }
        Some(header) if header.starts_with(BEARER) => {
            let slice = &header[BEARER.len()..];
            Ok(Some((AuthorizationScheme::Bearer, slice.to_string())))
        }
        Some(_) => Ok(None),
        None => Ok(None),
    }
}

pub fn is_bearer_token(request: &Request) -> bool {
    match request.headers().get_one("Authorization") {
        None => false,
        Some(auth_header) => auth_header.starts_with(BEARER),
    }
}

pub fn is_basic_token(request: &Request) -> bool {
    match request.headers().get_one("Authorization") {
        None => false,
        Some(auth_header) => auth_header.starts_with(BASIC),
    }
}

pub fn bearer_token_from_req(request: &Request) -> Result<Option<String>> {
    Ok(match authorization_token_from_req(request)? {
        Some((AuthorizationScheme::Bearer, token)) => Some(token),
        _ => None,
    })
}

pub async fn verify_jwt(
    jwt: String,
    jwt_key: Keypair,
    verify_options: Option<VerificationOptions>,
) -> Result<JwtPayload> {
    let key = ES256kKeyPair::from_bytes(jwt_key.secret_bytes().as_slice())?;
    let public_key = key.public_key();
    let claims = public_key.verify_token::<CustomClaimObj>(&jwt, verify_options)?;

    let scope = if claims.custom.scope.is_empty() {
        // Service auth tokens (from video.bsky.app etc.) don't have scope,
        // they have lxm instead. Default to Access scope.
        AuthScope::Access
    } else {
        AuthScope::from_str(&claims.custom.scope)?
    };
    // Service auth tokens (e.g. from video.bsky.app) use 'iss' instead of 'sub'.
    // Fall back to issuer when subject is absent.
    let iss = claims.issuer.clone();
    let sub = claims.subject.or_else(|| iss.clone());
    Ok(JwtPayload {
        scope,
        sub,
        iss,
        aud: claims.audiences,
        exp: claims.expires_at,
        iat: claims.issued_at,
        jti: claims.jwt_id,
        cnf_jkt: None,
        external_issuer: false,
    })
}

async fn verify_external_entryway_jwt(
    jwt: String,
    cfg: &State<ServerConfig>,
    verify_options: Option<VerificationOptions>,
) -> Result<JwtPayload> {
    let entryway = cfg.entryway.as_ref().ok_or_else(|| {
        anyhow::anyhow!("UntrustedIss: no external authorization server configured")
    })?;
    let public_key_hex = entryway.jwt_public_key_hex.as_ref().ok_or_else(|| {
        anyhow::anyhow!("UntrustedIss: external authorization server key is not configured")
    })?;
    let public_key_bytes = hex::decode(public_key_hex.as_bytes())?;
    let public_key = ES256kPublicKey::from_bytes(&public_key_bytes)?;
    let claims = public_key.verify_token::<ExternalAccessTokenClaims>(&jwt, verify_options)?;

    let scope = if claims.custom.scope.is_empty() {
        AuthScope::Access
    } else {
        AuthScope::from_str(&claims.custom.scope)?
    };
    let iss = claims.issuer.clone();
    let sub = claims.subject.or_else(|| iss.clone());

    match iss.as_deref() {
        Some(issuer) if issuer == entryway.url => {}
        Some(issuer) => bail!(
            "UntrustedIss: expected external authorization issuer `{}`, got `{issuer}`",
            entryway.url
        ),
        None => bail!("UntrustedIss: missing token issuer"),
    }

    Ok(JwtPayload {
        scope,
        sub,
        iss,
        aud: claims.audiences,
        exp: claims.expires_at,
        iat: claims.issued_at,
        jti: claims.jwt_id,
        cnf_jkt: claims.custom.cnf.and_then(|cnf| cnf.jkt),
        external_issuer: true,
    })
}

pub fn parse_basic_auth(token: &str) -> Option<BasicAuth> {
    if !token.starts_with(BASIC) {
        return None;
    }

    let b64 = &token[BASIC.len()..];
    let decoded: Vec<u8> = match base64pad.decode(b64) {
        Err(_) => return None,
        Ok(decoded) => decoded,
    };
    let parsed_str: &str = match str::from_utf8(&decoded) {
        Err(_) => return None,
        Ok(res) => res,
    };
    let parsed_parts = parsed_str.split(":").collect::<Vec<&str>>();

    match (parsed_parts.get(0), parsed_parts.get(1)) {
        (Some(username), Some(password)) => Some(BasicAuth {
            username: username.to_string(),
            password: password.to_string(),
        }),
        _ => None,
    }
}
