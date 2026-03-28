use crate::config::ServerConfig;
use crate::well_known::{oauth_protected_resource_metadata, OAuthProtectedResourceMetadata};
use rocket::serde::json::Json;
use rocket::State;

#[rocket::get("/.well-known/oauth-protected-resource")]
pub async fn protected_resource(cfg: &State<ServerConfig>) -> Json<OAuthProtectedResourceMetadata> {
    Json(oauth_protected_resource_metadata(cfg))
}
