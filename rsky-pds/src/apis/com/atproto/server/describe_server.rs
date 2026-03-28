use crate::apis::ApiError;
use crate::config::ServerConfig;
use rocket::serde::json::Json;
use rocket::State;
use rsky_lexicon::com::atproto::server::{
    DescribeServerOutput, DescribeServerRefContact, DescribeServerRefLinks,
};

#[tracing::instrument(skip_all)]
#[rocket::get("/xrpc/com.atproto.server.describeServer")]
pub async fn describe_server(
    cfg: &State<ServerConfig>,
) -> Result<Json<DescribeServerOutput>, ApiError> {
    Ok(Json(DescribeServerOutput {
        did: cfg.service.did.clone(),
        available_user_domains: cfg.identity.service_handle_domains.clone(),
        invite_code_required: Some(cfg.invites.required),
        phone_verification_required: None,
        links: DescribeServerRefLinks {
            privacy_policy: cfg.service.privacy_policy_url.clone(),
            terms_of_service: cfg.service.terms_of_service_url.clone(),
        },
        contact: DescribeServerRefContact {
            email: cfg.service.contact_email_address.clone(),
        },
    }))
}
