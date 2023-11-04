use axum::extract::{ConnectInfo, FromRef, FromRequestParts, TypedHeader};
use axum::headers::authorization::{Authorization, Bearer};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware::{self, FromExtractorLayer};
use axum::response::{IntoResponse, Response};
use futures::TryFutureExt;
use std::net::SocketAddr;
use std::sync::Arc;
use token_review::k8s_openapi::api::authentication::v1::{
    TokenReviewSpec, TokenReviewStatus, UserInfo,
};
use token_review::Client;
pub use token_review::Error;
use tower::ServiceExt;

pub async fn try_default<A, U>(
    audiences: A,
    usernames: U,
) -> Result<FromExtractorLayer<Extractor, State>, Error>
where
    A: Into<Arc<[String]>>,
    U: Into<Arc<[String]>>,
{
    Ok(middleware::from_extractor_with_state(State {
        client: Client::try_default().await?,
        audiences: audiences.into(),
        usernames: usernames.into(),
    }))
}

pub struct Extractor;

#[derive(Clone)]
pub struct State {
    client: Client,
    audiences: Arc<[String]>,
    usernames: Arc<[String]>,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for Extractor
where
    S: Sync,
    State: FromRef<S>,
    ConnectInfo<SocketAddr>: FromRequestParts<S>,
    TypedHeader<Authorization<Bearer>>: FromRequestParts<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let State {
            client,
            audiences,
            usernames,
        } = State::from_ref(state);

        let ConnectInfo(addr) = ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
            .map_err(IntoResponse::into_response)
            .await?;

        if addr.ip().is_loopback() {
            Ok(Self)
        } else {
            let TypedHeader(Authorization(bearer)) =
                TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                    .map_err(IntoResponse::into_response)
                    .await?;
            let spec = TokenReviewSpec {
                audiences: Some(audiences.to_vec()),
                token: Some(bearer.token().to_owned()),
            };
            let status = client
                .oneshot(spec)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
                .await?;
            if let Some(TokenReviewStatus {
                authenticated: Some(true),
                user:
                    Some(UserInfo {
                        username: Some(username),
                        ..
                    }),
                ..
            }) = status
            {
                if usernames.contains(&username) {
                    Ok(Self)
                } else {
                    Err(StatusCode::FORBIDDEN.into_response())
                }
            } else {
                Err(StatusCode::UNAUTHORIZED.into_response())
            }
        }
    }
}
