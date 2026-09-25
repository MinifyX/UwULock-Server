//! Errors, the way Bitwarden's clients expect them.
//!
//! Bitwarden's server answers a failed request with an `ErrorResponseModel`: the message in
//! `message`, in `validationErrors` and in `errorModel`, because different clients look in
//! different places. They show that message, so it has to be one a person can read. A few
//! answers are not that model but a JSON body of their own — a refused refresh token, a login
//! that needs its second step — and some are nothing but a status.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    body: Body,
}

#[derive(Debug)]
enum Body {
    Message(String),
    /// Exactly this JSON, like `{"error":"invalid_grant"}`.
    Json(Value),
    /// Messages by field, for an import where item 3 is too long.
    Validation(serde_json::Map<String, Value>),
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    /// 400 with a message for the person in front of the client.
    pub fn bad(message: impl Into<String>) -> Self {
        Self { status: StatusCode::BAD_REQUEST, body: Body::Message(message.into()) }
    }

    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, body: Body::Message(message.into()) }
    }

    /// 401: the clients try their refresh token, and log out if that does not help either.
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "Your session has ended. Log in again.")
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub fn too_many(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, message)
    }

    /// 400 with exactly this JSON as the body.
    pub fn json(value: Value) -> Self {
        Self { status: StatusCode::BAD_REQUEST, body: Body::Json(value) }
    }

    /// 400 "The model state is invalid." with messages by field.
    pub fn validation(errors: serde_json::Map<String, Value>) -> Self {
        Self { status: StatusCode::BAD_REQUEST, body: Body::Validation(errors) }
    }

    /// Something went wrong on this side. What exactly goes to the log, not to the client.
    pub fn internal(error: impl std::fmt::Display) -> Self {
        tracing::error!(%error, "request failed");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong on the server. Try again later.")
    }

    /// The message a person would read, for tests and logs.
    pub fn message(&self) -> String {
        match &self.body {
            Body::Message(message) => message.clone(),
            Body::Json(value) => value.to_string(),
            Body::Validation(errors) => Value::Object(errors.clone()).to_string(),
        }
    }
}

impl From<uwulock_store::StoreError> for ApiError {
    fn from(error: uwulock_store::StoreError) -> Self {
        Self::internal(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = match self.body {
            Body::Message(message) => json!({
                "message": message,
                "validationErrors": { "": [message] },
                "errorModel": { "message": message, "object": "error" },
                "error": "",
                "error_description": "",
                "exceptionMessage": null,
                "exceptionStackTrace": null,
                "innerExceptionMessage": null,
                "object": "error",
            }),
            Body::Json(value) => value,
            Body::Validation(errors) => json!({
                "message": "The model state is invalid.",
                "validationErrors": errors,
                "errorModel": { "message": "The model state is invalid.", "object": "error" },
                "object": "error",
            }),
        };
        (self.status, Json(body)).into_response()
    }
}

pub(crate) async fn not_found() -> ApiError {
    ApiError::not_found("Not found.")
}

#[cfg(test)]
mod tests {
    use crate::test_support::{TestServer, json};
    use axum::http::StatusCode;

    #[tokio::test]
    async fn an_unknown_path_is_a_bitwarden_error() {
        let server = TestServer::new().await;
        let response = server.get("/api/nothing-here").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = json(response).await;
        assert_eq!(body["object"], "error");
        assert_eq!(body["message"], "Not found.");
        assert_eq!(body["errorModel"]["message"], "Not found.");
    }
}
