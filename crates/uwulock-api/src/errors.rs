//! Errors, the way Bitwarden's clients expect them.
//!
//! Bitwarden's server answers a failed request with an `ErrorResponseModel`: a `message`,
//! optional `validationErrors`, and `"object": "error"`. The clients show the message, so it has
//! to be one a person can read.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({
            "message": self.message,
            "validationErrors": null,
            "exceptionMessage": null,
            "exceptionStackTrace": null,
            "innerExceptionMessage": null,
            "object": "error",
        });
        (self.status, Json(body)).into_response()
    }
}

pub(crate) async fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Not found.")
}

#[cfg(test)]
mod tests {
    use crate::test_support::{TestServer, json};
    use axum::http::StatusCode;

    #[tokio::test]
    async fn an_unknown_path_is_a_bitwarden_error() {
        let server = TestServer::new();
        let response = server.get("/api/nothing-here").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = json(response).await;
        assert_eq!(body["object"], "error");
        assert_eq!(body["message"], "Not found.");
    }
}
