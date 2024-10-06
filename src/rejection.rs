use std::convert::Infallible;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[derive(Debug)]
pub struct StringRejection(String);

pub(crate) type InfallibleRejection = (StatusCode, Infallible);

impl<T: Into<String>> From<T> for StringRejection {
    fn from(val: T) -> Self {
        Self(val.into())
    }
}

impl IntoResponse for StringRejection {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.0).into_response()
    }
}

impl std::fmt::Display for StringRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for StringRejection {}
