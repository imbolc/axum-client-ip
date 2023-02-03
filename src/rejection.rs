use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::convert::Infallible;

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
