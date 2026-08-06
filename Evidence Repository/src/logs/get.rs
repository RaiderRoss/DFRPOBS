use axum::{Json, response::IntoResponse};
use serde_json::Value;

async fn store(Json(log_data): Json<Value>) -> impl IntoResponse {
}