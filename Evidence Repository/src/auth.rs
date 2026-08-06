// use axum::{Json, response::IntoResponse};
// use serde::{Deserialize, Serialize};
// use serde_json::Value;

// #[derive(Debug, Serialize, Deserialize, Clone)]
// pub struct Data {
//     pub user: String,
//     pub admin: bool,
//     pub exp: usize,
// }

// async fn login(Json(user_data): Json<Value>) -> impl IntoResponse {
//     let username = user_data.get("username").unwrap().as_str().unwrap();
//     let password = user_data.get("password").unwrap().as_str().unwrap();
// }

// async fn register(Json(user_data): Json<Value>) -> impl IntoResponse {
//     let username = user_data.get("username").unwrap().as_str().unwrap();
//     let password = user_data.get("password").unwrap().as_str().unwrap();
//     let email = user_data.get("email").unwrap().as_str().unwrap();
// }
