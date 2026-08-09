// use axum::{Router, routing::get};
// use tokio::net::TcpListener;

use minio::s3::MinioClient;
use minio::s3::creds::StaticProvider;
use minio::s3::http::BaseUrl;
use minio::s3::response::BucketExistsResponse;
use minio::s3::types::S3Api;

mod auth;
mod logs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = "http://localhost:9000".parse::<BaseUrl>()?;
    let static_provider = StaticProvider::new("minioadmin", "minioadmin", None);

    let client = MinioClient::new(base_url, Some(static_provider), None, None)?;

    let exists: BucketExistsResponse = client.bucket_exists("my-bucket")?.build().send().await?;

    println!("Bucket exists: {}", exists.exists());
    // println!("Hello, world!");
    // let routes = Router::new()
    //     .route("/logs/{}", get(dumby))
    //     .route("", get(dumby))
    //     .route("/login", get(dumby));
    // let listener = TcpListener::bind("0.0.0.0:5000").await.unwrap();
    // axum::serve(listener, routes).await.unwrap();
    Ok(())
}

// async fn dumby() {
//     println!("This is a dumby function.");
// }
