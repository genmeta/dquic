//! Run the ESP-IDF echo workload on the host before cross-compiling it.
mod echo;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    echo::run().await
}
