use clap::Parser;
use qudp::UdpSocket;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short,long, default_value_t = String::from("127.0.0.1:12345"))]
    bind: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::TRACE)
        .init();

    let args = Args::parse();
    let addr = args.bind.parse().unwrap();

    let socket = UdpSocket::bind(addr).expect("failed to create socket");
    let mut receiver = socket.receiver();
    loop {
        match receiver.recv().await {
            Ok(n) => {
                tracing::info!(
                    target: "qudp",
                    packets = n,
                    dst = %receiver.lines[0].dst,
                    src = %receiver.lines[0].src,
                    len = receiver.lines[0].seg_size,
                    "received packets"
                );
            }
            Err(e) => {
                tracing::error!(target: "qudp", error = %e, "receive failed");
            }
        }
    }
}
