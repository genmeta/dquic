use std::io::IoSlice;

use clap::Parser;
use qbase::net::route::{Line, Link};
use qudp::UdpSocket;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value_t = String::from("127.0.0.1:0"))]
    src: String,

    #[arg(long, default_value_t = String::from("127.0.0.1:12345"))]
    dst: String,

    #[arg(long, default_value_t = 3600)]
    msg_size: usize,

    #[arg(long, default_value_t = 100)]
    msg_count: usize,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::TRACE)
        .init();

    let args = Args::parse();
    let addr = args.src.parse().unwrap();
    let socket = UdpSocket::bind(addr).expect("failed to create socket");
    let dst = args.dst.parse().unwrap();

    let send_hdr = Line::new(
        Link::new(socket.local_addr().expect("failed to get local addr"), dst),
        64,
        None,
        args.msg_size as u16,
    );

    let payload = vec![8u8; args.msg_size];
    let payloads = vec![IoSlice::new(&payload[..]); args.msg_count];

    match socket.send(&payloads, send_hdr).await {
        Ok(n) => {
            tracing::info!(target: "qudp", packets = n, bytes = n * args.msg_size, "sent packets")
        }
        Err(e) => tracing::error!(target: "qudp", error = %e, "send failed"),
    }
}
