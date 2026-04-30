use bytes::BytesMut;
use clap::Parser;
use qbase::net::route::Line;
use qudp::{BATCH_SIZE, UdpSocket};

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
    let mut iovecs: Vec<BytesMut> = (0..BATCH_SIZE)
        .map(|_| {
            let mut buf = BytesMut::with_capacity(1500);
            buf.resize(1500, 0);
            buf
        })
        .collect();
    let mut lines: Vec<Line> = (0..BATCH_SIZE).map(|_| Line::default()).collect();

    loop {
        match socket.receive(&mut iovecs, &mut lines).await {
            Ok(n) => {
                tracing::info!(
                    target: "qudp",
                    packets = n,
                    dst = %lines[0].dst,
                    src = %lines[0].src,
                    len = lines[0].seg_size,
                    "received packets"
                );
            }
            Err(e) => {
                tracing::error!(target: "qudp", error = %e, "receive failed");
            }
        }
    }
}
