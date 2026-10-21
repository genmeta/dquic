#[cfg(target_os = "linux")]
mod network_tests;
mod observation_tests;
mod support;
mod transaction_tests;

use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    frame::{AddAddressFrame, PunchDoneFrame, PunchHelloFrame, ReliableFrame, io::SendFrame},
    net::{NatType, addr::EndpointAddr, route::Link},
    packet::assemble::Package,
};
use qprotocol::EphemeralSocket;
use qtraversal::punch::{ArcPuncher, PunchPacketEncoder};

#[derive(Clone, Default)]
struct RecordedFrames(Arc<Mutex<Vec<ReliableFrame>>>);

impl SendFrame<ReliableFrame> for RecordedFrames {
    fn send_frame<I: IntoIterator<Item = ReliableFrame>>(&self, iter: I) {
        self.0.lock().unwrap().extend(iter);
    }
}

#[derive(Clone)]
struct UnusedEncoder;

impl PunchPacketEncoder for UnusedEncoder {
    fn encode_probe<P>(&self, _: P) -> io::Result<BytesMut>
    where
        P: for<'b> Package<&'b mut BytesMut>,
    {
        unreachable!("this test only sends reliable address frames")
    }
}

#[test]
fn local_addresses_are_announced_when_added_on_the_reliable_queue() {
    let frames = RecordedFrames::default();
    let puncher = ArcPuncher::new(frames.clone(), UnusedEncoder);
    let endpoint = EndpointAddr::direct("127.0.0.1:5000".parse().unwrap());
    puncher.on_local_added(
        "127.0.0.1:5000".parse().unwrap(),
        endpoint,
        "198.51.100.1:5000".parse().unwrap(),
        1,
        NatType::RestrictedCone,
    );
    assert!(matches!(
        frames.0.lock().unwrap().as_slice(),
        [ReliableFrame::AddAddress(frame)] if frame.seq_num() == 0
    ));
    puncher.on_local_removed(endpoint);
    assert!(matches!(
        frames.0.lock().unwrap().last(),
        Some(ReliableFrame::RemoveAddress(frame)) if frame.seq_num.into_u64() == 0
    ));
}

#[tokio::test]
async fn adding_another_default_group_binding_probes_that_specific_socket() {
    let first = EphemeralSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let second = EphemeralSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let first_addr = first.udp_socket().local_addr().unwrap();
    let second_addr = second.udp_socket().local_addr().unwrap();
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let puncher = ArcPuncher::new(RecordedFrames::default(), support::Encoder::default());
    puncher.on_local_added(
        first_addr,
        first_addr.into(),
        first_addr,
        0,
        NatType::FullCone,
    );
    puncher.recv_add_address(AddAddressFrame::new(
        9,
        peer.local_addr().unwrap(),
        0,
        NatType::FullCone,
    ));
    puncher.on_local_added(
        second_addr,
        second_addr.into(),
        second_addr,
        0,
        NatType::FullCone,
    );
    let mut received = std::collections::HashSet::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while received.len() < 2 {
            let mut bytes = [0; 128];
            let (len, source) = peer.recv_from(&mut bytes).await.unwrap();
            let qbase::frame::Frame::PunchHello(hello) =
                support::decode(BytesMut::from(&bytes[..len])).remove(0)
            else {
                panic!("expected HELLO");
            };
            assert_eq!(hello.remote_seq(), 9);
            assert_eq!(
                source,
                if hello.local_seq() == 0 {
                    first_addr
                } else {
                    second_addr
                }
            );
            received.insert(hello.local_seq());
        }
    })
    .await
    .expect("both bindings must send their own probe");
    assert_eq!(received, [0, 1].into_iter().collect());
    puncher.abort_transactions();
}

#[tokio::test]
async fn unsolicited_direct_hello_gets_a_reliable_done_response() {
    let frames = RecordedFrames::default();
    let puncher = ArcPuncher::new(frames.clone(), UnusedEncoder);
    let link = Link::new(
        "127.0.0.1:5000".parse().unwrap(),
        "127.0.0.1:6000".parse().unwrap(),
    );
    let hello = PunchHelloFrame::new(1, 2, 3);
    puncher.recv_punch_hello(link.into(), link, hello);
    assert!(matches!(
        frames.0.lock().unwrap().as_slice(),
        [ReliableFrame::PunchDone(done)] if *done == PunchDoneFrame::respond_to(&hello)
    ));
}
