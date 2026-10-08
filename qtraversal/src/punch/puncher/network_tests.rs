//! Docker/netns tests: mock the reliable broker and packet protection, but send
//! actual encoded punch frames through UDP, STUN and two independent NATs.
use std::task::{Context, Poll, Waker};

use qbase::{
    frame::{Frame, FrameReader},
    packet::{Constraints, PacketBuffer, Type},
};
use qprotocol::{StunProtocol, protocol::stun::ChangeServer};
use tokio::{
    sync::mpsc,
    time::{Instant, timeout},
};

use super::*;

const STUN: &str = "11.0.0.1:20002";
const PROBE: &[u8] = &[0x40, b'P'];
const DATA: &[u8] = &[0x40, b'D'];
type TestPuncher = ArcPuncher<Broker, Encoder>;

#[derive(Clone)]
struct Broker(mpsc::UnboundedSender<ReliableFrame>);

impl SendFrame<ReliableFrame> for Broker {
    fn send_frame<I: IntoIterator<Item = ReliableFrame>>(&self, frames: I) {
        for frame in frames {
            self.0.send(frame).expect("test broker remains connected");
        }
    }
}

#[derive(Clone)]
struct Encoder;

impl PunchPacketEncoder for Encoder {
    fn encode_probe<P>(&self, mut frame: P) -> io::Result<BytesMut>
    where
        P: for<'b> Package<&'b mut BytesMut>,
    {
        let mut bytes = BytesMut::from(PROBE);
        let mut limits = Constraints {
            flow_ctrl: usize::MAX,
            send_quota: 128,
            credit: 128,
            max_size: 128,
            ..Default::default()
        };
        let mut output = &mut bytes;
        let mut frames = Vec::new();
        let mut buffer =
            PacketBuffer::new(&mut output, &mut limits, &mut frames, packet_type(), 0, 0);
        let result = frame.poll_dump(&mut Context::from_waker(Waker::noop()), &mut buffer);
        assert!(
            matches!(result, Poll::Ready(Ok(1))),
            "encode probe: {result:?}"
        );
        Ok(bytes)
    }
}

fn packet_type() -> Type {
    Type::Short(0.into())
}

struct Peer {
    socket: EphemeralSocket,
    puncher: TestPuncher,
    address: AddAddressFrame,
    nat: NatType,
    outer: SocketAddr,
}

impl Peer {
    async fn new(ip: &str, expected: NatType) -> (Self, mpsc::UnboundedReceiver<ReliableFrame>) {
        let socket = EphemeralSocket::bind(format!("{ip}:0").parse().unwrap()).unwrap();
        let bound = socket.udp_socket().local_addr().unwrap();
        let stun = StunProtocol::global();
        let nat = timeout(
            Duration::from_secs(15),
            stun.detect_nat(bound, STUN.parse().unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(nat, expected, "NAT classification for {bound}");
        let outer = socket
            .outer_addr(stun, STUN.parse().unwrap())
            .await
            .unwrap();
        println!("NAT {bound} -> {outer}: {nat:?}");
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let puncher = TestPuncher::new(Broker(sender), Encoder);
        puncher.on_local_added(bound, outer.into(), outer, 0, nat);
        let ReliableFrame::AddAddress(address) = receiver.recv().await.unwrap() else {
            panic!("first broker frame must advertise the endpoint");
        };
        (
            Self {
                socket,
                puncher,
                address,
                nat,
                outer,
            },
            receiver,
        )
    }

    fn bound(&self) -> SocketAddr {
        self.socket.udp_socket().local_addr().unwrap()
    }

    fn completed(&self) -> bool {
        self.puncher
            .0
            .punch_history
            .contains_key(&PunchId::new(0, 0))
            && self.puncher.0.transaction.is_empty()
    }
}

#[derive(Clone, Copy, Debug)]
enum Start {
    A,
    B,
    Both { a_larger: bool },
}

struct Harness {
    peers: [Peer; 2],
    brokers: [mpsc::UnboundedReceiver<ReliableFrame>; 2],
    datagrams: mpsc::UnboundedReceiver<(BytesMut, Pathway, Link)>,
    direct: [Vec<Link>; 2],
    echoes: Vec<(u8, Link)>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        QuicProtocol::global().on_receive(|_, _, _| {});
        for peer in &self.peers {
            peer.puncher.abort_transactions();
            peer.puncher.release_temporary_sockets();
        }
    }
}

impl Harness {
    async fn new(a: NatType, b: NatType) -> Self {
        let (sender, datagrams) = mpsc::unbounded_channel();
        QuicProtocol::global().on_receive(move |packet, path, link| {
            let _ = sender.send((packet, path, link));
        });
        let (a, a_rx) = Peer::new("192.168.10.2", a).await;
        let (b, b_rx) = Peer::new("192.168.20.2", b).await;
        Self {
            peers: [a, b],
            brokers: [a_rx, b_rx],
            datagrams,
            direct: Default::default(),
            echoes: Vec::new(),
        }
    }

    fn pathway(&self, side: usize) -> Pathway {
        Pathway::new(
            EndpointAddr::mediate(STUN.parse().unwrap(), self.peers[side].outer),
            EndpointAddr::mediate(STUN.parse().unwrap(), self.peers[1 - side].outer),
        )
    }

    fn deliver(&self, source: usize, frame: ReliableFrame) {
        let side = 1 - source;
        let peer = &self.peers[side];
        match frame {
            ReliableFrame::PunchMeNow(frame) => {
                peer.puncher.recv_punch_me_now(self.pathway(side), frame)
            }
            ReliableFrame::PunchDone(frame) => peer
                .puncher
                .recv_punch_done(Link::new(peer.bound(), self.peers[source].outer), frame),
            _ => panic!("unexpected broker frame: {frame:?}"),
        }
    }

    async fn start(&mut self, start: Start) {
        let [a, b] = &self.peers;
        match start {
            Start::A => a.puncher.recv_add_address(b.address),
            Start::B => b.puncher.recv_add_address(a.address),
            Start::Both { a_larger } => {
                assert_eq!(
                    a.outer > b.outer,
                    a_larger,
                    "network layout must match arbitration case"
                );
                a.puncher.recv_add_address(b.address);
                b.puncher.recv_add_address(a.address);
                // Hold reliable requests until BOTH active strategies send NOW.
                // UDP probes may queue meanwhile, but none are delivered to a
                // transaction before this explicit simultaneous-active barrier.
                async fn next_now(
                    rx: &mut mpsc::UnboundedReceiver<ReliableFrame>,
                ) -> ReliableFrame {
                    let frame = timeout(Duration::from_secs(5), rx.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(matches!(frame, ReliableFrame::PunchMeNow(_)));
                    frame
                }
                let [a_rx, b_rx] = &mut self.brokers;
                let (a_now, b_now) = tokio::join!(next_now(a_rx), next_now(b_rx));
                let id = PunchId::new(0, 0);
                let original = [
                    a.puncher.0.transaction.get(&id).unwrap().1.clone(),
                    b.puncher.0.transaction.get(&id).unwrap().1.clone(),
                ];
                self.deliver(0, a_now);
                self.deliver(1, b_now);
                for (side, old) in original.iter().enumerate() {
                    let current = self.peers[side]
                        .puncher
                        .0
                        .transaction
                        .get(&id)
                        .unwrap()
                        .1
                        .clone();
                    let remains_active = (side == 0) == a_larger;
                    assert_eq!(Arc::ptr_eq(old, &current), remains_active);
                }
                println!(
                    "DOUBLE_ACTIVE negotiated: active={}",
                    if a_larger { "A" } else { "B" }
                );
            }
        }
    }

    async fn step(&mut self) {
        enum Event {
            Broker(usize, ReliableFrame),
            Udp(BytesMut, Pathway, Link),
        }
        let [a_rx, b_rx] = &mut self.brokers;
        let event = tokio::select! {
            Some(frame) = a_rx.recv() => Event::Broker(0, frame),
            Some(frame) = b_rx.recv() => Event::Broker(1, frame),
            Some((bytes, path, link)) = self.datagrams.recv() => Event::Udp(bytes, path, link),
        };
        match event {
            Event::Broker(side, frame) => self.deliver(side, frame),
            Event::Udp(mut bytes, path, link) => {
                let side = self
                    .peers
                    .iter()
                    .position(|peer| peer.bound().ip() == link.src.ip())
                    .unwrap();
                assert_eq!(
                    link.dst.ip(),
                    self.peers[1 - side].outer.ip(),
                    "must cross the peer NAT"
                );
                if bytes.starts_with(PROBE) {
                    self.direct[side].push(link);
                    for frame in
                        FrameReader::new(bytes.split_off(PROBE.len()).freeze(), packet_type())
                    {
                        match frame.unwrap().0 {
                            Frame::PunchHello(frame) => {
                                self.peers[side].puncher.recv_punch_hello(path, link, frame)
                            }
                            Frame::PunchDone(frame) => {
                                self.peers[side].puncher.recv_punch_done(link, frame)
                            }
                            frame => panic!("unexpected UDP probe: {frame:?}"),
                        }
                    }
                } else {
                    assert!(bytes.starts_with(DATA));
                    assert_eq!(bytes.len(), 4);
                    if bytes[2] == 0 {
                        bytes[2] = 1;
                        send_data(link, &bytes).await;
                    } else {
                        assert_eq!(bytes[2], 1);
                        assert_eq!(side, 0);
                        self.echoes.push((bytes[3], link));
                    }
                }
            }
        }
    }

    async fn verify_direct_echo(&mut self) {
        let link = *self.direct[0].last().unwrap();
        for sequence in 0..3 {
            send_data(link, &[DATA[0], DATA[1], 0, sequence]).await;
            timeout(Duration::from_secs(2), async {
                while !self.echoes.contains(&(sequence, link)) {
                    self.step().await;
                }
            })
            .await
            .expect("direct UDP round trip on the retained punch socket");
        }
    }
}

async fn send_data(link: Link, bytes: &[u8]) {
    let socket = Dock::global()
        .find_socket(link.src)
        .expect("winning socket is retained");
    socket
        .send(
            &[IoSlice::new(bytes)],
            Line::new(link, 64, None, bytes.len() as u16),
        )
        .await
        .unwrap();
}

async fn run(a: NatType, b: NatType, start: Start, blocked: bool) {
    let mut test = Harness::new(a, b).await;
    let unsupported = a == NatType::Symmetric && b == NatType::Symmetric;
    if unsupported {
        for side in 0..2 {
            let peer = &test.peers[side];
            let local = peer
                .puncher
                .0
                .addresses
                .lock()
                .unwrap()
                .local_for_seq(0)
                .unwrap();
            let error = peer
                .puncher
                .punch_actively(
                    local,
                    test.peers[1 - side].address,
                    Arc::new(Transaction::new()),
                )
                .await
                .expect_err("double Symmetric is unsupported");
            assert_eq!(error.to_string(), "unsupported NAT pair");
        }
        assert!(test.direct.iter().all(Vec::is_empty));
        return;
    }
    test.start(start).await;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let complete = test.peers.iter().all(Peer::completed);
        if blocked && complete {
            assert!(
                test.direct.iter().all(Vec::is_empty),
                "blocked topology must not pass probes"
            );
            return;
        }
        if !blocked && complete && test.direct.iter().all(|links| !links.is_empty()) {
            for peer in &test.peers {
                assert_eq!(
                    peer.puncher.0.temporary_sockets.len(),
                    usize::from(peer.nat == NatType::Symmetric)
                );
            }
            test.verify_direct_echo().await;
            println!("NAT_PUNCH_OK {a:?}/{b:?} {start:?}: bidirectional UDP and 3 direct echoes");
            return;
        }
        if Instant::now() >= deadline {
            if !blocked && a != b && test.direct.iter().all(Vec::is_empty) && complete {
                println!("NAT_RANDOM_MISS");
            }
            panic!(
                "punch did not complete: completed={complete}, direct={:?}",
                test.direct
            );
        }
        let _ = timeout(Duration::from_millis(20), test.step()).await;
    }
}

macro_rules! case {
    ($name:ident, $a:ident, $b:ident, $start:expr, $blocked:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "requires qtraversal/tools/run.sh Docker NAT topology"]
        async fn $name() {
            run(NatType::$a, NatType::$b, $start, $blocked).await;
        }
    };
}

case!(
    nat_rp_rp_a_active,
    RestrictedPort,
    RestrictedPort,
    Start::A,
    false
);
case!(
    nat_rp_rp_b_active,
    RestrictedPort,
    RestrictedPort,
    Start::B,
    false
);
case!(
    nat_rp_rp_both_a_larger,
    RestrictedPort,
    RestrictedPort,
    Start::Both { a_larger: true },
    false
);
case!(
    nat_rp_rp_both_b_larger,
    RestrictedPort,
    RestrictedPort,
    Start::Both { a_larger: false },
    false
);
case!(
    nat_rp_sym_a_active,
    RestrictedPort,
    Symmetric,
    Start::A,
    false
);
case!(
    nat_rp_sym_b_active,
    RestrictedPort,
    Symmetric,
    Start::B,
    false
);
case!(
    nat_rp_sym_both_a_larger,
    RestrictedPort,
    Symmetric,
    Start::Both { a_larger: true },
    false
);
case!(
    nat_rp_sym_both_b_larger,
    RestrictedPort,
    Symmetric,
    Start::Both { a_larger: false },
    false
);
case!(
    nat_sym_rp_a_active,
    Symmetric,
    RestrictedPort,
    Start::A,
    false
);
case!(
    nat_sym_rp_b_active,
    Symmetric,
    RestrictedPort,
    Start::B,
    false
);
case!(
    nat_sym_rp_both_a_larger,
    Symmetric,
    RestrictedPort,
    Start::Both { a_larger: true },
    false
);
case!(
    nat_sym_rp_both_b_larger,
    Symmetric,
    RestrictedPort,
    Start::Both { a_larger: false },
    false
);
case!(
    nat_sym_sym_unsupported,
    Symmetric,
    Symmetric,
    Start::A,
    false
);
case!(
    nat_rp_rp_blocked,
    RestrictedPort,
    RestrictedPort,
    Start::A,
    true
);

#[tokio::test]
#[ignore = "local STUN helper started by qtraversal/tools/run.sh"]
async fn stun_service() {
    let mut sockets = Vec::new();
    for last in 1..=3 {
        for port in [20002, 20003] {
            let bound = SocketAddr::from(([11, 0, 0, last], port));
            let socket = Arc::new(UdpSocket::bind(bound).unwrap());
            Dock::global().add(socket.clone()).unwrap();
            StunProtocol::global()
                .set_change_server(
                    bound,
                    ChangeServer {
                        change_port: port ^ 1,
                        change_address: ([11, 0, 0, last % 3 + 1], port ^ 1).into(),
                        outer_address: bound,
                    },
                )
                .unwrap();
            sockets.push(socket);
        }
    }
    println!("STUN_READY");
    std::future::pending::<()>().await;
}
