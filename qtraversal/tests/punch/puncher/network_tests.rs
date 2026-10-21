//! Docker/netns tests: mock the reliable broker and packet protection, but send
//! actual encoded punch frames through UDP, STUN and two independent NATs.
use std::{
    io::IoSlice,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::BytesMut;
use qbase::{
    frame::{AddAddressFrame, Frame, PunchMeNowFrame, ReliableFrame, io::SendFrame},
    net::{
        NatType,
        addr::EndpointAddr,
        route::{Line, Link, Pathway},
    },
};
use qprotocol::{
    Dock, EphemeralSocket, QuicProtocol, StunProtocol, UdpSocket, protocol::stun::ChangeServer,
};
use qtraversal::punch::ArcPuncher;
use tokio::{
    sync::mpsc,
    task::Id,
    time::{Instant, timeout},
};

use super::support::{Encoder, PROBE, decode};

const STUN: &str = "11.0.0.1:20002";
const DATA: &[u8] = &[0x40, b'D'];
type TestPuncher = ArcPuncher<Broker, Encoder>;

#[derive(Clone)]
struct Broker(mpsc::UnboundedSender<ReliableFrame>, Arc<Mutex<Vec<Id>>>);

impl SendFrame<ReliableFrame> for Broker {
    fn send_frame<I: IntoIterator<Item = ReliableFrame>>(&self, frames: I) {
        for frame in frames {
            if matches!(frame, ReliableFrame::PunchMeNow(_)) {
                self.1.lock().unwrap().push(tokio::task::id());
            }
            self.0.send(frame).expect("test broker remains connected");
        }
    }
}

struct Peer {
    socket: EphemeralSocket,
    puncher: TestPuncher,
    encoder: Encoder,
    request_tasks: Arc<Mutex<Vec<Id>>>,
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
        let encoder = Encoder::default();
        let request_tasks = Arc::new(Mutex::new(Vec::new()));
        let puncher = TestPuncher::new(Broker(sender, request_tasks.clone()), encoder.clone());
        puncher.on_local_added(bound, outer.into(), outer, 0, nat);
        let ReliableFrame::AddAddress(address) = receiver.recv().await.unwrap() else {
            panic!("first broker frame must advertise the endpoint");
        };
        (
            Self {
                socket,
                puncher,
                encoder,
                request_tasks,
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
    active_tasks: Option<[Id; 2]>,
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
            active_tasks: None,
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
                self.active_tasks = Some([
                    a.request_tasks.lock().unwrap()[0],
                    b.request_tasks.lock().unwrap()[0],
                ]);
                self.deliver(0, a_now);
                self.deliver(1, b_now);
                println!(
                    "DOUBLE_ACTIVE expected active={}",
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
                    for frame in decode(bytes) {
                        match frame {
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
        // Give both public entry points the unsupported pair. Neither strategy
        // may send NOW or HELLO, and completion must still suppress replay.
        test.peers[0]
            .puncher
            .recv_add_address(test.peers[1].address);
        test.peers[1]
            .puncher
            .recv_add_address(test.peers[0].address);
    } else {
        test.start(start).await;
    }
    // Keep forwarding until the existing 15-second budget expires. Inspecting
    // an internal transaction map used to shorten this wait. Public replay and
    // socket lifetime checks below also detect unfinished/aborted transactions.
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let _ = timeout(Duration::from_millis(20), test.step()).await;
    }
    let counts = test
        .peers
        .each_ref()
        .map(|peer| peer.encoder.hellos().len());
    for (side, peer) in test.peers.iter().enumerate() {
        peer.puncher.abort_transactions();
        // Use a supported NAT to ensure a missing completion record would
        // produce a HELLO, even for the double-Symmetric negative case.
        peer.puncher.recv_punch_me_now(
            test.pathway(side),
            PunchMeNowFrame::new(0, 0, test.peers[1 - side].outer, 0, NatType::FullCone),
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    for (side, peer) in test.peers.iter().enumerate() {
        assert_eq!(
            peer.encoder.hellos().len(),
            counts[side],
            "completed pair must not restart"
        );
    }
    if blocked || unsupported {
        assert!(
            test.direct.iter().all(Vec::is_empty),
            "negative topology must not pass probes"
        );
        if unsupported {
            for peer in &test.peers {
                assert!(peer.encoder.hellos().is_empty());
                assert!(peer.request_tasks.lock().unwrap().is_empty());
            }
        }
        return;
    }
    if a != b && test.direct.iter().all(Vec::is_empty) {
        println!("NAT_RANDOM_MISS");
    }
    assert!(
        test.direct.iter().all(|links| !links.is_empty()),
        "missing bidirectional probes: {:?}",
        test.direct
    );
    if let Some(active) = test.active_tasks {
        for (side, peer) in test.peers.iter().enumerate() {
            let larger = peer.outer > test.peers[1 - side].outer;
            let hellos = peer.encoder.hellos();
            if larger {
                assert!(
                    hellos.iter().all(|(task, _)| *task == active[side]),
                    "larger peer keeps the active sender"
                );
            } else {
                assert!(
                    hellos.iter().any(|(task, _)| *task != active[side]),
                    "smaller peer switches to a passive sender"
                );
            }
        }
    }
    // Aborting any remaining tasks above must not destroy the winning socket:
    // these round trips require ownership to have transferred to the puncher.
    test.verify_direct_echo().await;
    for (side, peer) in test.peers.iter().enumerate() {
        let winning = test.direct[side].last().unwrap().src;
        assert_eq!(winning != peer.bound(), peer.nat == NatType::Symmetric);
        assert!(Dock::global().find_socket(winning).is_some());
        peer.puncher.release_temporary_sockets();
        assert_eq!(
            Dock::global().find_socket(winning).is_none(),
            peer.nat == NatType::Symmetric
        );
        assert!(Dock::global().find_socket(peer.bound()).is_some());
    }
    println!("NAT_PUNCH_OK {a:?}/{b:?} {start:?}: bidirectional UDP and 3 direct echoes");
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
