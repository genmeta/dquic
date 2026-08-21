use std::{
    io,
    ops::Deref,
    sync::{Arc, atomic::Ordering::Acquire},
};

use bytes::BufMut;
use derive_more::From;
use qbase::{
    Epoch, GetEpoch,
    cid::{BorrowedCid, ConnectionId},
    datagram::{Type as DatagramType, WriteDatagramType, r#type::v0},
    frame::PingFrame,
    net::{
        AddrFamily,
        addr::{EndpointAddr, WriteEndpointAddr},
        route::Pathway,
        tx::{ArcSendWaker, Signals},
    },
    packet::{
        AssemblePacket, Package, PacketContent, PacketInfo, ProductHeader,
        header::{
            long::{HandshakeHeader, InitialHeader, ZeroRttHeader, io::LongHeaderBuilder},
            short::OneRttHeader,
        },
        io::{Packages, PadProbe, PadTo20, PadToFull, Repeat},
        signal::SpinBit,
    },
    role::Role,
    token::TokenRegistry,
};
use qcongestion::{ArcCC, Transport};
use qinterface::io::IO;
use qrecovery::journal::{AckPackege, ArcRcvdJournal, Journal};

use crate::{
    ArcDcidCell, ArcReliableFrameDeque, CidRegistry, Components,
    path::{AntiAmplifier, ArcPathContexts, Constraints},
    space::{Spaces, data::DataSpace, handshake::HandshakeSpace, initial::InitialSpace},
    tls::ArcTlsHandshake,
    tx::PacketWriter,
};

// /// Trait alias
// pub trait PackageIntoSpacePacketWriter<H, S: PacketSpace<H>>:
//     for<'b, 's> Package<PacketWriter<'b, 's, S::JournalFrame>>
// {
// }

// impl<H, S: PacketSpace<H>, P> PackageIntoSpacePacketWriter<H, S> for P where
//     P: for<'b, 's> Package<PacketWriter<'b, 's, S::JournalFrame>>
// {
// }

// pn space?
pub trait PacketSpace<H> {
    type JournalFrame;

    fn new_packet<'b, 's>(
        &'s self,
        header: H,
        cc: &ArcCC,
        buffer: &'b mut [u8],
    ) -> Result<PacketWriter<'b, 's, Self::JournalFrame>, Signals>;
}

pub struct Burst {
    path: Arc<super::Path>,
    initial_token: Vec<u8>,
    cid_registry: CidRegistry,
    spin: bool,

    spaces: Spaces,
    paths: ArcPathContexts,

    tls_handshake: ArcTlsHandshake,
}

fn datagram_capacity(
    max_segment_size: usize,
    mtu: usize,
    forward_overhead: usize,
    remaining_credit: usize,
) -> Result<usize, Signals> {
    let capacity = max_segment_size.min(mtu).min(remaining_credit);
    (capacity > forward_overhead)
        .then_some(capacity)
        .ok_or(Signals::CREDIT)
}

fn forward_reserved_overhead(pathway: Pathway) -> usize {
    if matches!(pathway.local(), EndpointAddr::Direct { .. })
        && matches!(pathway.remote(), EndpointAddr::Direct { .. })
    {
        0
    } else {
        2 + pathway.local().encoding_size() + pathway.remote().encoding_size()
    }
}

fn encode_forward_in_place(buffer: &mut [u8], raw_len: usize, pathway: Pathway) -> usize {
    let family = pathway.local().addr().family();
    let source = pathway.local().kind();
    let destination = pathway.remote().kind();
    let ty = v0::Type::Forward(family, source, destination);
    let prefix_len = 2 + pathway.local().encoding_size() + pathway.remote().encoding_size();
    let encoded_len = prefix_len + raw_len;
    debug_assert!(encoded_len <= buffer.len());

    let mut prefix = &mut buffer[..prefix_len];
    prefix.put_datagram_type(&DatagramType::V0(ty));
    prefix.put_endpoint_addr(pathway.local());
    prefix.put_endpoint_addr(pathway.remote());
    debug_assert!(prefix.is_empty());
    encoded_len
}

impl super::Path {
    pub fn new_burst(self: &Arc<Self>, components: &Components) -> Burst {
        Burst {
            path: self.clone(),
            initial_token: match components.token_registry.deref() {
                TokenRegistry::Client((server_name, token_sink)) => {
                    token_sink.fetch_token(server_name)
                }
                TokenRegistry::Server(..) => vec![],
            },
            cid_registry: components.cid_registry.clone(),
            spin: false, // TODO
            spaces: components.spaces.clone(),
            paths: components.paths.clone(),
            tls_handshake: components.tls_handshake.clone(),
        }
    }
}

// 用双层Result
#[derive(From)]
pub enum BurstError {
    Signals(Signals),
    PathDeactived,
}

pub struct PacketsAssembler<'a> {
    cc: &'a ArcCC,
    constraints: Constraints,
    cid_registry: &'a CidRegistry,
    borrowed_dcid: Result<BorrowedCid<'a, ArcReliableFrameDeque>, Signals>,
    initial_token: &'a [u8],
    spin: SpinBit,
}

impl<'a> PacketsAssembler<'a> {
    fn new(
        cid_registry: &'a CidRegistry,
        dcid_cell: &'a ArcDcidCell,
        anti_amplifier: &AntiAmplifier,
        cc: &'a ArcCC,
        tx_waker: ArcSendWaker,
        initial_token: &'a [u8],
        spin: impl Into<SpinBit>,
    ) -> Result<PacketsAssembler<'a>, BurstError> {
        let send_quota = cc.send_quota()?;
        let Some(credit_limit) = anti_amplifier.balance()? else {
            return Err(BurstError::PathDeactived);
        };

        let Some(borrowed_dcid) = dcid_cell.borrow_cid(tx_waker).transpose() else {
            return Err(BurstError::PathDeactived);
        };

        let constraints = Constraints::new(credit_limit, send_quota);
        Ok(Self {
            cid_registry,
            borrowed_dcid,
            cc,
            constraints,
            initial_token,
            spin: spin.into(),
        })
    }

    fn initial_scid(&self) -> Result<ConnectionId, Signals> {
        self.cid_registry
            .local
            .initial_scid()
            .ok_or(Signals::empty())
    }

    fn applied_dcid(&self) -> Result<ConnectionId, Signals> {
        self.borrowed_dcid.as_deref().copied().map_err(|e| *e)
    }

    /// Return the connection ID that used to send the initial and zero rtt packets.
    ///
    /// dquic implements multi-path handshake feature, the client creates many paths and sends initial packets.
    ///
    /// Client will only use origin_dcid to send initial and zero rtt packets.
    ///
    /// The client and server must negotiate a handshake path and assign the initial dcid to this path
    /// to prevent the unique connection ID from being obtained by an invalid path, causing the connection to fail.
    ///
    /// The client and server choose the path where they receive the first initial packet as the handshake path.
    /// The server will only return the initial packet on the handshake path to negotiate the handshake path.
    ///
    /// Therefore, for the server, it can only send the initial packet with the connection ID assigned to the path.
    /// This manifests itself during the handshake as sending the initial packet only on the first path.
    fn initial_dcid(&self) -> Result<ConnectionId, Signals> {
        match self.cid_registry.role() {
            Role::Client => Ok(self.cid_registry.origin_dcid()),
            Role::Server => self.applied_dcid(),
        }
    }

    pub fn commit(&mut self, sent_bytes: usize, pkt_info: PacketInfo) {
        self.constraints.commit(sent_bytes, pkt_info.in_flight());
        self.cc.on_pkt_sent(
            pkt_info.epoch().expect("todo"),
            pkt_info.packet_number(),
            pkt_info.ack_eliciting(),
            sent_bytes,
            pkt_info.in_flight(),
            pkt_info.largest_ack(),
        );
    }
}

impl ProductHeader<InitialHeader> for PacketsAssembler<'_> {
    fn new_header(&self) -> Result<InitialHeader, Signals> {
        Ok(
            LongHeaderBuilder::with_cid(self.initial_dcid()?, self.initial_scid()?)
                .initial(self.initial_token.to_vec()),
        )
    }
}

impl ProductHeader<ZeroRttHeader> for PacketsAssembler<'_> {
    fn new_header(&self) -> Result<ZeroRttHeader, Signals> {
        Ok(LongHeaderBuilder::with_cid(self.initial_dcid()?, self.initial_scid()?).zero_rtt())
    }
}

impl ProductHeader<HandshakeHeader> for PacketsAssembler<'_> {
    fn new_header(&self) -> Result<HandshakeHeader, Signals> {
        Ok(LongHeaderBuilder::with_cid(self.applied_dcid()?, self.initial_scid()?).handshake())
    }
}

impl ProductHeader<OneRttHeader> for PacketsAssembler<'_> {
    fn new_header(&self) -> Result<OneRttHeader, Signals> {
        Ok(OneRttHeader::new(self.spin, self.applied_dcid()?))
    }
}

impl<'a> PacketsAssembler<'a> {
    pub fn assemble<'s, 'b, H, Space, P>(
        &mut self,
        space: &'s Space,
        data_sources: P,
        buffer: &'b mut [u8],
        packet_content: &mut PacketContent,
    ) -> Result<usize, Signals>
    where
        Self: ProductHeader<H>,
        Space: PacketSpace<H> + GetEpoch,
        Space::JournalFrame: 's,
        P: Package<PacketWriter<'b, 's, Space::JournalFrame>>,
    {
        let buffer = self.constraints.constrain(buffer);
        let mut packet = space.new_packet(self.new_header()?, self.cc, buffer)?;
        *packet_content += packet.assemble_packet(&mut Packages((data_sources, PadTo20)))?;
        let (sent_bytes, props) = packet.encrypt_and_protect_packet();
        self.commit(sent_bytes, props);
        Result::<_, Signals>::Ok(sent_bytes)
    }
}

pub type PackageIntoSpace<H, S> =
    dyn for<'b, 's> Package<PacketWriter<'b, 's, <S as PacketSpace<H>>::JournalFrame>> + Send;

pub struct DataSources {
    initial: Box<PackageIntoSpace<InitialHeader, InitialSpace>>,
    zero_rtt: Box<PackageIntoSpace<ZeroRttHeader, DataSpace>>,
    handshake: Box<PackageIntoSpace<HandshakeHeader, HandshakeSpace>>,
    one_rtt: Box<PackageIntoSpace<OneRttHeader, DataSpace>>,
}

impl Components {
    pub(super) fn packages(&self) -> DataSources {
        let initial_packages = self.crypto_streams[Epoch::Initial]
            .outgoing()
            .package(Epoch::Initial);
        let zero_rtt_packages = Packages((
            // repeat to send multi reliable frames in one packet
            Repeat(self.reliable_frames.clone()),
            // repeat to send multi stream frames in one packet
            Repeat(
                self.data_streams
                    .package(self.flow_ctrl.sender.clone(), true),
            ),
            // TODO: datagram
        ));
        let handshake_packages = self.crypto_streams[Epoch::Handshake]
            .outgoing()
            .package(Epoch::Handshake);
        let one_rtt_packages = Packages((
            self.crypto_streams[Epoch::Data]
                .outgoing()
                .package(Epoch::Data),
            // repeat to send multi reliable frames in one packet
            Repeat(self.reliable_frames.clone()),
            // repeat to send multi stream frames in one packet
            Repeat(
                self.data_streams
                    .package(self.flow_ctrl.sender.clone(), false),
            ),
            // TODO: datagram
        ));
        DataSources {
            initial: Box::new(initial_packages),
            zero_rtt: Box::new(zero_rtt_packages),
            handshake: Box::new(handshake_packages),
            one_rtt: Box::new(one_rtt_packages),
        }
    }
}

fn ack_package<'s, S, F>(space: &'s S, cc: &ArcCC) -> AckPackege<'s>
where
    S: GetEpoch + AsRef<Journal<F>>,
    F: 's,
{
    // (1) may_loss被调用时cc已经被锁定，may_loss会尝试锁定sent_journal
    // (2) PacketMemory会持有sent_journal的guard，而need_ack会尝试锁定cc
    // 在PacketMemory存在时尝试锁定cc，可能会和 (1) 冲突:
    //   (1)持有cc，要锁定sent_journal；(2)持有sent_journal要锁定cc
    // 在多线程的情况下，可能会发生死锁。所以提前调用need_ack，避免交叉导致死锁
    ArcRcvdJournal::ack_package(space.as_ref().as_ref(), cc.need_ack(space.epoch()))
}

impl Burst {
    fn assembler<'a>(&'a self) -> Result<PacketsAssembler<'a>, BurstError> {
        PacketsAssembler::new(
            &self.cid_registry,
            &self.path.dcid_cell,
            &self.path.anti_amplifier,
            &self.path.cc,
            self.path.tx_waker.clone(),
            &self.initial_token,
            self.spin,
        )
    }

    fn load_spaces(
        &self,
        DataSources {
            initial: initial_data_sources,
            zero_rtt: zero_rtt_data_sources,
            handshake: handshake_data_sources,
            one_rtt: one_rtt_data_sources,
        }: &mut DataSources,
        mut buffer: &mut [u8],
    ) -> Result<(usize, PacketContent), BurstError> {
        let Self {
            path,
            spaces,
            tls_handshake,
            ..
        } = self;

        let initial_space = spaces.initial().as_ref();
        let handshake_space = spaces.handshake().as_ref();
        let data_space = spaces.data().as_ref();

        let origin = buffer.remaining_mut();
        let mut packet_content = PacketContent::default();

        let mut assembler = self.assembler()?;
        let mut signals = Signals::empty();

        let Ok(tls_fin) = tls_handshake.is_finished() else {
            return Err(BurstError::PathDeactived);
        };

        match assembler.assemble(
            initial_space,
            &mut Packages((ack_package(initial_space, &path.cc), initial_data_sources)),
            buffer,
            &mut packet_content,
        ) {
            Ok(bytes_sent) => buffer = buffer[bytes_sent..].as_mut(),
            Err(s) => signals |= s,
        };

        let loaded_initial = buffer.remaining_mut() != origin;

        if !tls_fin {
            match assembler.assemble::<ZeroRttHeader, _, _>(
                data_space,
                zero_rtt_data_sources,
                buffer,
                &mut packet_content,
            ) {
                Ok(bytes_sent) => buffer = buffer[bytes_sent..].as_mut(),
                Err(s) => signals |= s,
            }
        }

        match assembler.assemble(
            handshake_space,
            &mut Packages((
                ack_package(handshake_space, &path.cc),
                handshake_data_sources,
            )),
            buffer,
            &mut packet_content,
        ) {
            Ok(bytes_sent) => {
                buffer = buffer[bytes_sent..].as_mut();
                // RFC 9001 Section 4.9.1 requires clients to discard Initial keys
                // when they first send a Handshake packet.
                if self.cid_registry.role() == Role::Client && self.spaces.discard_initial_key() {
                    self.paths.discard_initial_space();
                }
            }
            Err(s) => signals |= s,
        }

        if tls_fin {
            let result = if path.validated.load(Acquire) {
                assembler.assemble::<OneRttHeader, _, _>(
                    data_space,
                    &mut Packages((
                        ack_package(data_space, &path.cc),
                        &path.challenge_sndbuf,
                        &path.response_sndbuf,
                        one_rtt_data_sources,
                        loaded_initial.then_some(PadToFull),
                        PadProbe,
                    )),
                    buffer,
                    &mut packet_content,
                )
            } else {
                assembler.assemble::<OneRttHeader, _, _>(
                    data_space,
                    &mut Packages((
                        ack_package(data_space, &path.cc),
                        &path.challenge_sndbuf,
                        &path.response_sndbuf,
                        loaded_initial.then_some(PadToFull),
                        PadProbe,
                    )),
                    buffer,
                    &mut packet_content,
                )
            };

            match result {
                Ok(bytes_sent) => buffer = buffer[bytes_sent..].as_mut(),
                Err(s) => signals |= s,
            }
        }

        if loaded_initial {
            assert!(buffer.remaining_mut() != origin);
            buffer.put_bytes(0, buffer.remaining_mut());
            return Ok((origin, packet_content));
        }

        let sent_bytes = origin - buffer.remaining_mut();
        (sent_bytes > 0)
            .then_some((sent_bytes, packet_content))
            .ok_or(BurstError::Signals(signals))
    }
}

struct PingSource {
    need_send_ack_eliciting: usize,
}

impl<Target: ?Sized> Package<Target> for PingSource
where
    PingFrame: Package<Target>,
{
    fn dump(&mut self, target: &mut Target) -> Result<PacketContent, Signals> {
        if self.need_send_ack_eliciting > 0 {
            return PingFrame.dump(target);
        }
        // TODO: refactor signal names
        Err(Signals::PING)
    }
}

fn ping_package(cc: &ArcCC, epoch: Epoch) -> PingSource {
    // avoid deadlock, same as ack_package
    PingSource {
        need_send_ack_eliciting: cc.need_send_ack_eliciting(epoch),
    }
}

impl Burst {
    fn load_ping(&self, buffer: &mut [u8]) -> Result<(usize, PacketContent), BurstError> {
        let Self { spaces, path, .. } = self;

        let mut assembler = self.assembler()?;
        let mut signals = Signals::empty();
        let mut packet_content = PacketContent::default();

        for &epoch in Epoch::iter().rev() {
            let result = match epoch {
                Epoch::Data => {
                    let ack_package = ack_package(spaces.data().as_ref(), &path.cc);
                    let ping_package = ping_package(&path.cc, epoch);
                    assembler.assemble::<OneRttHeader, _, _>(
                        spaces.data().as_ref(),
                        &mut Packages((ack_package, ping_package, PadToFull)),
                        buffer,
                        &mut packet_content,
                    )
                }
                Epoch::Handshake => {
                    let ack_package = ack_package(spaces.handshake().as_ref(), &path.cc);
                    let ping_package = ping_package(&path.cc, epoch);
                    assembler.assemble(
                        spaces.handshake().as_ref(),
                        &mut Packages((ack_package, ping_package, PadToFull)),
                        buffer,
                        &mut packet_content,
                    )
                }
                Epoch::Initial => {
                    let ack_package = ack_package(spaces.initial().as_ref(), &path.cc);
                    let ping_package = ping_package(&path.cc, epoch);
                    assembler.assemble(
                        spaces.initial().as_ref(),
                        &mut Packages((ack_package, ping_package, PadToFull)),
                        buffer,
                        &mut packet_content,
                    )
                }
            };

            match result {
                Ok(sent_bytes) => return Ok((sent_bytes, packet_content)),
                Err(s) => signals |= s,
            }
        }

        Err(BurstError::Signals(signals))
    }

    fn load_keep_alive(&self, buffer: &mut [u8]) -> Result<(usize, PacketContent), BurstError> {
        let Self {
            spaces,
            path,
            tls_handshake,
            ..
        } = self;
        let mut assembler = self.assembler()?;
        let mut packet_content = PacketContent::default();
        let one_rtt_ready = tls_handshake
            .is_finished()
            .is_ok_and(|is_finished| is_finished);
        let now = tokio::time::Instant::now();
        if !path.keep_alive_due(one_rtt_ready, now) {
            return Err(BurstError::Signals(Signals::TRANSPORT));
        }
        match assembler.assemble::<OneRttHeader, _, _>(
            spaces.data().as_ref(),
            &PingFrame,
            buffer,
            &mut packet_content,
        ) {
            Ok(sent_bytes) => Ok((sent_bytes, packet_content)),
            Err(s) => Err(BurstError::Signals(s)),
        }
    }

    pub fn burst<'b>(
        &self,
        data_sources: &mut DataSources,
        buffers: &'b mut Vec<Vec<u8>>,
    ) -> Result<(Vec<io::IoSlice<'b>>, PacketContent), BurstError> {
        if !self.path.is_active() {
            return Err(BurstError::PathDeactived);
        }
        let Ok(max_segments) = self.path.interface.max_segments() else {
            return Err(BurstError::PathDeactived);
        };
        let Ok(max_segment_size) = self.path.interface.max_segment_size() else {
            return Err(BurstError::PathDeactived);
        };

        let reversed_size = forward_reserved_overhead(self.path.pathway);
        let mut segment_lengths = Vec::with_capacity(max_segments);
        let mut burst_content = PacketContent::default();
        let Some(mut remaining_credit) = self.path.anti_amplifier.balance()? else {
            return Err(BurstError::PathDeactived);
        };

        for segment_index in 0..max_segments {
            if buffers.len() <= segment_index {
                buffers.push(vec![0; max_segment_size]);
            }

            let segment = &mut buffers[segment_index];
            if segment.len() < max_segment_size {
                segment.resize(max_segment_size, 0);
            }

            let segment = &mut segment[..max_segment_size];
            let buffer_size = match datagram_capacity(
                segment.len(),
                self.path.mtu() as _,
                reversed_size,
                remaining_credit,
            ) {
                Ok(capacity) => capacity,
                Err(error) if segment_lengths.is_empty() => {
                    return Err(BurstError::Signals(error));
                }
                Err(_) => break,
            };
            let buffer = &mut segment[..buffer_size][reversed_size..];
            let load_result = self
                .load_spaces(data_sources, buffer)
                .or_else(|error| match error {
                    BurstError::Signals(signals) => self.load_ping(buffer).map_err(|e| match e {
                        BurstError::Signals(s) => BurstError::Signals(signals | s),
                        e @ BurstError::PathDeactived => e,
                    }),
                    e @ BurstError::PathDeactived => Err(e),
                })
                .or_else(|error| match error {
                    BurstError::Signals(signals) => {
                        self.load_keep_alive(buffer).map_err(|e| match e {
                            BurstError::Signals(s) => BurstError::Signals(signals | s),
                            e @ BurstError::PathDeactived => e,
                        })
                    }
                    e @ BurstError::PathDeactived => Err(e),
                })
                .map(|(packet_size, packet_content)| {
                    burst_content += packet_content;
                    if reversed_size > 0 {
                        let encoded_size =
                            encode_forward_in_place(segment, packet_size, self.path.pathway);
                        tracing::trace!(
                            target: "dquic",
                            pathway = %self.path.pathway,
                            link = %self.path.link(),
                            "put forward envelope"
                        );
                        return encoded_size;
                    }
                    packet_size
                });

            let segment_length = match load_result {
                Err(error) if segment_lengths.is_empty() => return Err(error),
                Err(_) => break,
                Ok(segment_length) => segment_length,
            };
            remaining_credit = remaining_credit.saturating_sub(segment_length);
            let final_segment =
                segment_length < segment_lengths.last().copied().unwrap_or_default();
            segment_lengths.push(segment_length);
            if final_segment {
                break;
            }
        }

        Ok((
            segment_lengths
                .iter()
                .zip(buffers)
                .map(|(&len, buffer)| io::IoSlice::new(&buffer[..len]))
                .collect(),
            burst_content,
        ))
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use qbase::datagram::{Datagram, be_datagram};

    use super::*;

    fn forwarding_round_trip(raw: &[u8]) {
        let pathway = Pathway::new(
            EndpointAddr::mediate(
                "198.51.100.1:3478".parse().unwrap(),
                "192.0.2.1:50000".parse().unwrap(),
            ),
            EndpointAddr::direct("203.0.113.1:4433".parse().unwrap()),
        );
        let raw_offset = forward_reserved_overhead(pathway);
        let mut buffer = vec![0; raw_offset + raw.len()];
        buffer[raw_offset..].copy_from_slice(raw);

        let encoded_len = encode_forward_in_place(&mut buffer, raw.len(), pathway);
        let Datagram::Forward(decoded_pathway, forward) =
            be_datagram(BytesMut::from(&buffer[..encoded_len])).unwrap()
        else {
            panic!("expected Forward datagram");
        };
        assert_eq!(decoded_pathway, pathway);
        assert_eq!(forward.into_raw(), raw);
    }

    #[test]
    fn amplification_credit_is_shared_by_all_segments() {
        let mut remaining_credit = 3_600;
        let mut total = 0;

        for _ in 0..64 {
            let Ok(capacity) = datagram_capacity(1_500, 1_200, 0, remaining_credit) else {
                break;
            };
            remaining_credit -= capacity;
            total += capacity;
        }

        assert_eq!(total, 3_600);
        assert_eq!(remaining_credit, 0);
    }

    #[test]
    fn forwarding_overhead_is_part_of_the_datagram_credit() {
        assert_eq!(datagram_capacity(1_500, 1_200, 50, 1_200), Ok(1_200));
        assert_eq!(
            datagram_capacity(1_500, 1_200, 50, 50),
            Err(Signals::CREDIT)
        );
    }

    #[test]
    fn in_place_forwarding_preserves_any_raw_datagram() {
        forwarding_round_trip(&[0x45, 1, 2, 3]);
        forwarding_round_trip(&[0xc1, 0, 0, 0, 1, 1, 2, 3]);
    }
}
