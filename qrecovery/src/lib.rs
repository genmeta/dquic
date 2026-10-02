//! Crate to implement reliable transmission.
//!
//! The structures in this crate dont have the ability to send or receive frames directly, but they
//! provide interfaces to generate frames and write them into buffers, handle received frames, and
//! handle frame acknowledgment and loss. This is what [`Incoming`], [`Outgoing`], [`DataStreams`],
//! [`CryptoStreamIncoming`], [`CryptoStreamOutgoing`] and [`CryptoStream`] do.
//!
//! The [`reliable`] module of this crate provids the records for sent and received packets, and a
//! reliable frame queue to ensure that the frames in it will be sent to the peer and confirmed.
//!
//! The sent record can provide a packet number for the new packet (although the QUIC packet number
//! is incremented, the packet number stored in the packet header is encoded).
//!
//! The sent records are also responsible for processing the ack frames sent by the other party.
//! Through the other party's ack frames, which packets have been confirmed can be known, and then
//! the frames in these packets are fed back to [`DataStreams`] and [`CryptoStream`] for processing.
//!
//! The loss of packets is determined by congestion control, and sending records can feed back the
//! frame in may lost data packets to [`DataStreams`] and [`CryptoStream`].
//!
//! The received records are used to generate the ack frame, and decode the packet number in the
//! packet received.
//!
//! [`Incoming`]: crate::recv::Incoming
//! [`Outgoing`]: crate::send::Outgoing
//! [`DataStreams`]: crate::streams::DataStreams
//! [`CryptoStreamIncoming`]: crate::crypto::CryptoStreamIncoming
//! [`CryptoStreamOutgoing`]: crate::crypto::CryptoStreamOutgoing
//! [`CryptoStream`]: crate::crypto::CryptoStream
pub mod crypto;
pub mod journal;
pub mod recv;
pub mod reliable;
pub mod send;
pub mod streams;
