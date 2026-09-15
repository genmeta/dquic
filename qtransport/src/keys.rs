//! Keys own readiness, retirement, and packet protection generations.
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use qbase::{error::ErrorKind, frame::FrameReader, packet::DataPacket};
use qrecovery::journal::ArcRcvdJournal;
use tokio::{sync::Notify, time::Instant};

use crate::{Error, control::Control, send::packet::PacketError};

pub enum KeysState<K> {
    Pending,
    Ready(K),
    Invalid,
}

pub struct ArcKeys<K = qtls::BidirectionalKeys> {
    inner: Arc<(Mutex<KeysState<K>>, Notify)>,
    pub(crate) control: Arc<Control>,
}

impl<K> Clone for ArcKeys<K> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            control: self.control.clone(),
        }
    }
}

impl<K> ArcKeys<K> {
    pub fn new_pending(control: Arc<Control>) -> Self {
        Self {
            inner: Arc::new((Mutex::new(KeysState::Pending), Notify::new())),
            control,
        }
    }

    pub fn install(&self, keys: K) -> Result<(), Error> {
        let _submission = self.control.submission.lock().unwrap();
        let mut state = self.inner.0.lock().unwrap();
        if !matches!(*state, KeysState::Pending) {
            return Err(crate::error(
                ErrorKind::Internal,
                "keys already installed or retired",
            ));
        }
        *state = KeysState::Ready(keys);
        self.inner.1.notify_waiters();
        Ok(())
    }

    pub fn invalid(&self) {
        let _submission = self.control.submission.lock().unwrap();
        *self.inner.0.lock().unwrap() = KeysState::Invalid;
        self.control.retire_locked();
        self.inner.1.notify_waiters();
    }

    /// Use installed material synchronously, for a handshake space's packet builder.
    /// References cannot escape the closure; retirement serializes with this use.
    pub fn with_ready<R>(&self, use_keys: impl FnOnce(&K) -> R) -> Option<R> {
        match &*self.inner.0.lock().unwrap() {
            KeysState::Ready(keys) => Some(use_keys(keys)),
            _ => None,
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(*self.inner.0.lock().unwrap(), KeysState::Ready(_))
    }

    pub async fn ready(&self) -> bool {
        loop {
            let changed = self.inner.1.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match *self.inner.0.lock().unwrap() {
                KeysState::Ready(_) => return true,
                KeysState::Invalid => return false,
                KeysState::Pending => {}
            }
            changed.await;
        }
    }
}

/// Packet protection for an independently driven receive space.
pub trait ReceiveKeys: Send + Sync {
    fn ready(&self) -> impl Future<Output = bool> + Send;
    fn open(
        &self,
        packet: DataPacket,
        journal: &ArcRcvdJournal,
        pto: Duration,
    ) -> Result<Option<(u64, FrameReader)>, Error>;
}

impl ReceiveKeys for ArcKeys {
    fn ready(&self) -> impl Future<Output = bool> + Send {
        self.ready()
    }
    fn open(
        &self,
        packet: DataPacket,
        journal: &ArcRcvdJournal,
        _: Duration,
    ) -> Result<Option<(u64, FrameReader)>, Error> {
        let state = self.inner.0.lock().unwrap();
        let KeysState::Ready(keys) = &*state else {
            return Ok(None);
        };
        crate::recv::open_with(
            packet,
            &keys.opening.header,
            journal,
            |pn, _, header, body| {
                Ok(keys
                    .opening
                    .packet
                    .open(pn, header, body)
                    .ok()
                    .map(|plain| plain.len()))
            },
        )
    }
}

struct OneRttKeys {
    opening_header: qtls::HeaderProtectionKey,
    sealing_header: qtls::HeaderProtectionKey,
    opening: qtls::OpeningKeyCursor,
    sealing: qtls::SealingKeyCursor,
    current_opening: qtls::PacketKey,
    next_opening: qtls::PacketKey,
    previous: Option<(qtls::PacketKey, Instant)>,
    opening_generation: u64,
    sealing_generation: u64,
    first_received: Option<u64>,
    largest_received: Option<u64>,
    last_sealed: Option<u64>,
    sealed_count: u64,
    failed_authentications: u64,
    confirmed: bool,
    acked: bool,
    update_requested: bool,
}

#[derive(Clone)]
pub struct ArcOneRttKeys(ArcKeys<OneRttKeys>);

impl ArcOneRttKeys {
    pub fn new_pending(control: Arc<Control>) -> Self {
        Self(ArcKeys::new_pending(control))
    }

    pub fn install(&self, mut keys: qtls::OneRttKeyMaterial) -> Result<(), Error> {
        let current_opening = keys.opening.current().clone();
        let next_opening = keys
            .opening
            .advance()
            .map_err(|_| crate::error(ErrorKind::KeyUpdate, "key generation exhausted"))?
            .key;
        self.0.install(OneRttKeys {
            opening_header: keys.opening_header,
            sealing_header: keys.sealing_header,
            opening: keys.opening,
            sealing: keys.sealing,
            current_opening,
            next_opening,
            previous: None,
            opening_generation: 0,
            sealing_generation: 0,
            first_received: None,
            largest_received: None,
            last_sealed: None,
            sealed_count: 0,
            failed_authentications: 0,
            confirmed: false,
            acked: false,
            update_requested: false,
        })
    }

    pub fn invalid(&self) {
        self.0.invalid();
    }
    pub fn is_ready(&self) -> bool {
        self.0.is_ready()
    }
    pub async fn ready(&self) -> bool {
        self.0.ready().await
    }

    pub fn confirm_handshake(&self) {
        if let KeysState::Ready(keys) = &mut *self.0.inner.0.lock().unwrap() {
            keys.confirmed = true;
        }
    }

    /// Request a local update after a packet of the current generation was acknowledged.
    pub fn update(&self) -> Result<(), Error> {
        let _submission = self.0.control.submission.lock().unwrap();
        let mut state = self.0.inner.0.lock().unwrap();
        let KeysState::Ready(keys) = &mut *state else {
            return Err(crate::error(ErrorKind::KeyUpdate, "1-RTT keys unavailable"));
        };
        if !keys.confirmed || !keys.acked {
            return Err(crate::error(
                ErrorKind::KeyUpdate,
                "key update requires confirmation and an ACK",
            ));
        }
        keys.update_requested = true;
        Ok(())
    }

    pub(crate) fn on_ack(&self, generation: u64) {
        if let KeysState::Ready(keys) = &mut *self.0.inner.0.lock().unwrap()
            && keys.sealing_generation == generation
        {
            keys.acked = true;
        }
    }

    pub(crate) fn current_generation(&self, generation: u64) -> bool {
        matches!(&*self.0.inner.0.lock().unwrap(), KeysState::Ready(keys)
            if keys.sealing_generation == generation && keys.opening_generation <= generation && !keys.update_requested)
    }

    pub(crate) fn seal<T>(
        &self,
        pn: u64,
        seal: impl FnOnce(&qtls::HeaderProtectionKey, &qtls::PacketKey, u64) -> Result<T, PacketError>,
    ) -> Result<T, PacketError> {
        let mut state = self.0.inner.0.lock().unwrap();
        let KeysState::Ready(keys) = &mut *state else {
            return Err(PacketError::Stale);
        };
        if keys.last_sealed.is_some_and(|last| pn <= last) {
            return Err(PacketError::Stale);
        }
        let nearing_limit = keys.sealed_count
            >= keys
                .sealing
                .current()
                .confidentiality_limit()
                .saturating_sub(1);
        if keys.update_requested
            || keys.opening_generation > keys.sealing_generation
            || (nearing_limit && keys.confirmed && keys.acked)
        {
            keys.sealing.advance()?;
            keys.sealing_generation += 1;
            keys.sealed_count = 0;
            keys.acked = false;
            keys.update_requested = false;
        }
        if keys.sealed_count >= keys.sealing.current().confidentiality_limit() {
            return Err(crate::error(
                ErrorKind::AeadLimitReached,
                "packet protection confidentiality limit",
            )
            .into());
        }
        keys.last_sealed = Some(pn);
        keys.sealed_count += 1;
        seal(
            &keys.sealing_header,
            keys.sealing.current(),
            keys.sealing_generation,
        )
    }

    pub(crate) fn tag_len(&self) -> Option<usize> {
        match &*self.0.inner.0.lock().unwrap() {
            KeysState::Ready(keys) => Some(keys.sealing.current().tag_len()),
            _ => None,
        }
    }
}

impl ReceiveKeys for ArcOneRttKeys {
    fn ready(&self) -> impl Future<Output = bool> + Send {
        self.ready()
    }
    fn open(
        &self,
        packet: DataPacket,
        journal: &ArcRcvdJournal,
        pto: Duration,
    ) -> Result<Option<(u64, FrameReader)>, Error> {
        // Peer key evolution and pending submission use the same short boundary.
        let _submission = self.0.control.submission.lock().unwrap();
        let mut state = self.0.inner.0.lock().unwrap();
        let KeysState::Ready(keys) = &mut *state else {
            return Ok(None);
        };
        let now = Instant::now();
        if keys
            .previous
            .as_ref()
            .is_some_and(|(_, until)| now >= *until)
        {
            keys.previous = None;
        }
        let OneRttKeys {
            opening_header,
            opening,
            current_opening,
            next_opening,
            previous,
            opening_generation,
            first_received,
            largest_received,
            confirmed,
            failed_authentications,
            ..
        } = keys;
        crate::recv::open_with(
            packet,
            opening_header,
            journal,
            |pn, first, header, body| {
                let changed = ((first >> 2) & 1) as u64 != *opening_generation % 2;
                let updating = changed && largest_received.is_none_or(|largest| pn > largest);
                let key = if updating {
                    &*next_opening
                } else if changed {
                    if first_received.is_some_and(|first| pn >= first) {
                        return Ok(None);
                    }
                    let Some((key, _)) = previous else {
                        return Ok(None);
                    };
                    key
                } else {
                    &*current_opening
                };
                let plain_len = match key.open(pn, header, body) {
                    Ok(plain) => plain.len(),
                    Err(_) => {
                        *failed_authentications += 1;
                        if *failed_authentications >= key.integrity_limit() {
                            return Err(crate::error(
                                ErrorKind::AeadLimitReached,
                                "packet protection integrity limit",
                            ));
                        }
                        return Ok(None);
                    }
                };
                if updating {
                    if !*confirmed {
                        return Err(crate::error(
                            ErrorKind::KeyUpdate,
                            "key update before handshake confirmation",
                        ));
                    }
                    let old = std::mem::replace(current_opening, next_opening.clone());
                    *next_opening = opening
                        .advance()
                        .map_err(|_| {
                            crate::error(ErrorKind::KeyUpdate, "key generation exhausted")
                        })?
                        .key;
                    *previous = Some((old, now + pto.saturating_mul(3)));
                    *opening_generation += 1;
                    *first_received = Some(pn);
                    *largest_received = Some(pn);
                } else if !changed {
                    *first_received = Some(first_received.map_or(pn, |first| first.min(pn)));
                    *largest_received =
                        Some(largest_received.map_or(pn, |largest| largest.max(pn)));
                }
                Ok(Some(plain_len))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use qbase::{
        cid::ConnectionId,
        frame::PingFrame,
        packet::{OneRttHeader, PacketNumber},
    };

    use super::*;
    use crate::send::{constraints::Constraints, packet::OneRttPacket};

    fn ready() -> ArcOneRttKeys {
        let ([client, _], _) = crate::tests::handshake();
        let keys = ArcOneRttKeys::new_pending(Arc::new(Control::new(Arc::new(Mutex::new(())))));
        keys.install(client).unwrap();
        keys
    }
    fn packet(pn: u64) -> OneRttPacket {
        let mut packet = OneRttPacket::new(
            bytes::BytesMut::zeroed(1200),
            OneRttHeader::new(Default::default(), ConnectionId::default()),
            pn,
            16,
        )
        .unwrap();
        packet
            .assemble(
                &mut Constraints {
                    capacity: 1200,
                    congestion: 1200,
                    anti_amplification: 1200,
                },
                [&mut PingFrame],
            )
            .unwrap();
        packet
    }

    #[test]
    fn update_needs_confirmation_and_ack_and_sealing_never_reuses_a_number() {
        let keys = ready();
        assert!(keys.update().is_err());
        keys.confirm_handshake();
        assert!(keys.update().is_err());
        packet(0).seal(&keys).unwrap();
        keys.on_ack(0);
        keys.update().unwrap();
        assert_eq!(packet(1).seal(&keys).unwrap().generation, 1);
        assert!(matches!(packet(1).seal(&keys), Err(PacketError::Stale)));
        assert!(matches!(packet(0).seal(&keys), Err(PacketError::Stale)));
        assert!(
            keys.update().is_err(),
            "old generation's ACK does not authorize another update"
        );
    }

    #[test]
    fn confidentiality_limit_updates_when_permitted_and_fails_when_not() {
        let keys = ready();
        keys.confirm_handshake();
        keys.on_ack(0);
        {
            let mut state = keys.0.inner.0.lock().unwrap();
            let KeysState::Ready(keys) = &mut *state else {
                panic!()
            };
            keys.sealed_count = keys.sealing.current().confidentiality_limit();
        }
        assert_eq!(packet(0).seal(&keys).unwrap().generation, 1);
        {
            let mut state = keys.0.inner.0.lock().unwrap();
            let KeysState::Ready(keys) = &mut *state else {
                panic!()
            };
            keys.sealed_count = keys.sealing.current().confidentiality_limit();
        }
        assert!(
            matches!(packet(1).seal(&keys), Err(PacketError::Connection(error)) if error.kind() == ErrorKind::AeadLimitReached)
        );
    }

    #[test]
    fn authentication_failures_enforce_the_integrity_limit() {
        let ([client, server], _) = crate::tests::handshake();
        let sending = ArcOneRttKeys::new_pending(Arc::new(Control::new(Arc::new(Mutex::new(())))));
        sending.install(client).unwrap();
        let receiving =
            ArcOneRttKeys::new_pending(Arc::new(Control::new(Arc::new(Mutex::new(())))));
        receiving.install(server).unwrap();
        {
            let mut state = receiving.0.inner.0.lock().unwrap();
            let KeysState::Ready(keys) = &mut *state else {
                panic!()
            };
            keys.failed_authentications = keys.current_opening.integrity_limit() - 1;
        }
        let mut forged = packet(0).seal(&sending).unwrap().bytes;
        let last = forged.len() - 1;
        forged[last] ^= 1;
        let qbase::packet::Packet::Data(packet) = qbase::packet::PacketReader::new(forged, 0)
            .next()
            .unwrap()
            .unwrap()
        else {
            panic!()
        };
        let journal = ArcRcvdJournal::with_capacity(0, None);
        assert!(
            matches!(receiving.open(packet, &journal, Duration::from_secs(1)), Err(error) if error.kind() == ErrorKind::AeadLimitReached)
        );
        assert_eq!(journal.decode_pn(PacketNumber::encode(0, 0)), Ok(0));
    }

    #[tokio::test]
    async fn retirement_wakes_a_pending_key_wait_and_cannot_be_reinstalled() {
        let control = Arc::new(Control::new(Arc::new(Mutex::new(()))));
        let keys = ArcKeys::<()>::new_pending(control.clone());
        let waiting = keys.clone();
        let task = tokio::spawn(async move { waiting.ready().await });
        tokio::task::yield_now().await;
        keys.invalid();
        assert!(!task.await.unwrap());
        assert!(keys.install(()).is_err());
        assert!(!control.receiving().await);
        assert!(control.sending_stopped());
    }
}
