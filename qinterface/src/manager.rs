use std::{
    any::Any,
    fmt::Debug,
    future::Future,
    io, mem,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    sync::{Arc, OnceLock},
    task::{Context, Poll, ready},
};

use bytes::BytesMut;
use dashmap::{DashMap, Entry};
use futures::FutureExt;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use qbase::{
    net::route,
    util::{UniqueId, UniqueIdGenerator},
};
use tokio::sync::SetOnce;
use tracing::Instrument as _;

use crate::{
    BindInterface, Interface, RebindedError, WeakBindInterface,
    bind_uri::BindUri,
    component::{Component, Components},
    io::{IO, IoExt, ProductIO},
};

/// Global [`IO`] manager that manages the lifecycle of all interfaces.
///
/// Calling the [`InterfaceManager::bind`] method with a [`BindUri`] returns a [`BindInterface`], primarily used for listening on addresses.
/// As long as [`BindInterface`] instances exist, the corresponding [`IO`] for that [`BindUri`] won't be automatically released.
///
/// For actual data transmission, you need [`Interface`], which can be obtained via [`InterfaceManager::borrow`] or [`BindInterface::borrow`].
/// Like [`BindInterface`], it keeps the [`IO`] alive, but with one key difference: once a rebind occurs,
/// any previous [`Interface`] for that [`BindUri`] becomes invalid, and attempting to send or receive packets
/// will result in [`RebindedError] errors.
#[derive(Default, Debug)]
pub struct InterfaceManager {
    interfaces: DashMap<BindUri, InterfaceEntry>,
    bind_id_generator: UniqueIdGenerator,
}

#[derive(Debug)]
struct InterfaceEntry {
    weak_iface: WeakBindInterface,
    dropped: Arc<SetOnce<()>>,
}

impl InterfaceEntry {
    fn is_dropped(&self) -> bool {
        self.dropped.get().is_some()
    }

    fn dropped(&self) -> impl Future<Output = ()> + use<> {
        let dropped = self.dropped.clone();
        async move {
            dropped.wait().await;
        }
    }
}

impl InterfaceManager {
    #[inline]
    pub fn global() -> &'static Arc<Self> {
        static GLOBAL: OnceLock<Arc<InterfaceManager>> = OnceLock::new();
        GLOBAL.get_or_init(Arc::default)
    }

    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    fn new_binding(
        self: &Arc<Self>,
        entry: Entry<BindUri, InterfaceEntry>,
        factory: Arc<dyn ProductIO>,
    ) -> BindInterface {
        let context = InterfaceContext {
            factory: factory.clone(),
            binding: RwLock::new(Binding::new(
                factory.bind(entry.key().clone()),
                self.bind_id_generator.generate(),
            )),
            dropped: Arc::new(SetOnce::new()),
            ifaces: self.clone(),
            components: RwLock::new(Components::default()),
        };
        let dropped = context.dropped.clone();
        let iface = BindInterface::new(context);
        let weak_iface = iface.downgrade();

        entry.insert(InterfaceEntry {
            weak_iface,
            dropped,
        });

        iface
    }

    pub async fn bind(
        self: &Arc<Self>,
        bind_uri: BindUri,
        factory: Arc<dyn ProductIO>,
    ) -> BindInterface {
        // TODO: error: rebind with difference factory
        loop {
            match self.interfaces.entry(bind_uri.clone()) {
                // (1) new binding: context closed but not yet removed
                Entry::Occupied(entry) if entry.get().is_dropped() => {
                    return self.new_binding(Entry::Occupied(entry), factory);
                }
                // (2) new binding: no existing context
                Entry::Vacant(entry) => {
                    return self.new_binding(Entry::Vacant(entry), factory);
                }
                // try reuse existing binding
                Entry::Occupied(entry) => match entry.get().weak_iface.upgrade() {
                    // (3) reuse existing binding
                    Ok(iface) => {
                        if iface.borrow().bound_addr().is_ok() {
                            return iface.clone();
                        }

                        tracing::debug!(
                            bind_uri = %bind_uri,
                            "replacing closed interface binding during bind"
                        );
                        drop(iface);
                        return self.new_binding(Entry::Occupied(entry), factory);
                    }
                    // (4) no existing binding: close context and retry
                    Err(..) => {
                        let dropped_future = entry.get().dropped();
                        drop(entry);
                        dropped_future.await;
                    }
                },
            }
        }
    }

    #[inline]
    pub fn borrow(&self, bind_uri: &BindUri) -> Option<Interface> {
        self.interfaces
            .get(bind_uri)
            .and_then(|entry| Some(entry.weak_iface.upgrade().ok()?.borrow()))
    }

    #[inline]
    pub fn get(&self, bind_uri: &BindUri) -> Option<BindInterface> {
        self.interfaces
            .get(bind_uri)
            .and_then(|entry| entry.weak_iface.upgrade().ok())
    }

    #[inline]
    pub fn unbind(self: &Arc<Self>, bind_uri: BindUri) -> impl Future<Output = ()> + Send + use<> {
        let Entry::Occupied(entry) = self.interfaces.entry(bind_uri) else {
            return std::future::ready(()).right_future();
        };

        match entry.get().weak_iface.upgrade() {
            Ok(bind_iface) => {
                let drop_future = bind_iface.context.as_ref().drop();
                spawn_on_drop::SpawnOnDrop::new(Box::pin(drop_future)).left_future()
            }
            // Dropping by InterfaceContext::Drop
            Err(..) => entry.get().dropped().right_future(),
        }
        .left_future()
    }
}

mod spawn_on_drop {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll, ready},
    };

    use tracing::Instrument;

    pub(crate) struct SpawnOnDrop<F: Future<Output: Send + 'static> + Unpin + Send + 'static> {
        pub(crate) future: Option<F>,
    }

    impl<F: Future<Output: Send + 'static> + Unpin + Send + 'static> SpawnOnDrop<F> {
        pub(crate) fn new(future: F) -> Self {
            Self {
                future: Some(future),
            }
        }
    }

    impl<F: Future<Output: Send + 'static> + Unpin + Send + 'static> Future for SpawnOnDrop<F> {
        type Output = F::Output;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.as_mut().get_mut().future.as_mut() {
                Some(future) => {
                    let output = ready!(Pin::new(future).poll(cx));
                    self.future = None;
                    Poll::Ready(output)
                }
                None => panic!("future polled after completion"),
            }
        }
    }

    impl<F: Future<Output: Send + 'static> + Unpin + Send + 'static> Drop for SpawnOnDrop<F> {
        fn drop(&mut self) {
            if let Some(future) = self.future.take() {
                // Best-effort: schedule the must-complete future before it is dropped.
                tokio::spawn(future.in_current_span());
            }
        }
    }
}

struct Binding {
    io: Box<dyn IO>,
    id: UniqueId,
    span: tracing::Span,
}

impl Binding {
    fn new(io: Box<dyn IO>, id: UniqueId) -> Self {
        let bind_uri = io.bind_uri();
        let span = tracing::debug_span!(
            parent: None,
            "interface",
            %bind_uri,
            bind_id = usize::from(id),
        );
        Self { io, id, span }
    }
}

pub struct InterfaceContext {
    factory: Arc<dyn ProductIO>,
    binding: RwLock<Binding>,
    // shared with [InterfaceEntry]
    dropped: Arc<SetOnce<()>>,
    ifaces: Arc<InterfaceManager>,
    components: RwLock<Components>,
}

impl InterfaceContext {
    fn binding(&self) -> RwLockReadGuard<'_, Binding> {
        self.binding.read_recursive()
    }

    fn binding_mut(&self) -> RwLockWriteGuard<'_, Binding> {
        self.binding.write()
    }

    pub fn bind_id(&self) -> UniqueId {
        self.binding().id
    }

    fn with_io<T>(&self, f: impl FnOnce(&dyn IO) -> T) -> T {
        let binding = self.binding();
        let _guard = binding.span.enter();
        f(binding.io.as_ref())
    }

    pub(crate) fn with_bind_io<T>(
        &self,
        bind_id: UniqueId,
        f: impl FnOnce(&dyn IO) -> T,
    ) -> Result<T, RebindedError> {
        let binding = self.binding();
        if binding.id != bind_id {
            return Err(RebindedError);
        }
        let _guard = binding.span.enter();
        Ok(f(binding.io.as_ref()))
    }

    fn components(&self) -> RwLockReadGuard<'_, Components> {
        self.components.read_recursive()
    }

    fn components_mut(&self) -> RwLockWriteGuard<'_, Components> {
        self.components.write()
    }

    pub fn poll_close(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        let (mut binding, components) = (self.binding_mut(), self.components());
        for (.., component) in &components.map {
            ready!(component.poll_shutdown(cx));
        }
        binding.io.poll_close(cx)
    }
}

impl Debug for InterfaceContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interface")
            .field("bind_uri", &self.binding().io.bind_uri())
            .finish()
    }
}

impl BindInterface {
    pub fn poll_rebind(&self, cx: &mut Context<'_>) -> Poll<()> {
        let context = self.context.as_ref();

        // 降级binding锁
        // A: rebind, reinit
        // B:                rebind, reinit

        // 释放binding锁
        // A: lock(B), lock(C), rebind, release(B), reinit, release(C)
        // B:                                      lock(B),             lock(C), rebind, reinit

        // hold read lock to prevent subsequent rebind, avoid compoents seeing inconsistent state
        let (new_bind_id, components, span) = {
            let mut binding = context.binding_mut();
            let components = context.components();

            ready!(context.factory.poll_rebind(cx, &mut binding.io));
            binding.id = context.ifaces.bind_id_generator.generate();
            binding.span = tracing::debug_span!(
                parent: None,
                "interface",
                bind_uri = %binding.io.bind_uri(),
                bind_id = usize::from(binding.id),
            );
            (binding.id, components, binding.span.clone())
        };

        let iface = Interface {
            bind_id: new_bind_id,
            bind_iface: self.clone(),
        };
        let _guard = span.enter();
        for (.., component) in &components.map {
            component.reinit(&iface);
        }
        Poll::Ready(())
    }

    pub fn insert_component_with<C: Component>(&self, init: impl FnOnce(&Interface) -> C) {
        self.with_components_mut(|components, iface| {
            components.init_with(|| init(iface));
        });
    }

    pub fn with_components<T>(&self, f: impl FnOnce(&Components, &Interface) -> T) -> T {
        let context = self.context.as_ref();
        let (binding, components) = (context.binding(), context.components());
        let _guard = binding.span.enter();

        let iface = Interface {
            bind_id: binding.id,
            bind_iface: self.clone(),
        };
        f(components.deref(), &iface)
    }

    pub fn with_components_mut<T>(&self, f: impl FnOnce(&mut Components, &Interface) -> T) -> T {
        let context = self.context.as_ref();
        let (binding, mut components) = (context.binding(), context.components_mut());
        let _guard = binding.span.enter();

        let iface = Interface {
            bind_id: binding.id,
            bind_iface: self.clone(),
        };
        f(components.deref_mut(), &iface)
    }
}

impl Interface {
    pub fn with_component<C: Component, T>(
        &self,
        f: impl FnOnce(&C) -> T,
    ) -> Result<Option<T>, RebindedError> {
        let context = self.bind_iface.context.as_ref();
        let (binding, components) = (context.binding(), context.components());

        if self.bind_id != binding.id {
            return Err(RebindedError);
        }

        let _guard = binding.span.enter();
        Ok(components.with(f))
    }

    pub fn with_components<T>(&self, f: impl FnOnce(&Components) -> T) -> Result<T, RebindedError> {
        let context = self.bind_iface.context.as_ref();
        let (binding, components) = (context.binding(), context.components());

        if self.bind_id != binding.id {
            return Err(RebindedError);
        }

        let _guard = binding.span.enter();
        Ok(f(components.deref()))
    }

    pub fn get_component<C: Component + Clone>(&self) -> Result<Option<C>, RebindedError> {
        self.with_component(C::clone)
    }
}

impl IO for InterfaceContext {
    fn bind_uri(&self) -> BindUri {
        self.binding().io.bind_uri()
    }

    fn bound_addr(&self) -> io::Result<SocketAddr> {
        self.with_io(|io| io.bound_addr())
    }

    fn max_segment_size(&self) -> io::Result<usize> {
        self.with_io(|io| io.max_segment_size())
    }

    fn max_segments(&self) -> io::Result<usize> {
        self.with_io(|io| io.max_segments())
    }

    fn poll_send(
        &self,
        cx: &mut Context,
        pkts: &[io::IoSlice],
        route: route::Route,
    ) -> Poll<io::Result<usize>> {
        self.with_io(|io| io.poll_send(cx, pkts, route))
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        pkts: &mut [BytesMut],
        route: &mut [route::Route],
    ) -> Poll<io::Result<usize>> {
        self.with_io(|io| io.poll_recv(cx, pkts, route))
    }

    fn poll_close(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        InterfaceContext::poll_close(self, cx)
    }
}

mod dropping_io {
    use thiserror::Error;

    use super::*;

    #[derive(Debug, Clone, Error)]
    #[error("QuicIO is dropping and cannot be used anymore, you should never see this error")]
    pub(crate) struct DroppingIO {
        pub(crate) bind_uri: BindUri,
    }

    impl DroppingIO {
        pub(crate) fn to_io_error(&self) -> io::Error {
            io::Error::new(io::ErrorKind::NotConnected, self.clone())
        }
    }

    impl From<DroppingIO> for io::Error {
        fn from(error: DroppingIO) -> Self {
            error.to_io_error()
        }
    }

    impl IO for DroppingIO {
        fn bind_uri(&self) -> BindUri {
            self.bind_uri.clone()
        }

        fn bound_addr(&self) -> io::Result<SocketAddr> {
            Err(self.to_io_error())
        }

        fn max_segment_size(&self) -> io::Result<usize> {
            Err(self.to_io_error())
        }

        fn max_segments(&self) -> io::Result<usize> {
            Err(self.to_io_error())
        }

        fn poll_send(
            &self,
            _: &mut Context,
            _: &[io::IoSlice],
            _: route::Route,
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(self.to_io_error()))
        }

        fn poll_recv(
            &self,
            _: &mut Context,
            _: &mut [BytesMut],
            _: &mut [route::Route],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(self.to_io_error()))
        }

        fn poll_close(&mut self, _: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}

impl Binding {
    pub fn is_dropping(&self) -> bool {
        (self.io.as_ref() as &dyn Any).is::<dropping_io::DroppingIO>()
    }

    pub fn take_io(&mut self) -> Option<Box<dyn IO>> {
        if self.is_dropping() {
            return None;
        }
        let bind_uri = self.io.bind_uri();
        let dropping_io = Box::new(dropping_io::DroppingIO { bind_uri });
        Some(mem::replace(&mut self.io, dropping_io))
    }
}

impl InterfaceContext {
    fn drop(&self) -> impl Future<Output = ()> + Send + use<> {
        let dropped = self.dropped.clone();
        let Some(mut io) = self.binding_mut().take_io() else {
            return std::future::ready(()).right_future();
        };

        let ifaces = self.ifaces.clone();
        let bind_uri = io.bind_uri();
        let components = mem::take(self.components_mut().deref_mut());

        async move {
            for (_, component) in components.map {
                _ = core::future::poll_fn(|cx| component.poll_shutdown(cx)).await;
            }
            _ = io.close().await;

            dropped.set(()).expect("duplicated drop, this is a bug");
            tokio::task::spawn_blocking(move || {
                ifaces
                    .interfaces
                    .remove_if(&bind_uri, |_, entry| entry.is_dropped());
            });
        }
        .left_future()
    }
}

impl Drop for InterfaceContext {
    fn drop(&mut self) {
        if !{ self.binding().is_dropping() } {
            // Best-effort: schedule async cleanup before the context is dropped.
            tokio::spawn(InterfaceContext::drop(self).in_current_span());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use futures::task::noop_waker_ref;

    use super::*;
    use crate::{
        component::Component,
        io::{IO, ProductIO},
    };

    #[derive(Debug)]
    struct TestComponent {
        shutdown_calls: Arc<AtomicUsize>,
    }

    impl Component for TestComponent {
        fn poll_shutdown(&self, _cx: &mut Context<'_>) -> Poll<()> {
            self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(())
        }

        fn reinit(&self, _iface: &crate::Interface) {}
    }

    #[derive(Debug)]
    struct TestIo {
        bind_uri: BindUri,
        close_calls: Arc<AtomicUsize>,
    }

    impl IO for TestIo {
        fn bind_uri(&self) -> BindUri {
            self.bind_uri.clone()
        }

        fn bound_addr(&self) -> io::Result<SocketAddr> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not needed"))
        }

        fn max_segment_size(&self) -> io::Result<usize> {
            Ok(1200)
        }

        fn max_segments(&self) -> io::Result<usize> {
            Ok(1)
        }

        fn poll_send(
            &self,
            _cx: &mut Context,
            _pkts: &[io::IoSlice],
            _route: route::Route,
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }

        fn poll_recv(
            &self,
            _cx: &mut Context,
            _pkts: &mut [BytesMut],
            _route: &mut [route::Route],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_close(&mut self, _cx: &mut Context) -> Poll<io::Result<()>> {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct TestFactory {
        close_calls: Arc<AtomicUsize>,
    }

    impl ProductIO for TestFactory {
        fn bind(&self, bind_uri: BindUri) -> Box<dyn IO> {
            Box::new(TestIo {
                bind_uri,
                close_calls: self.close_calls.clone(),
            })
        }
    }

    #[test]
    fn binding_take_io_is_idempotent_and_switches_to_dropping_io() {
        let close_calls = Arc::new(AtomicUsize::new(0));
        let bind_uri: BindUri = "inet://127.0.0.1:0".into();

        let mut binding = Binding::new(
            Box::new(TestIo {
                bind_uri: bind_uri.clone(),
                close_calls: close_calls.clone(),
            }),
            UniqueIdGenerator::new().generate(),
        );

        let first = binding.take_io();
        assert!(first.is_some());
        assert!(binding.is_dropping());

        let second = binding.take_io();
        assert!(second.is_none());

        // Ensure the original IO wasn't closed by take_io itself.
        assert_eq!(close_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn poll_close_shuts_down_components_before_io_close() {
        let shutdown_calls = Arc::new(AtomicUsize::new(0));
        let close_calls = Arc::new(AtomicUsize::new(0));

        let bind_uri: BindUri = "inet://127.0.0.1:0".into();
        let mut components = Components::new();
        components.init_with(|| TestComponent {
            shutdown_calls: shutdown_calls.clone(),
        });

        let mut cx = Context::from_waker(noop_waker_ref());
        let ctx = InterfaceContext {
            factory: Arc::new(TestFactory {
                close_calls: close_calls.clone(),
            }),
            binding: RwLock::new(Binding::new(
                Box::new(TestIo {
                    bind_uri,
                    close_calls: close_calls.clone(),
                }),
                UniqueIdGenerator::new().generate(),
            )),
            dropped: Arc::new(SetOnce::new()),
            ifaces: Arc::new(InterfaceManager::new()),
            components: RwLock::new(components),
        };

        let r = ctx.poll_close(&mut cx);
        assert!(matches!(r, Poll::Ready(Ok(()))));
        assert_eq!(shutdown_calls.load(Ordering::SeqCst), 1);
        assert_eq!(close_calls.load(Ordering::SeqCst), 1);

        // Prevent Drop from spawning without a runtime.
        let _ = ctx.binding_mut().take_io();
    }
}
