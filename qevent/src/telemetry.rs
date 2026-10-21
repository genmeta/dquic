pub(crate) mod filter;
pub mod handy;

#[doc(hidden)]
pub mod macro_support;
mod macros;

use std::{
    collections::HashMap,
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use handy::NoopExporter;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{Event, GroupID, VantagePointType};

pub trait QLog {
    fn new_trace(&self, vantage_point: VantagePointType, group_id: GroupID) -> Span;
}

pub trait ExportEvent: Send + Sync {
    fn emit(&self, event: Event);

    fn filter_event(&self, scheme: &'static str) -> bool {
        _ = scheme;
        true
    }

    fn filter_raw_data(&self) -> bool {
        false
    }
}

#[derive(Clone)]
pub struct Span {
    exporter: Arc<dyn ExportEvent>,
    fields: Arc<HashMap<&'static str, Value>>,
}

impl Debug for Span {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Span")
            .field("exporter", &"..")
            .field("fields", &self.fields)
            .finish()
    }
}

impl Span {
    #[inline]
    pub fn emit(&self, event: Event) {
        self.exporter.emit(event);
    }

    #[inline]
    pub fn filter_event(&self, scheme: &'static str) -> bool {
        self.exporter.filter_event(scheme)
    }

    #[inline]
    pub fn filter_raw_data(&self) -> bool {
        self.exporter.filter_raw_data()
    }

    #[inline]
    pub fn load<T: DeserializeOwned>(&self, name: &'static str) -> T {
        let Some(value) = self.fields.get(name) else {
            panic!(
                "Failed to load field `{name}` from span fields: {:?}",
                self.fields
            );
        };
        match serde_json::from_value(value.clone()) {
            Ok(value) => value,
            Err(e) => panic!(
                "Failed to load field `{name}` from span fields: {:?}, error: {:?}",
                self.fields, e
            ),
        }
    }

    #[inline]
    pub fn try_load<T: DeserializeOwned>(&self, name: &'static str) -> Option<T> {
        serde_json::from_value(self.fields.get(name)?.clone()).ok()
    }
}

impl PartialEq for Span {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.fields, &other.fields) && Arc::ptr_eq(&self.exporter, &other.exporter)
    }
}

impl Default for Span {
    fn default() -> Self {
        Self {
            exporter: Arc::new(NoopExporter),
            fields: Arc::new(HashMap::new()),
        }
    }
}

pub struct Entered {
    previous: Option<Span>,
}

mod current_span {
    use std::cell::RefCell;

    use super::{Entered, Span};

    thread_local! {
        pub static CURRENT_SPAN: RefCell<Span> = RefCell::new(Span::default());
    }

    impl Drop for Entered {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                CURRENT_SPAN.with(|span| {
                    span.replace(previous.clone());
                });
            }
        }
    }

    impl Span {
        pub fn enter(&self) -> Entered {
            let previous = CURRENT_SPAN.with(|current| {
                if &*current.borrow() == self {
                    None
                } else {
                    Some(current.replace(self.clone()))
                }
            });
            Entered { previous }
        }

        pub fn in_scope<T>(&self, f: impl FnOnce() -> T) -> T {
            let _guard = self.enter();
            f()
        }

        pub fn current() -> Span {
            CURRENT_SPAN.with(|span| span.borrow().clone())
        }
    }
}

pin_project_lite::pin_project! {
    pub struct Instrumented<F: ?Sized> {
        span: Span,
        #[pin]
        inner: F,
    }
}

pub trait Instrument {
    fn instrument(self, span: Span) -> Instrumented<Self>;

    fn instrument_in_current(self) -> Instrumented<Self>;
}

impl<F: Future> Instrument for F {
    fn instrument(self, span: Span) -> Instrumented<Self> {
        Instrumented { span, inner: self }
    }

    fn instrument_in_current(self) -> Instrumented<Self> {
        self.instrument(crate::span!())
    }
}

impl<F: Future> Future for Instrumented<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        this.span.in_scope(|| this.inner.poll(cx))
    }
}
