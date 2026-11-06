use serde::Serialize;

use super::*;
use crate::{BeSpecificEventData, EventBuilder};

#[inline]
pub fn new_span(exporter: Arc<dyn ExportEvent>, fields: HashMap<&'static str, Value>) -> Span {
    Span { exporter, fields: Arc::new(fields) }
}

pub fn modify_event_builder_costom_fields(builder: &mut EventBuilder, f: impl FnOnce(&mut HashMap<String, Value>)) {
    if builder.custom_fields.is_none() {
        builder.custom_fields = Some(HashMap::new());
    }
    let custom_fields = builder.custom_fields.as_mut().unwrap();
    f(custom_fields);
}

pub fn current_span_exporter() -> Arc<dyn ExportEvent> {
    current_span::CURRENT_SPAN.with(|span| span.borrow().exporter.clone())
}

pub fn current_span_fields() -> HashMap<&'static str, Value> {
    current_span::CURRENT_SPAN.with(|span| span.borrow().fields.as_ref().clone())
}

pub fn try_load_current_span<T: DeserializeOwned>(name: &'static str) -> Option<T> {
    current_span::CURRENT_SPAN.with(|span| {
        let span = span.borrow();
        Some(from_value::<T>(span.fields.get(name)?.clone()))
    })
}

pub fn build_and_emit_event<D: BeSpecificEventData>(build_data: impl FnOnce() -> D, build_event: impl FnOnce(D) -> Event) {
    if !filter::event(D::scheme()) {
        return;
    }
    let event = build_event(build_data());
    current_span::CURRENT_SPAN.with(|span| span.borrow().emit(event));
}

pub fn to_value<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).unwrap()
}

pub fn from_value<T: DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}
