mod telemetry {
    mod handy;
}

use std::sync::Arc;

use qbase::cid::ConnectionId;
use qevent::{
    Event, GroupID, event,
    quic::{ConnectionID, connectivity::ServerListening},
    span,
    telemetry::{ExportEvent, Span, handy::NoopExporter},
};

#[test]
#[cfg(feature = "telemetry")]
fn span_fields() {
    let exporter = Arc::new(NoopExporter);
    let _span = span!(exporter.clone());
    let a = 0i32;
    let c = 123456789usize;
    span!(exporter.clone(), a, a, b = 12.3f32, c, d = "Hello world!").in_scope(|| {
        assert_eq!(Span::current().load::<i32>("a"), 0);
        assert_eq!(Span::current().load::<f32>("b"), 12.3);
        assert_eq!(Span::current().load::<usize>("c"), 123456789);
        assert_eq!(Span::current().load::<String>("d"), "Hello world!");
        let e = vec![1, 2, 3];
        span!(exporter.clone(), a = 1, b = 2, c = 3, e).in_scope(|| {
            assert_eq!(Span::current().load::<i32>("a"), 1);
            assert_eq!(Span::current().load::<i32>("b"), 2);
            assert_eq!(Span::current().load::<i32>("c"), 3);
            assert_eq!(Span::current().load::<String>("d"), "Hello world!");
            assert_eq!(Span::current().load::<Vec<i32>>("e"), vec![1, 2, 3]);
        });
    })
}

#[test]
#[cfg(not(feature = "telemetry"))]
fn span_fields_are_disabled() {
    span!(Arc::new(NoopExporter), a = 1i32).in_scope(|| {
        assert_eq!(Span::current().try_load::<i32>("a"), None);
    });
}

#[test]
fn event() {
    struct TestBroker;

    impl ExportEvent for TestBroker {
        fn emit(&self, event: Event) {
            let str = serde_json::to_string_pretty(&event).unwrap();
            let event = serde_json::to_value(event).unwrap();
            println!("{str}");
            assert_eq!(event["name"], "quic:server_listening");
            let event_data_json = serde_json::json!({
                "ip_v4": "127.0.0.1",
                "port_v4": 8080,
            });
            assert_eq!(event["data"], event_data_json);
            assert_eq!(event["group_id"], String::from(group_id()));
            assert_eq!(event["use_strict_mode"], true);
        }
    }

    fn group_id() -> GroupID {
        GroupID::from(ConnectionID::from(ConnectionId::from_slice(&[
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        ])))
    }

    span!(Arc::new(TestBroker), group_id = group_id()).in_scope(|| {
        event!(
            qevent::build!(ServerListening {
                ip_v4: "127.0.0.1".to_owned(),
                port_v4: 8080u16,
            }),
            use_strict_mode = true
        );
    });
}
