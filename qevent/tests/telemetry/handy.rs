#![cfg(feature = "telemetry")]

use qevent::{
    quic::connectivity::ServerListening,
    telemetry::{Instrument, QLog, Span, handy::LegacySeqLogger},
};

#[tokio::test]
async fn legacy_seq_exporter() {
    let exporter = LegacySeqLogger::new(tokio::io::stdout());

    let root_span = exporter.new_trace(
        qevent::VantagePointType::Server,
        qevent::GroupID::from("test_group".to_string()),
    );

    let task = root_span.in_scope(|| {
        let any_field = 112233u64;
        qevent::span!(@current, any_field).in_scope(|| {
            qevent::event!(ServerListening {
                ip_v4: "127.0.0.1".to_owned(),
                port_v4: 443u16
            });

            tokio::spawn(
                async move {
                    assert_eq!(Span::current().load::<u64>("any_field"), 112233u64);
                    // do something
                }
                .instrument(qevent::span!(@current, path_id = String::from("new path"))),
            )
        })
    });

    task.await.unwrap();
}
