use std::sync::Arc;

use qevent::{
    legacy::{QlogFileSeq, TraceSeq, exporter::IoExpoter},
    quic::connectivity::ServerListening,
    telemetry::{Instrument, Span},
};

#[tokio::test]
async fn io_exporter() {
    let exporter = IoExpoter::new(
        qevent::build!(QlogFileSeq {
            title: "io exporter example",
            trace: TraceSeq {}
        }),
        tokio::io::stdout(),
    );

    let meaningless_field = 112233u64;
    let task = qevent::span!(Arc::new(exporter), meaningless_field).in_scope(|| {
        qevent::event!(ServerListening {
            ip_v4: "127.0.0.1".to_owned(),
            port_v4: 443u16
        });

        tokio::spawn(
            async move {
                #[cfg(feature = "telemetry")]
                {
                    assert_eq!(Span::current().load::<String>("path_id"), "new path");
                    assert_eq!(Span::current().load::<u64>("meaningless_field"), 112233u64);
                }
                #[cfg(not(feature = "telemetry"))]
                {
                    assert_eq!(Span::current().try_load::<String>("path_id"), None);
                    assert_eq!(Span::current().try_load::<u64>("meaningless_field"), None);
                }
            }
            .instrument(qevent::span!(@current, path_id = String::from("new path"))),
        )
    });

    task.await.unwrap();
}
