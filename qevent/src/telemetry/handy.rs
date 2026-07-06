use std::{
    future::Future,
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::{
    io::{self, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use super::{ExportEvent, QLog, Span};
use crate::{Event, GroupID, VantagePoint, VantagePointType, span};

pub struct NoopExporter;

impl ExportEvent for NoopExporter {
    fn emit(&self, event: Event) {
        _ = event;
    }

    fn filter_event(&self, _: &'static str) -> bool {
        false
    }

    fn filter_raw_data(&self) -> bool {
        false
    }
}

impl ExportEvent for mpsc::UnboundedSender<Event> {
    fn emit(&self, event: Event) {
        _ = self.send(event);
    }
}

pub struct NoopLogger;

impl QLog for NoopLogger {
    #[inline]
    fn new_trace(&self, _: VantagePointType, _: GroupID) -> Span {
        span!(Arc::new(NoopExporter))
    }
}

impl<L: QLog + ?Sized> QLog for Arc<L> {
    #[inline]
    fn new_trace(&self, vantage_point: VantagePointType, group_id: GroupID) -> Span {
        self.as_ref().new_trace(vantage_point, group_id)
    }
}

pub trait TelemetryStorage {
    fn join(
        &self,
        file_name: &str,
    ) -> impl Future<Output = impl AsyncWrite + Send + Unpin + 'static> + Send + 'static;
}

impl TelemetryStorage for PathBuf {
    fn join(
        &self,
        file_name: &str,
    ) -> impl Future<Output = impl AsyncWrite + Send + Unpin + 'static> + Send + 'static {
        let file_path = Path::join(self, file_name);
        async move {
            tokio::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&file_path)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "failed to create sqlog file {}: {e:?}, qlogs to this connection will be ignored.",
                        file_path.display()
                    )
                })
        }
    }
}

impl TelemetryStorage for tokio::io::Stdout {
    #[allow(clippy::manual_async_fn)]
    fn join(
        &self,
        _: &str,
    ) -> impl Future<Output = impl AsyncWrite + Send + Unpin + 'static> + Send + 'static {
        async move { tokio::io::stdout() }
    }
}

impl TelemetryStorage for tokio::io::Stderr {
    #[allow(clippy::manual_async_fn)]
    fn join(
        &self,
        _: &str,
    ) -> impl Future<Output = impl AsyncWrite + Send + Unpin + 'static> + Send + 'static {
        async move { tokio::io::stderr() }
    }
}

pub struct LegacySeqLogger<S> {
    storage: S,
}

impl<S: Clone> Clone for LegacySeqLogger<S> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
        }
    }
}

impl<S> LegacySeqLogger<S> {
    pub fn new(storage: S) -> Self {
        Self { storage }
    }
}

impl<S: TelemetryStorage> QLog for LegacySeqLogger<S> {
    fn new_trace(&self, vantage_point: VantagePointType, group_id: GroupID) -> Span {
        use crate::legacy;

        let file_name = format!("{group_id}_{vantage_point}.sqlog");
        let file = self.storage.join(&file_name);

        let qlog_file_seq = crate::build!(legacy::QlogFileSeq {
            title: file_name,
            trace: legacy::TraceSeq {
                vantage_point: VantagePoint {
                    r#type: vantage_point
                },
            }
        });

        let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
        tokio::spawn(tracing::Instrument::in_current_span(async move {
            let mut log_file = io::BufWriter::new(file.await);

            const RS: u8 = 0x1E;

            log_file.write_u8(RS).await?;
            let qlog_file_seq = serde_json::to_string(&qlog_file_seq).unwrap();
            log_file.write_all(qlog_file_seq.as_bytes()).await?;
            log_file.write_u8(b'\n').await?;

            while let Some(event) = rx.recv().await {
                let Ok(event) = legacy::Event::try_from(event) else {
                    continue;
                };
                let event = serde_json::to_string(&event).unwrap();
                // log_file.write_vectored();
                log_file.write_u8(RS).await?;
                log_file.write_all(event.as_bytes()).await?;
                log_file.write_u8(b'\n').await?;
            }

            log_file.shutdown().await
        }));

        crate::span!(Arc::new(tx), group_id = group_id)
    }
}

pub struct TracingLogger;

impl QLog for TracingLogger {
    fn new_trace(&self, vantage_point: VantagePointType, group_id: GroupID) -> Span {
        use crate::legacy;

        let span = tracing::info_span!(
            target: "qlog",
            parent: None,
            "qlog",
            role = %vantage_point,
            odcid = %group_id
        );

        let qlog_file_seq = crate::build!(legacy::QlogFileSeq {
            title: format!("{group_id}_{vantage_point}.sqlog"),
            trace: legacy::TraceSeq {
                vantage_point: VantagePoint {
                    r#type: vantage_point
                },
            }
        });

        let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
        tokio::spawn(tracing::Instrument::instrument(
            async move {
                tracing::debug!(target: "qlog", "{}", serde_json::to_string(&qlog_file_seq).unwrap());

                while let Some(event) = rx.recv().await {
                    let Ok(event) = legacy::Event::try_from(event) else {
                        continue;
                    };
                    tracing::debug!(target: "qlog", "{}", serde_json::to_string(&event).unwrap());
                }
            },
            span,
        ));

        crate::span!(Arc::new(tx), group_id = group_id)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        quic::connectivity::ServerListening,
        telemetry::{Instrument, QLog, Span, handy::LegacySeqLogger},
    };

    #[tokio::test]
    #[cfg(feature = "telemetry")]
    async fn legacy_seq_exporter() {
        let exporter = LegacySeqLogger::new(tokio::io::stdout());

        let root_span = exporter.new_trace(
            crate::VantagePointType::Server,
            crate::GroupID::from("test_group".to_string()),
        );

        root_span.in_scope(|| {
            let any_field = 112233u64;
            crate::span!(@current, any_field).in_scope(|| {
                crate::event!(ServerListening {
                    ip_v4: "127.0.0.1".to_owned(),
                    port_v4: 443u16
                });

                tokio::spawn(
                    async move {
                        assert_eq!(Span::current().load::<u64>("any_field"), 112233u64);
                        // do something
                    }
                    .instrument(crate::span!(@current, path_id = String::from("new path"))),
                );
            });
        });

        tokio::task::yield_now().await;
    }
}
