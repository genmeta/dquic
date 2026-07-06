use std::io;

use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use super::QlogFileSeq;
use crate::{Event, telemetry::ExportEvent};

pub struct IoExpoter(mpsc::UnboundedSender<Event>);

impl IoExpoter {
    pub fn new<O>(qlog_file_seq: QlogFileSeq, mut output: O) -> Self
    where
        O: AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(tracing::Instrument::in_current_span(async move {
            let task = async {
                const RS: u8 = 0x1E;

                output.write_u8(RS).await?;
                let qlog_file_seq = serde_json::to_string(&qlog_file_seq).unwrap();
                output.write_all(qlog_file_seq.as_bytes()).await?;
                output.write_u8(b'\n').await?;

                while let Some(event) = rx.recv().await {
                    let event = match super::Event::try_from(event) {
                        Ok(event) => serde_json::to_string(&event).unwrap(),
                        Err(_unsuppert) => continue,
                    };
                    output.write_u8(RS).await?;
                    output.write_all(event.as_bytes()).await?;
                    output.write_u8(b'\n').await?;
                }

                io::Result::Ok(())
            };
            if let Err(error) = task.await {
                tracing::error!(
                    target: "qlog",
                    ?error,
                    ?qlog_file_seq,
                    "failed to write qlog, subsequent qlogs in this exporter will be ignored"
                );
            }
        }));
        Self(tx)
    }
}

impl ExportEvent for IoExpoter {
    fn emit(&self, event: Event) {
        _ = self.0.send(event);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        legacy::TraceSeq,
        quic::connectivity::ServerListening,
        telemetry::{Instrument, Span},
    };

    #[tokio::test]
    async fn io_exporter() {
        let exporter = IoExpoter::new(
            crate::build!(QlogFileSeq {
                title: "io exporter example",
                trace: TraceSeq {}
            }),
            tokio::io::stdout(),
        );

        let meaningless_field = 112233u64;
        crate::span!(Arc::new(exporter), meaningless_field).in_scope(|| {
            crate::event!(ServerListening {
                ip_v4: "127.0.0.1".to_owned(),
                port_v4: 443u16
            });

            tokio::spawn(
                async move {
                    assert_eq!(Span::current().load::<String>("path_id"), "new path");
                    assert_eq!(Span::current().load::<u64>("meaningless_field"), 112233u64);
                    // do something
                }
                .instrument(crate::span!(@current, path_id = String::from("new path"))),
            );
        });

        tokio::task::yield_now().await;
    }
}
