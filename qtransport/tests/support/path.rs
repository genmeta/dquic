use std::sync::Arc;

use qbase::{cid::ArcRemoteCids, handshake::HandshakeFacts, net::route::Pathway, time::heartbeat::ArcHeartbeat};
use qtransport::{ArcProgress, ArcReliableFrames, ArcResend, path::Path, space::ArcSpaces, terminate::ArcTerminator};

pub(crate) fn path(
    remote_cids: ArcRemoteCids<ArcReliableFrames>,
    pathway: Pathway,
    facts: Arc<HandshakeFacts>,
    spaces: ArcSpaces,
    resenders: ArcResend,
    heartbeat: ArcHeartbeat,
    terminator: ArcTerminator,
) -> Path {
    let dcid = remote_cids.apply_dcid();
    let progress = ArcProgress::new(facts.clone(), remote_cids, spaces.clone(), resenders.clone(), terminator.clone());
    Path::new(dcid, pathway, facts, spaces, resenders, heartbeat, terminator, progress)
}
