use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use qbase::{error::Error, param::ServerParameters};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::endpoint::{Accepted, Endpoint, Scope};

pub(crate) struct Registration {
    pub(crate) endpoint: Arc<Endpoint>,
    pub(crate) scope: Scope,
    pub(crate) parameters: ServerParameters,
    pub(crate) process_conn: Arc<dyn Fn(Accepted) + Send + Sync>,
    pub(crate) live: Mutex<bool>,
    pub(crate) stop: CancellationToken,
}

/// One shared registration table and mature-connection dispatch queue.
pub(crate) struct Listener {
    registrations: Mutex<HashMap<String, Arc<Registration>>>,
    pub(crate) accepted: mpsc::Sender<(Arc<Registration>, Accepted)>,
}

impl Listener {
    pub(crate) fn new() -> (Arc<Self>, mpsc::Receiver<(Arc<Registration>, Accepted)>) {
        let (accepted, receiver) = mpsc::channel(32);
        (
            Arc::new(Self {
                registrations: Mutex::new(HashMap::new()),
                accepted,
            }),
            receiver,
        )
    }

    pub(crate) fn register(
        &self,
        endpoint: Arc<Endpoint>,
        scope: Scope,
        process_conn: Arc<dyn Fn(Accepted) + Send + Sync>,
    ) -> Result<(), Error> {
        let parameters = endpoint.local_parameters::<qbase::role::Server>()?;
        let mut registrations = self.registrations.lock().unwrap();
        if registrations.contains_key(endpoint.name()) {
            return Err(crate::internal("endpoint is already listening"));
        }
        registrations.insert(
            endpoint.name().to_owned(),
            Arc::new(Registration {
                endpoint,
                scope,
                parameters,
                process_conn,
                live: Mutex::new(true),
                stop: CancellationToken::new(),
            }),
        );
        Ok(())
    }

    pub(crate) fn unregister(&self, endpoint: &Endpoint) -> Result<(), Error> {
        let mut registrations = self.registrations.lock().unwrap();
        let registration = registrations
            .get(endpoint.name())
            .filter(|registration| Arc::ptr_eq(&registration.endpoint.identity, &endpoint.identity))
            .ok_or_else(|| crate::internal("endpoint is not listening"))?;
        *registration.live.lock().unwrap() = false;
        registration.stop.cancel();
        registrations.remove(endpoint.name());
        Ok(())
    }

    pub(crate) fn select(&self, name: &str) -> Option<Arc<Registration>> {
        self.registrations.lock().unwrap().get(name).cloned()
    }

    pub(crate) fn idle_timeout(&self) -> std::time::Duration {
        let registrations = self.registrations.lock().unwrap();
        let timeouts = registrations
            .values()
            .map(|registration| {
                registration
                    .parameters
                    .get::<std::time::Duration>(qbase::param::ParameterId::MaxIdleTimeout)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        if timeouts.contains(&std::time::Duration::ZERO) {
            std::time::Duration::ZERO
        } else {
            timeouts
                .into_iter()
                .max()
                .unwrap_or(std::time::Duration::from_secs(30))
        }
    }

    pub(crate) async fn dispatch(
        mut accepted: mpsc::Receiver<(Arc<Registration>, Accepted)>,
        stop: CancellationToken,
    ) {
        let mut callbacks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                result = callbacks.join_next(), if !callbacks.is_empty() => { let _ = result; },
                connection = accepted.recv(), if callbacks.len() < 16 => {
                    let Some((registration, connection)) = connection else { break };
                    callbacks.spawn(async move {
                        {
                            let live = registration.live.lock().unwrap();
                            if !*live { return }
                            // Claim under the same lock as unlisten. Already claimed
                            // callbacks may continue after registration is removed.
                        }
                        (registration.process_conn)(connection);
                    });
                }
            }
        }
    }
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener").finish_non_exhaustive()
    }
}

impl qtls::ResolveServerAuthority for Listener {
    fn resolve(&self, request: qtls::ServerCredentialRequest<'_>) -> Option<qtls::LocalAuthority> {
        let registration = self.select(request.server_name?)?;
        qtls::ResolveServerAuthority::resolve(registration.endpoint.as_ref(), request)
    }
}
