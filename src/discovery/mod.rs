pub mod announcer;
pub mod listener;
pub mod peer;

pub use announcer::Announcer;
pub use listener::Listener;
pub use peer::{Announcement, Peer};

use crate::config::Settings;
use crate::error::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, watch};
use uuid::Uuid;

/// Discovery service that manages both announcer and listener
pub struct DiscoveryService {
    instance_id: Uuid,
    announcer: Announcer,
    listener: Listener,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl DiscoveryService {
    pub fn new(settings: &Settings, fingerprint: String) -> Self {
        let instance_id = Uuid::new_v4();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let announcer = Announcer::new(instance_id, settings, fingerprint);
        let listener = Listener::new(instance_id, settings.discovery_port);

        Self {
            instance_id,
            announcer,
            listener,
            shutdown_tx,
            shutdown_rx,
        }
    }

    pub fn instance_id(&self) -> Uuid {
        self.instance_id
    }

    /// Get handle to the peers list
    pub fn peers(&self) -> Arc<RwLock<HashMap<Uuid, Peer>>> {
        self.listener.peers()
    }

    /// Get current list of discovered peers
    pub async fn get_peers(&self) -> Vec<Peer> {
        self.listener.get_peers().await
    }

    /// Start the discovery service (announcer + listener)
    pub async fn run(&self) -> Result<()> {
        let announcer_shutdown = self.shutdown_rx.clone();
        let listener_shutdown = self.shutdown_rx.clone();

        // Run both tasks concurrently
        tokio::try_join!(
            self.announcer.run(announcer_shutdown),
            self.listener.run(listener_shutdown),
        )?;

        Ok(())
    }

    /// Signal shutdown
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}
