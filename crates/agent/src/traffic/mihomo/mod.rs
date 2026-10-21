mod discovery;
mod manager;
mod model;
mod observer;
mod transport;

pub use discovery::discover_clash_verge_controller;
pub use manager::MihomoControllerManager;
pub use model::{
    ControllerConfig, ControllerSecret, MihomoConnectionEvent, MihomoEndpoint, MihomoEvent,
    MihomoLogEvent, MihomoProxy,
};
pub use observer::MihomoTrafficDecisionProvider;
pub use transport::{LocalMihomoTransport, MihomoEventStream, MihomoTransport};
