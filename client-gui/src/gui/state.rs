use std::{fs, path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

const SETTINGS_FILE: &str = "settings.json";

#[derive(Default)]
pub struct AppState {
    pub current_view: CurrentView,
    pub connection: ConnectionState,
    pub settings: SettingsState,
    //pub logs: LogsState,
}

#[derive(Default)]
pub struct ConnectionState {
    pub connection_step: ConnectionStep,
    pub client_ptr: usize,
    pub connection_time: Option<Duration>,
}

#[derive(PartialEq)]
pub enum ConnectionStep {
    Disconnected,
    Initializing,
    Negotiating,
    CreatungTun,
    Connected
}
impl Default for ConnectionStep {
    fn default() -> Self {
        ConnectionStep::Disconnected
    }
}


#[derive(Serialize, Deserialize)]
pub struct SettingsState {
    pub server_pubkey_filepath: PathBuf,
    pub server_addr: String,
    pub server_port: String,
    pub username: String,
    pub password: String
}

impl Default for SettingsState {
    fn default() -> Self {
        if let Ok(settings_json) = fs::read_to_string(SETTINGS_FILE) {
            serde_json::from_str(&settings_json).unwrap_or_default()
        } else {
            Self { 
                server_pubkey_filepath: Default::default(),
                    server_addr: Default::default(), 
                    server_port: Default::default(), 
                    username: Default::default(), 
                    password: Default::default() 
            }
        }
    }
}

impl SettingsState {
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(&self)?;
        fs::write(SETTINGS_FILE, json)?;
        Ok(())
    }
}


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CurrentView {
    Connection,
    Settings,
}

impl Default for CurrentView {
    fn default() -> Self {
        CurrentView::Connection
    }
}
