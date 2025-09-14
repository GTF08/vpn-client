use iced::window::{Event, Id};

use crate::gui::state::CurrentView;

#[derive(Debug, Clone)]
pub enum Message {
    ServerPubkeyButtonPressed,
    ServerAddressChanged(String),
    ServerPortChanged(String),
    UsernameChanged(String),
    PasswordChagned(String),
    SaveSettingsButtonClicked,
    ViewChanged(CurrentView),
    VPNConnectPressed,
    VPNInitFinished(usize),
    VPNNegotiationFinished(i32),
    VPNTunnelCreated(i32),
    VPNDisconnectPressed,
    VPNDisconnected(i32),
    WindowEvent(Id, Event)
}