use std::{ffi::{c_char, c_void, CString}, path::PathBuf};

use iced::{
    widget::Container, Element, Task, Theme
};

use iced::{
    widget::{column, row}
};
use rfd::FileDialog;

use log::{info, error, debug};

use crate::{
    gui::{components::{header, sidebar}, message::Message, state::{AppState, ConnectionStep, CurrentView}, styles, views::{connection_view, settings_view}},
    vpn_externs::{self},
};

#[derive(Default)]
pub struct App {
    state: AppState,
}

impl App {
    pub fn view(&'_ self) -> Element<'_, Message> {
        Container::new(
            column![
                header::view(),
                row![
                    sidebar::view(&self.state),
                    self.current_view()
                ].spacing(20)
            ].spacing(10)
        )
        .padding(20)
        .into()

    }

    pub fn update(&mut self, message: Message) -> iced::Task<Message> {
        match message {
            Message::ServerPubkeyButtonPressed => {
                let new_pubkey_filepath = FileDialog::new()
                    .set_directory(std::env::current_dir().unwrap().parent().unwrap())
                    .pick_file();
                if let Some(path) = new_pubkey_filepath {
                    self.state.settings.server_pubkey_filepath = path
                }
                Task::none()
                //self.update(Message::ServerPubkeyChanged(new_pubkey_filepath))
            },
            Message::ServerAddressChanged(new_addr) => {
                self.state.settings.server_addr = new_addr;
                Task::none()
            },
            Message::ServerPortChanged(new_port) => {
                self.state.settings.server_port = new_port;
                Task::none()
            },
            Message::UsernameChanged(new_username) => {
                self.state.settings.username = new_username;
                Task::none()
            },
            Message::PasswordChagned(new_password) => {
                self.state.settings.password = new_password;
                Task::none()
            },
            Message::ViewChanged(current_view) => {
                self.state.current_view = current_view;
                Task::none()
            },
            Message::SaveSettingsButtonClicked => {
                if let Err(e) = self.state.settings.save() {
                    error!("Failed to save settings: {e}")
                }
                Task::none()
            }
            Message::VPNConnectPressed => {
                self.state.connection.connection_step = super::state::ConnectionStep::Initializing;
                self.vpn_init()
            },
            Message::VPNInitFinished(client_ptr) => {
                self.state.connection.client_ptr = client_ptr;
                self.state.connection.connection_step = super::state::ConnectionStep::Negotiating;
                self.vpn_negotiate(client_ptr)
            },
            Message::VPNNegotiationFinished(result) => {
                if result == 1 {
                    self.state.connection.connection_step = super::state::ConnectionStep::CreatungTun;
                    self.vpn_create_tunnel(self.state.connection.client_ptr)
                } else {
                    error!("Failed to negotiate with server, result: {}", result);
                    self.vpn_cleanup(self.state.connection.client_ptr);
                    Task::none()
                }
            },
            Message::VPNTunnelCreated(result) => {
                if result == 1 {
                    self.state.connection.connection_step = super::state::ConnectionStep::Connected;
                    self.vpn_loop_start(self.state.connection.client_ptr)
                } else {
                    error!("Failed to create tunnel with result: {}", result);
                    self.vpn_cleanup(self.state.connection.client_ptr);
                    
                    Task::none()
                }
            },
            Message::VPNDisconnected(result) => {
                if result < 0 {
                    error!("VPN Loop finished with result: {}", result);
                } else {
                    info!("VPN Loop finished gracefully");
                }
                self.vpn_cleanup(self.state.connection.client_ptr);
                Task::none()
            },
            Message::VPNDisconnectPressed => {
                self.vpn_disconnect(self.state.connection.client_ptr);
                Task::none()
            },
            Message::WindowEvent(_id, e) => {
                match e {
                    iced::window::Event::CloseRequested => {
                        if self.state.connection.connection_step == ConnectionStep::Connected {
                            self.vpn_disconnect(self.state.connection.client_ptr);   
                        }
                        info!("Exiting application");
                        iced::exit()
                    },
                    _ => {Task::none()}
                }
            }
        }
    }

    fn theme(&self) -> Theme {
        styles::theme()
    }
}

impl App {
    fn current_view(&'_ self) -> Element<'_, Message> {
        match self.state.current_view {
            CurrentView::Connection => connection_view::view(&self.state.connection),
            CurrentView::Settings => settings_view::view(&self.state.settings),
        }.into()
    }

    fn vpn_init(&mut self) -> iced::Task<Message> {
        let server_pubkey_filepath = self.state.settings.server_pubkey_filepath.clone();
        let server_addr = self.state.settings.server_addr.clone();
        let server_port = self.state.settings.server_port.clone();
        let username = self.state.settings.username.clone();
        let password = self.state.settings.password.clone();

        debug!("Starting VPN init async task");
        let shit = iced::task::Task::perform(
            async {
                vpn_init_wrapper(
                    server_pubkey_filepath,
                    server_addr,
                    server_port,
                    username,
                    password
                )
            },
            |client_ptr| {
                info!("VPN init finished with client_ptr: {}", client_ptr);
                Message::VPNInitFinished(client_ptr)
            }
        );
        shit
    }

    fn vpn_negotiate(&self, client_ptr: usize) -> iced::Task<Message> {
        debug!("Starting VPN negotiation async task");
        let shit_task = iced::task::Task::perform(async move {
            unsafe { vpn_externs::vpn_negotiate(client_ptr as *mut c_void) }
        },
        |result| {
            info!("VPN negotiation finished with result: {}", result);
            Message::VPNNegotiationFinished(result)
        }
        );
        shit_task
    }

    fn vpn_create_tunnel(&self, client_ptr: usize) -> iced::Task<Message>  {
        debug!("Starting VPN Tun Creation async task");
        let shit_task = iced::task::Task::perform(async move {
            unsafe { vpn_externs::vpn_create_tun(client_ptr as *mut c_void) }
        },
        |result| {
            info!("VPN Tun Creation finished with result: {}", result);
            Message::VPNTunnelCreated(result)
        }
        );
        shit_task
    }

    fn vpn_loop_start(&self, client_ptr: usize) -> iced::Task<Message> {
        debug!("Starting VPN Loop async task");
        let shit_task = iced::task::Task::perform(async move {
            unsafe { vpn_externs::vpn_loop(client_ptr as *mut c_void) }
        },
        |result| {
            info!("VPN Loop finished with result: {}", result);
            Message::VPNDisconnected(result)
        }
        );
        shit_task
    }


    fn vpn_disconnect(&mut self, client_ptr: usize) {
        info!("Disconnection from VPN");
        unsafe { vpn_externs::vpn_disconnect(client_ptr as *mut c_void) }
    }

    fn vpn_cleanup(&mut self, client_ptr: usize) {
        info!("Cleaning up VPN, client pointer: {}", client_ptr);
        unsafe { vpn_externs::vpn_cleanup(client_ptr as *mut c_void);}
        self.state.connection.connection_step = super::state::ConnectionStep::Disconnected;
    }
}


fn vpn_init_wrapper(
    server_pubkey_filepath: PathBuf,
    server_addr: String,
    server_port: String,
    username: String,
    password: String
) -> usize {
        info!("Initializing VPN connection");
        let server_pubkey_filepath_c = CString::new(server_pubkey_filepath.as_os_str().to_str().unwrap()).unwrap();
        let server_addr_c = CString::new(server_addr.as_str()).unwrap();
        let server_port_c = CString::new(server_port.as_str()).unwrap();
        let username_c = CString::new(username.as_str()).unwrap();
        let password_c = CString::new(password.as_str()).unwrap();
        let sex = unsafe {
            vpn_externs::vpn_init(
                server_pubkey_filepath_c.as_ptr() as *const c_char,
                server_addr_c.as_ptr() as *const c_char,
                server_port_c.as_ptr() as *const c_char,
                username_c.as_ptr() as *const c_char,
                password_c.as_ptr() as *const c_char,
            )
        };
        sex as usize 
    }