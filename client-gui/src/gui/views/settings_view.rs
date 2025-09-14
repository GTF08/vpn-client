
use iced::{widget::{column, row, text_input, Button, Container, Text}, Alignment, Element, Length};

use crate::gui::{message::Message, state::SettingsState};



pub fn view(setting_state: &'_ SettingsState) -> Element<'_, Message> {
    column![
        row![
            Container::new(
                 Text::new(format!("{}", &setting_state.server_pubkey_filepath.display()))
            )
                .width(Length::Fill)
                .clip(true)
            ,
            Button::new("Change File")
                .on_press(Message::ServerPubkeyButtonPressed)
        ]
            .height(Length::FillPortion(1))
            .spacing(10)
        ,
        Container::new(
             text_input("Server IP", &setting_state.server_addr)
                .on_input(Message::ServerAddressChanged),
        )
            .height(Length::FillPortion(1))
        ,
        Container::new(
            text_input("Server Port", &setting_state.server_port)
                .on_input(Message::ServerPortChanged),
        )
            .height(Length::FillPortion(1))
        ,
        Container::new(
            text_input("Username", &setting_state.username)
                .on_input(Message::UsernameChanged),
        )
            .height(Length::FillPortion(1))
        ,
        Container::new(
            text_input("Password", &setting_state.password)
                .on_input(Message::PasswordChagned)
        )
            .height(Length::FillPortion(1)),
        Container::new(
            Button::new("Save Settings")
                .on_press(Message::SaveSettingsButtonClicked)
                .width(Length::Fill)
        )
            .height(Length::FillPortion(1)),
    ]
    .clip(true)
    .spacing(10)
    .into()
}



// pub fn update(setting_state: &mut SettingsState, message: Message) {
//     match message {
//         Message::ServerAddressChanged(new_addr) => setting_state.server_addr = new_addr,
//         Message::ServerPortChanged(new_port) => setting_state.server_addr = new_port,
//         Message::UsernameChanged(new_username) => setting_state.username = new_username,
//         Message::PasswordChagned(new_password) => setting_state.password = new_password,
//         _ => {}
//     }
// }