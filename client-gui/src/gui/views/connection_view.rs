use iced::{
    widget::{Button, Column, Container, Text}, Alignment, Element, Length
};

use crate::{
    gui::message::Message,
    gui::state::ConnectionState,
};

pub fn view(state: &'_ ConnectionState) -> Element<'_, Message> {
    let content = match state.connection_step {
        crate::gui::state::ConnectionStep::Disconnected => {
            Column::new()
                .push(Text::new("Не подключено").size(18).align_x(Alignment::Center).width(Length::Fill))
                .push(
                Button::new(Text::new("Подключиться").align_x(Alignment::Center))
                    .on_press(Message::VPNConnectPressed)
                    .width(Length::Fill)
                    //.style(iced::theme::Palette::DARK)
                )
                .spacing(10)
        },
        crate::gui::state::ConnectionStep::Initializing => {
             Column::new()
                .push(Text::new("Инициализация...").size(18).align_x(Alignment::Center).width(Length::Fill))
                .push(
                Button::new(Text::new("Подключаюсь...").align_x(Alignment::Center))
                    .width(Length::Fill)
                    //.style(iced::theme::Palette::DARK)
                )
                .spacing(10)
        },
        crate::gui::state::ConnectionStep::Negotiating => {
            Column::new()
                .push(Text::new("Обмен данными...").size(18).align_x(Alignment::Center).width(Length::Fill))
                .push(
                Button::new(Text::new("Подключаюсь...").align_x(Alignment::Center))
                    .width(Length::Fill)
                    //.style(iced::theme::Palette::DARK)
                )
                .spacing(10)
        },
        crate::gui::state::ConnectionStep::CreatungTun => {
            Column::new()
                .push(Text::new("Создание туннеля...").size(18).align_x(Alignment::Center).width(Length::Fill))
                .push(
                Button::new(Text::new("Подключаюсь...").align_x(Alignment::Center))
                    .width(Length::Fill)
                    //.style(iced::theme::Palette::DARK)
                )
                .spacing(10)
        },
        crate::gui::state::ConnectionStep::Connected => {
            Column::new()
                .push(Text::new("Подключено").size(18).align_x(Alignment::Center).width(Length::Fill))
                .push(
                    Button::new(Text::new("Отключиться").align_x(Alignment::Center))
                        .width(Length::Fill)
                        .on_press(Message::VPNDisconnectPressed)
                        //.style(iced::theme::Palette::DRACULA)
                )
                .spacing(10)
        },
    };

    Container::new(content)
        .padding(20)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}