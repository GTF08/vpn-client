use iced::{
    widget::{Container, Row, Text},
    Element, Length,
};

use crate::gui::message::Message;

pub fn view() -> Element<'static, Message> {
    Container::new(
        Row::new()
            .push(Text::new("Vinnie Poh").size(24))
            .align_y(iced::Alignment::Center)
            .spacing(20)
    )
    .padding(10)
    .width(Length::Fill)
    //.style(iced::theme::Palette::DRACULA)
    .into()
}