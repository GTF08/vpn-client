use iced::{
    widget::{Button, Column, Container, Text},
    Element, Length,
};

use crate::{gui::message::Message, gui::state::{AppState, CurrentView}};

pub fn view(state: &'_ AppState) -> Element<'_, Message> {
    let buttons = [
        ("Подключение", CurrentView::Connection),
        ("Настройки", CurrentView::Settings),
    ];

    let mut column = Column::new().spacing(10);

    for (label, view) in buttons {
        let is_active = state.current_view == view;
        let mut button = Button::new(Text::new(label))
            .width(Length::Fill);
        button = if !is_active {
            button.on_press(Message::ViewChanged(view))
        } 
        else {
            button
        };

        // let button = if is_active {
        //     button.style(iced::theme::Palette::Primary)
        // } else {
        //     button.style(iced::theme::Palette::Secondary)
        // };

        column = column.push(button);
    }

    Container::new(column)
        .padding(10)
        .width(Length::Fixed(200.0))
        //.style(iced::widget::Container::Box)
        .into()
}